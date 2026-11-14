package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type runtimeMetadata struct {
	PID       int    `json:"pid"`
	HTTPPort  int    `json:"http_port"`
	SOCKSPort int    `json:"socks_port"`
	Token     string `json:"token"`
	WebUIURL  string `json:"web_ui_url,omitempty"`
}

func defaultStandaloneConfigPath() string {
	return filepath.Join(DefaultStateDir(), "config.json")
}

func defaultRuntimeMetaPath() string {
	return filepath.Join(DefaultStateDir(), "runtime.json")
}

func defaultManifestVerPath() string {
	return filepath.Join(DefaultStateDir(), "manifest_ver.dat")
}

func runCLI(args []string) int {
	if len(args) == 0 {
		printCLIUsage()
		return 0
	}

	sub := strings.ToLower(args[0])
	rest := args[1:]

	switch sub {
	case "help", "-h", "--help":
		printCLIUsage()
		return 0
	case "version", "-v", "--version":
		fmt.Printf("%s %s (%s/%s)\n", EngineName, EngineVersion, runtime.GOOS, runtime.GOARCH)
		return 0
	}

	// Support Windows NativeUtlsEngineHost style top-level flags:
	//   pixelcore-utls-windows-amd64.exe --headless --config <path>
	if strings.HasPrefix(args[0], "-") {
		return cmdStart(args)
	}

	// Handle direct deep-link invocation from macOS Info.plist / Linux .desktop
	if strings.HasPrefix(sub, "pixeltunnel://") {
		return cmdActivate([]string{args[0]})
	}

	switch sub {
	case "start":
		return cmdStart(rest)
	case "stop":
		return cmdStop(rest)
	case "status":
		return cmdStatus(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "env":
		return cmdEnv(rest)
	case "activate":
		return cmdActivate(rest)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printCLIUsage()
		return 2
	}
}

func printCLIUsage() {
	fmt.Printf(`PixelTunnel %s (%s/%s)

Usage:
  pixeltunnel start [--config <path>] [--headless] [--no-system-proxy] [--watch-stdin]
  pixeltunnel stop
  pixeltunnel status
  pixeltunnel doctor [--json]
  pixeltunnel env [--ps]
  pixeltunnel activate <key-or-uri>
`, EngineVersion, runtime.GOOS, runtime.GOARCH)
}

type startEngineOptions struct {
	Config          *EngineConfig
	ConfigPath      string
	Headless        bool
	NoSysProxy      bool
	WatchStdin      bool
	Stdin           io.Reader
	LocalToken      string
	ManifestVerPath string
	ManifestFetcher func(context.Context, *DohResolver, ManifestVerifierOptions) (*ManifestDocument, string, error)
	SkipWarmConnect bool
	StopCh          <-chan struct{}
	OnStarted       func(*LocalProxyServer)
}

func cmdStart(args []string) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "Path to active_config.json or standalone config.json")
	headless := fs.Bool("headless", false, "Run headless without Web-UI or OS proxy mutation")
	noSysProxy := fs.Bool("no-system-proxy", false, "Skip OS PAC/IDE proxy configuration")
	watchStdin := fs.Bool("watch-stdin", false, "Exit when stdin pipe closes (disabled by default for -H=windowsgui safety)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	resolvedCfgPath := strings.TrimSpace(*cfgPath)
	if resolvedCfgPath == "" {
		resolvedCfgPath = defaultStandaloneConfigPath()
	}

	var cfg *EngineConfig
	var err error
	if _, serr := os.Stat(resolvedCfgPath); serr == nil {
		cfg, err = LoadConfig(resolvedCfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed loading config %s: %v\n", resolvedCfgPath, err)
			return 1
		}
	} else {
		cfg = DefaultEngineConfig()
		cfg.ConfigPath = resolvedCfgPath
		cfg.ApplyFallbackManifestIfNeeded()
		cfg.RebuildEffectiveRules()
		if !*headless {
			_ = SaveConfig(resolvedCfgPath, cfg)
		}
	}

	return runStartEngine(startEngineOptions{
		Config:          cfg,
		ConfigPath:      resolvedCfgPath,
		Headless:        *headless,
		NoSysProxy:      *noSysProxy,
		WatchStdin:      *watchStdin,
		Stdin:           os.Stdin,
		ManifestVerPath: defaultManifestVerPath(),
		ManifestFetcher: func(ctx context.Context, resolver *DohResolver, opts ManifestVerifierOptions) (*ManifestDocument, string, error) {
			return FetchLatestManifest(ctx, resolver, opts, "")
		},
	})
}

func runStartEngine(opts startEngineOptions) int {
	cfg := opts.Config
	if cfg == nil {
		cfg = DefaultEngineConfig()
	}
	resolver := NewDohResolver(nil, nil)
	muxMgr := NewMuxManager(cfg, resolver)

	proxySrv := NewLocalProxyServer(LocalProxyOptions{
		Config:     cfg,
		Mux:        muxMgr,
		Resolver:   resolver,
		Headless:   opts.Headless,
		LocalToken: opts.LocalToken,
		OnRulesReloaded: func(updated *EngineConfig, rev uint64) {
			if !opts.Headless && !opts.NoSysProxy {
				pacURL := fmt.Sprintf("http://127.0.0.1:%d/proxy.pac?r=%d", updated.HTTPPort, rev)
				_ = ConfigureSystemProxy(pacURL, updated.HTTPPort, false)
			}
		},
	})

	if err := proxySrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed starting local proxy listeners: %v\n", err)
		return 1
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	muxMgr.StartMonitors(func(reason string, failoverMs int64) {
		if !opts.Headless {
			fmt.Fprintf(os.Stderr, "[instant-wake] reason=%s failover=%dms\n", reason, failoverMs)
		}
	})

	// Fetch signed manifest and warm upstream mux asynchronously AFTER local listeners
	// are up so /__pixelcore/v4/status responds immediately (<50ms boot).
	verFilePath := opts.ManifestVerPath
	if verFilePath == "" {
		verFilePath = defaultManifestVerPath()
	}
	go func() {
		if opts.ManifestFetcher != nil {
			mOpts := ManifestVerifierOptions{
				VersionFilePath: verFilePath,
				CacheFilePath:   defaultManifestCachePath(),
				AllowSameVer:    true,
			}
			mctx, mcancel := context.WithTimeout(bgCtx, 8*time.Second)
			doc, src, merr := opts.ManifestFetcher(mctx, resolver, mOpts)
			mcancel()
			if merr == nil && doc != nil && bgCtx.Err() == nil {
				_ = proxySrv.UpdateManifestDoc(doc, src)
			}
		}
		if !opts.SkipWarmConnect && bgCtx.Err() == nil {
			wctx, wcancel := context.WithTimeout(bgCtx, 8*time.Second)
			_ = muxMgr.WarmConnect(wctx)
			wcancel()
		}
	}()

	httpPort := proxySrv.HTTPPort()
	socksPort := proxySrv.SOCKSPort()
	uiURL := ""
	if !opts.Headless {
		uiURL = fmt.Sprintf("http://127.0.0.1:%d/ui?t=%s", httpPort, proxySrv.BootstrapToken())
		if !opts.NoSysProxy {
			pacURL := fmt.Sprintf("http://127.0.0.1:%d/proxy.pac?r=%d", httpPort, proxySrv.PACRev())
			_ = ConfigureSystemProxy(pacURL, httpPort, false)
			HealIDEConfigurations(httpPort, true, false)
		}
		_ = writeRuntimeMeta(&runtimeMetadata{
			PID:       os.Getpid(),
			HTTPPort:  httpPort,
			SOCKSPort: socksPort,
			Token:     proxySrv.LocalToken(),
			WebUIURL:  uiURL,
		})
		fmt.Printf("PixelTunnel %s started\n", EngineVersion)
		fmt.Printf("  HTTP/CONNECT : http://127.0.0.1:%d\n", httpPort)
		fmt.Printf("  SOCKS5h      : socks5h://127.0.0.1:%d\n", socksPort)
		fmt.Printf("  Web-UI       : %s\n", uiURL)
	}

	if opts.OnStarted != nil {
		opts.OnStarted(proxySrv)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Opt-in stdin pipe EOF watcher only when --watch-stdin is passed; disabled by default
	// because -H=windowsgui executables start with a closed/invalid stdin handle.
	parentExitCh := make(chan struct{})
	if opts.WatchStdin && opts.Stdin != nil {
		go func() {
			var b [1]byte
			for {
				_, rerr := opts.Stdin.Read(b[:])
				if rerr != nil {
					close(parentExitCh)
					return
				}
			}
		}()
	}

	select {
	case <-sigCh:
	case <-parentExitCh:
	case <-opts.StopCh:
	}

	bgCancel()
	muxMgr.Close()
	proxySrv.Close()
	if !opts.Headless && !opts.NoSysProxy {
		_ = RollbackSystemProxy(false)
		HealIDEConfigurations(httpPort, false, false)
		_ = os.Remove(defaultRuntimeMetaPath())
	}
	return 0
}

func cmdStop(_ []string) int {
	rm, err := readRuntimeMeta()
	if err == nil && rm.PID > 0 {
		if proc, perr := os.FindProcess(rm.PID); perr == nil {
			_ = proc.Signal(syscall.SIGTERM)
			time.Sleep(400 * time.Millisecond)
		}
	}
	_ = RollbackSystemProxy(false)
	httpPort := DefaultHTTPPort
	if rm != nil && rm.HTTPPort > 0 {
		httpPort = rm.HTTPPort
	}
	HealIDEConfigurations(httpPort, false, false)
	_ = os.Remove(defaultRuntimeMetaPath())
	fmt.Println("PixelTunnel stopped and OS proxy restored.")
	return 0
}

func cmdStatus(_ []string) int {
	rm, err := readRuntimeMeta()
	if err != nil {
		fmt.Println("PixelTunnel is not running (no active runtime metadata).")
		return 1
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/__pixelcore/v4/status", rm.HTTPPort), nil)
	req.Header.Set("X-Pixel-Local-Token", rm.Token)
	resp, derr := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if derr != nil {
		fmt.Printf("PixelTunnel daemon unreachable (%v).\n", derr)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(strings.TrimSpace(string(body)))
	return 0
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Output raw Diagnostics 4.0 JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var rep XRayReport
	if rm, err := readRuntimeMeta(); err == nil && rm.HTTPPort > 0 {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/__pixelcore/v4/run-xray", rm.HTTPPort), nil)
		req.Header.Set("X-Pixel-Local-Token", rm.Token)
		if resp, derr := (&http.Client{Timeout: 15 * time.Second}).Do(req); derr == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&rep) == nil {
				printDoctorResult(&rep, *jsonOut)
				return 0
			}
		}
	}

	// Standalone offline run when daemon isn't running
	cfg := DefaultEngineConfig()
	if c, cerr := LoadConfig(defaultStandaloneConfigPath()); cerr == nil {
		cfg = c
	} else {
		cfg.ApplyFallbackManifestIfNeeded()
		cfg.RebuildEffectiveRules()
	}
	resolver := NewDohResolver(nil, nil)
	mux := NewMuxManager(cfg, resolver)
	defer mux.Close()
	xray := NewXRayRunner(func() *EngineConfig { return cfg }, mux, resolver, NewRouteRadar(10))
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	offlineRep := xray.RunXRay(ctx)
	printDoctorResult(offlineRep, *jsonOut)
	return 0
}

func printDoctorResult(rep *XRayReport, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Print(rep.ReportText)
}

func cmdEnv(args []string) int {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	psMode := fs.Bool("ps", false, "Print PowerShell $env syntax")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	httpPort, socksPort := DefaultHTTPPort, DefaultSOCKSPort
	if rm, err := readRuntimeMeta(); err == nil {
		if rm.HTTPPort > 0 {
			httpPort = rm.HTTPPort
		}
		if rm.SOCKSPort > 0 {
			socksPort = rm.SOCKSPort
		}
	}

	if *psMode || runtime.GOOS == "windows" {
		fmt.Printf("$env:HTTP_PROXY=\"http://127.0.0.1:%d\"\n", httpPort)
		fmt.Printf("$env:HTTPS_PROXY=\"http://127.0.0.1:%d\"\n", httpPort)
		fmt.Printf("$env:ALL_PROXY=\"socks5h://127.0.0.1:%d\"\n", socksPort)
		return 0
	}
	fmt.Printf("export HTTP_PROXY=\"http://127.0.0.1:%d\"\n", httpPort)
	fmt.Printf("export HTTPS_PROXY=\"http://127.0.0.1:%d\"\n", httpPort)
	fmt.Printf("export ALL_PROXY=\"socks5h://127.0.0.1:%d\"\n", socksPort)
	return 0
}

func cmdActivate(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: pixeltunnel activate <uuid | vless:// | pwp4:// | pwp3:// | sub-url | pixeltunnel://>")
		return 2
	}
	pk, err := ParseKeyInput(args[0])
	if err != nil {
		if errors.Is(err, ErrTrialKeyNotPro) {
			fmt.Fprintln(os.Stderr, "Error: Free/trial key cannot be activated as PRO.")
		} else {
			fmt.Fprintf(os.Stderr, "Invalid PRO key: %v\n", err)
		}
		return 1
	}

	// Update saved standalone config
	cfgPath := defaultStandaloneConfigPath()
	cfg, cerr := LoadConfig(cfgPath)
	if cerr != nil {
		cfg = DefaultEngineConfig()
		cfg.ConfigPath = cfgPath
	}
	cfg.ApplyParsedKey(pk)
	if serr := SaveConfig(cfgPath, cfg); serr != nil {
		fmt.Fprintf(os.Stderr, "Failed saving config %s: %v\n", cfgPath, serr)
		return 1
	}

	// Push live activation to running daemon if active
	if rm, rerr := readRuntimeMeta(); rerr == nil && rm.HTTPPort > 0 {
		body, _ := json.Marshal(map[string]string{"key": args[0]})
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/__pixelcore/v4/activate", rm.HTTPPort), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Pixel-Local-Token", rm.Token)
		if resp, derr := (&http.Client{Timeout: 4 * time.Second}).Do(req); derr == nil {
			_ = resp.Body.Close()
		}
	}
	fmt.Printf("Activated PRO license (%s)\n", pk.Format)
	return 0
}

func readRuntimeMeta() (*runtimeMetadata, error) {
	raw, err := os.ReadFile(defaultRuntimeMetaPath())
	if err != nil {
		return nil, err
	}
	var rm runtimeMetadata
	if err := json.Unmarshal(raw, &rm); err != nil {
		return nil, err
	}
	return &rm, nil
}

func writeRuntimeMeta(rm *runtimeMetadata) error {
	p := defaultRuntimeMetaPath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rm, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0600)
}

// Keep unused strconv import referenced if needed
var _ = strconv.Itoa
