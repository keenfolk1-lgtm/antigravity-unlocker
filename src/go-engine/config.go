package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

const (
	EngineName    = "PixelCore_v4_Go"
	EngineVersion = "2.0.0"

	DefaultHost              = "201.34.152.97"
	DefaultSNI               = "ai.pixelstore.space"
	DefaultPWP4Path          = "/api/v4/telemetry/events"
	DefaultPWP3Path          = "/api/v3/telemetry/mux"
	DefaultManifestPubKeyB64 = "RUNTMSAAAABSoZ4cJSq/nncGfKF83UmMeoHcB30X4nlBdFrOgOwWHtZQk6vmShbw3ijqkZQTCaT9KDyqz6tfU8T9aClQNBlG"
	DefaultManifestAesHex    = "296181aecf480e7f58dcd21d8989b45d078ac2e7546a679f764312242bf95fa8"
	DefaultGitHubManifestURL = "https://raw.githubusercontent.com/keenfolk1-lgtm/antigravity-unlocker/main/manifest/nodes_v3.enc"
	DefaultDohTXTDomain      = "_v3.pixelstore.space"
	DefaultPinnedSPKISHA256  = "057ab81186e5e5beae4ac0fade013988ca7abfa9d69dafe3bfb548f94ec434f0"

	DefaultHTTPPort  = 17890
	DefaultSOCKSPort = 17891
)

var legacyTrialUUIDs = map[string]struct{}{
	"e434aed7-0a9f-449f-81b9-870086cf2d09": {},
	"66eda2cf-432e-475b-a5cb-ebbf391e649f": {},
	"02d80b07-7824-f8d4-ac3a-e431ea3a8a32": {},
}

var (
	uuidRegex  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	subIDRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{6,64}$`)
)

var (
	ErrTrialKeyNotPro = errors.New("trial/free key cannot be activated as PRO")
	ErrInvalidKey     = errors.New("unrecognized PRO key or URI format")
)

// DefaultEdgeSNIs and DefaultDecoySNIs mirror PixelCoreEngineV3 defaults.
var DefaultEdgeSNIs = []string{"ai.pixelstore.space", "dns.pixelstore.space"}
var DefaultDecoySNIs = []string{"ai.pixelstore.space", "www.amd.com", "www.apple.com"}

// CategoryDomains defines built-in proxy domain lists grouped by service category.
// Includes unified C# WPF v2.categories keys (antigravity, ai, mcp, media, social)
// as well as granular keys (dev, discord, youtube, telegram) for compatibility.
var CategoryDomains = func() map[string][]string {
	mcpDev := []string{
		"github.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"githubusercontent.com",
		"githubassets.com",
		"ghcr.io",
		"npmjs.org",
		"registry.npmjs.org",
		"npmjs.com",
		"pypi.org",
		"files.pythonhosted.org",
		"pythonhosted.org",
		"astral.sh",
		"pkg.go.dev",
		"crates.io",
		"docker.io",
		"cloudflare.com",
		"smithery.ai",
		"context7.com",
		"modelcontextprotocol.io",
		"glama.ai",
		"deno.land",
		"jsr.io",
		"bun.sh",
		"pkg.dev",
	}
	discord := []string{
		"discord.com",
		"discord.gg",
		"discordapp.com",
		"discordapp.net",
		"discord.media",
		"discordstatus.com",
		"discordcdn.com",
	}
	youtube := []string{
		"youtube.com",
		"youtu.be",
		"ytimg.com",
		"googlevideo.com",
		"youtube-nocookie.com",
		"youtubei.googleapis.com",
	}
	telegram := []string{
		"telegram.org",
		"t.me",
		"web.telegram.org",
		"tdesktop.com",
		"telegra.ph",
		"telesco.pe",
	}
	media := make([]string, 0, len(discord)+len(youtube)+len(telegram)+3)
	media = append(media, discord...)
	media = append(media, youtube...)
	media = append(media, telegram...)
	media = append(media, "twitch.tv", "ttvnw.net", "jtvnw.net")

	return map[string][]string{
		"antigravity": {
			"antigravity.google",
			"antigravity-unleash.goog",
			"antigravity-unlocker.pages.dev",
			"antigravity.dev",
			"daily-cloudcode-pa.googleapis.com",
			"cloudcode-pa.googleapis.com",
			"generativelanguage.googleapis.com",
			"aistudio.google.com",
			"gemini.google.com",
			"makersuite.google.com",
			"alkalimakersuite-pa.clients6.google.com",
			"notebooklm.google.com",
			"notebooklm.google",
			"colab.research.google.com",
			"labs.google",
			"deepmind.google",
			"ai.google.dev",
			"googleapis.com",
			"oauth2.googleapis.com",
			"www.googleapis.com",
			"clients1.google.com",
			"clients2.google.com",
			"clients3.google.com",
			"clients4.google.com",
			"clients5.google.com",
			"clients6.google.com",
			"cloudaicompanion.googleapis.com",
			"daily-cloud-pa.clients6.google.com",
			"geminiweb-pa.clients6.google.com",
			"aicode.googleapis.com",
			"gstatic.com",
			"googleusercontent.com",
			"accounts.google.com",
			"google.com",
			"gvt1.com",
			"gvt2.com",
			"gvt3.com",
			"ggpht.com",
			"1e100.net",
			"pki.goog",
		},
		"ai": {
			"anthropic.com",
			"claude.ai",
			"claude.com",
			"openai.com",
			"chatgpt.com",
			"oaistatic.com",
			"oaiusercontent.com",
			"auth0.com",
			"cursor.sh",
			"cursor.com",
			"cursorapi.com",
			"cursor-cdn.com",
			"codeium.com",
			"windsurf.com",
			"perplexity.ai",
			"x.ai",
			"grok.com",
			"huggingface.co",
			"hf.co",
			"elevenlabs.io",
			"suno.com",
			"suno.ai",
			"midjourney.com",
			"klingai.com",
			"runwayml.com",
			"sora.com",
			"luma.ai",
			"lumalabs.ai",
			"heygen.com",
			"v0.dev",
			"bolt.new",
			"lovable.dev",
			"replit.com",
			"openrouter.ai",
			"together.ai",
			"groq.com",
			"deepseek.com",
			"mistral.ai",
			"cohere.com",
			"replicate.com",
			"civitai.com",
			"githubcopilot.com",
			"copilot.microsoft.com",
		},
		"mcp":      mcpDev,
		"dev":      mcpDev,
		"media":    media,
		"discord":  discord,
		"youtube":  youtube,
		"telegram": telegram,
		"social": {
			"x.com",
			"twitter.com",
			"twimg.com",
			"t.co",
			"instagram.com",
			"cdninstagram.com",
			"facebook.com",
			"fbcdn.net",
			"threads.net",
			"tiktok.com",
			"linkedin.com",
			"spotify.com",
			"spotify.net",
			"scdn.co",
			"spotifycdn.com",
			"pscdn.co",
			"byspotify.com",
			"spotify.link",
			"spotilocal.com",
			"spclient.wg.spotify.com",
			"apresolve.spotify.com",
			"dealer.spotify.com",
			"login5.spotify.com",
			"accounts.spotify.com",
			"open.spotify.com",
			"akamaized.net",
			"netflix.com",
			"nflxvideo.net",
			"notion.so",
			"figma.com",
			"canva.com",
			"vercel.com",
			"stripe.com",
			"linear.app",
		},
	}
}()

// BuiltinDirectDomains lists domains/suffixes routed DIRECT to avoid breaking Russian/local services.
var BuiltinDirectDomains = []string{
	".ru",
	".xn--p1ai",
	".su",
	".by",
	"localhost",
	"pixelstore.space",
	"vk.com",
	"yandex.ru",
	"mail.ru",
	"gosuslugi.ru",
	"sberbank.ru",
	"tbank.ru",
	"ozon.ru",
	"wildberries.ru",
	"avito.ru",
	"dzen.ru",
	"kinopoisk.ru",
	"rutube.ru",
}

// NodeConfig describes one upstream PWP-4 / PWP-3 server node.
type NodeConfig struct {
	Name           string   `json:"name"`
	Region         string   `json:"region"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	SNI            string   `json:"sni"`
	Path           string   `json:"path"`
	PWP4Path       string   `json:"pwp4_path,omitempty"`
	Secret         string   `json:"secret"`
	UUID           string   `json:"uuid,omitempty"`
	TLS            bool     `json:"tls"`
	Mux            bool     `json:"mux"`
	Frag           bool     `json:"frag"`
	FragProfile    int      `json:"frag_profile,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	EnableDpiSplit bool     `json:"-"`
}

// HasRole checks whether the node advertises the requested role (e.g., "ai" or "media").
func (n NodeConfig) HasRole(role string) bool {
	if role == "" {
		return true
	}
	if len(n.Roles) == 0 {
		// Unannotated nodes serve general / AI traffic by default for backward compat.
		return true
	}
	for _, r := range n.Roles {
		if strings.EqualFold(strings.TrimSpace(r), role) {
			return true
		}
	}
	return false
}

func sameEndpoint(a, b NodeConfig) bool {
	if a.Host == "" || b.Host == "" {
		return false
	}
	pa, pb := a.Port, b.Port
	if pa <= 0 {
		pa = 443
	}
	if pb <= 0 {
		pb = 443
	}
	return strings.EqualFold(strings.TrimSpace(a.Host), strings.TrimSpace(b.Host)) && pa == pb
}

// EffectivePWP4Path returns the HTTP path for PWP-4 handshake.
func (n NodeConfig) EffectivePWP4Path() string {
	if p := strings.TrimSpace(n.PWP4Path); p != "" {
		if !strings.HasPrefix(p, "/") {
			return "/" + p
		}
		return p
	}
	return DefaultPWP4Path
}

// V2Config holds v2.0 transport and UI preferences inside active_config.json.
type V2Config struct {
	PreferPWP4        bool            `json:"prefer_pwp4"`
	UTLSProfile       string          `json:"utls_profile"`
	DPIProfile        int             `json:"dpi_profile"`
	StandbyEnabled    bool            `json:"standby_enabled"`
	FailoverTimeoutMs int             `json:"failover_timeout_ms"`
	WSLBridge         bool            `json:"wsl_bridge"`
	SmartPAC          bool            `json:"smart_pac"`
	PACRev            uint64          `json:"pac_rev,omitempty"`
	ProxyAll          bool            `json:"proxy_all"`
	Categories        map[string]bool `json:"categories,omitempty"`
	CustomProxy       []string        `json:"custom_proxy_domains,omitempty"`
	CustomDirect      []string        `json:"custom_direct_domains,omitempty"`
	PreferRoleRouting bool            `json:"role_routing"`
}

// EngineConfig is the normalized in-memory client engine configuration.
type EngineConfig struct {
	HTTPPort        int             `json:"http_port"`
	SOCKSPort       int             `json:"socks_port"`
	EnableWSLBridge bool            `json:"wsl_bridge"`
	PreferredRegion string          `json:"preferred_region"`
	ActiveNode      NodeConfig      `json:"active_node"`
	Nodes           []NodeConfig    `json:"nodes,omitempty"`
	ClientUUID      string          `json:"client_uuid"`
	DeviceHWID      string          `json:"device_hwid"`
	SubLink         string          `json:"sub_link,omitempty"`
	ProxyAll        bool            `json:"proxy_all"`
	Categories      map[string]bool `json:"categories"`
	ProxyDomains    []string        `json:"proxy_domains"`
	DirectDomains   []string        `json:"direct_domains"`
	CustomProxy     []string        `json:"custom_proxy_domains,omitempty"`
	CustomDirect    []string        `json:"custom_direct_domains,omitempty"`
	PinnedSPKI      []string        `json:"pinned_spki,omitempty"`
	EdgeSNIs        []string        `json:"edge_snis,omitempty"`
	DecoySNIs       []string        `json:"decoy_snis,omitempty"`
	V2              V2Config        `json:"v2"`
	ConfigPath      string          `json:"-"`
	RawSourceJSON   []byte          `json:"-"`
}

// Clone returns a deep copy of EngineConfig safe for concurrent background updates.
func (c *EngineConfig) Clone() *EngineConfig {
	if c == nil {
		return nil
	}
	cp := *c
	cp.Nodes = make([]NodeConfig, len(c.Nodes))
	for i, n := range c.Nodes {
		cp.Nodes[i] = n
		if len(n.Roles) > 0 {
			cp.Nodes[i].Roles = append([]string(nil), n.Roles...)
		}
	}
	if len(c.ActiveNode.Roles) > 0 {
		cp.ActiveNode.Roles = append([]string(nil), c.ActiveNode.Roles...)
	}
	if c.Categories != nil {
		cp.Categories = make(map[string]bool, len(c.Categories))
		for k, v := range c.Categories {
			cp.Categories[k] = v
		}
	}
	cp.ProxyDomains = append([]string(nil), c.ProxyDomains...)
	cp.DirectDomains = append([]string(nil), c.DirectDomains...)
	cp.CustomProxy = append([]string(nil), c.CustomProxy...)
	cp.CustomDirect = append([]string(nil), c.CustomDirect...)
	cp.PinnedSPKI = append([]string(nil), c.PinnedSPKI...)
	cp.EdgeSNIs = append([]string(nil), c.EdgeSNIs...)
	cp.DecoySNIs = append([]string(nil), c.DecoySNIs...)
	if c.V2.Categories != nil {
		cp.V2.Categories = make(map[string]bool, len(c.V2.Categories))
		for k, v := range c.V2.Categories {
			cp.V2.Categories[k] = v
		}
	}
	cp.V2.CustomProxy = append([]string(nil), c.V2.CustomProxy...)
	cp.V2.CustomDirect = append([]string(nil), c.V2.CustomDirect...)
	cp.RawSourceJSON = append([]byte(nil), c.RawSourceJSON...)
	return &cp
}

// DefaultEngineConfig initializes a sensible default configuration.
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		HTTPPort:        DefaultHTTPPort,
		SOCKSPort:       DefaultSOCKSPort,
		PreferredRegion: "auto",
		DeviceHWID:      ComputeDeviceHWID(),
		Categories: map[string]bool{
			"antigravity": true,
			"ai":          true,
			"mcp":         true,
			"media":       false,
			"social":      false,
		},
		PinnedSPKI: []string{DefaultPinnedSPKISHA256},
		EdgeSNIs:   append([]string(nil), DefaultEdgeSNIs...),
		DecoySNIs:  append([]string(nil), DefaultDecoySNIs...),
		V2: V2Config{
			PreferPWP4:        true,
			UTLSProfile:       "chrome",
			DPIProfile:        0,
			StandbyEnabled:    true,
			FailoverTimeoutMs: 150,
			SmartPAC:          true,
			PACRev:            1,
			PreferRoleRouting: true,
		},
		ActiveNode: NodeConfig{
			Name:           "Default-Edge",
			Region:         "EU",
			Host:           DefaultHost,
			Port:           443,
			SNI:            DefaultSNI,
			Path:           DefaultPWP3Path,
			PWP4Path:       DefaultPWP4Path,
			TLS:            true,
			Mux:            true,
			Frag:           true,
			EnableDpiSplit: true,
		},
	}
}

// activeConfigRaw models the C# active_config.json schema plus standalone fields.
type activeConfigRaw struct {
	HTTPIn *struct {
		Port     int  `json:"port"`
		AllowLan bool `json:"allowLan"`
	} `json:"http-in"`
	SOCKSIn *struct {
		Port     int  `json:"port"`
		AllowLan bool `json:"allowLan"`
	} `json:"socks-in"`
	V2 *struct {
		PreferPWP4        *bool           `json:"prefer_pwp4"`
		UTLSProfile       string          `json:"utls_profile"`
		DPIProfile        *int            `json:"dpi_profile"`
		StandbyEnabled    *bool           `json:"standby_enabled"`
		FailoverTimeoutMs *int            `json:"failover_timeout_ms"`
		WSLBridge         *bool           `json:"wsl_bridge"`
		SmartPAC          *bool           `json:"smart_pac"`
		PACRev            uint64          `json:"pac_rev"`
		ProxyAll          *bool           `json:"proxy_all"`
		Categories        map[string]bool `json:"categories"`
		CustomProxy       []string        `json:"custom_proxy_domains"`
		CustomDirect      []string        `json:"custom_direct_domains"`
		CustomProxyShort  []string        `json:"custom_proxy"`
		CustomDirectShort []string        `json:"custom_direct"`
		RoleRouting       *bool           `json:"role_routing"`
	} `json:"v2"`
	Outbounds []struct {
		Protocol string `json:"protocol"`
		Tag      string `json:"tag"`
		Settings struct {
			Vnext []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
				Users   []struct {
					ID string `json:"id"`
				} `json:"users"`
			} `json:"vnext"`
		} `json:"settings"`
		StreamSettings struct {
			Network         string   `json:"network"`
			Security        string   `json:"security"`
			PWPSecret       string   `json:"pwpSecret"`
			PWPPort         int      `json:"pwpPort"`
			PWPTLS          *bool    `json:"pwpTls"`
			PWPMux          *bool    `json:"pwpMux"`
			PWP4Path        string   `json:"pwp4Path"`
			PreferredRegion string   `json:"preferredRegion"`
			FragProfile     *int     `json:"fragProfile"`
			Roles           []string `json:"roles"`
			TLSSettings     *struct {
				ServerName string `json:"serverName"`
			} `json:"tlsSettings"`
		} `json:"streamSettings"`
	} `json:"outbounds"`
	Routing *struct {
		Rules []struct {
			Type        string   `json:"type"`
			Domain      []string `json:"domain"`
			IP          []string `json:"ip"`
			OutboundTag string   `json:"outboundTag"`
		} `json:"rules"`
		DefaultOutbound string `json:"defaultOutbound"`
	} `json:"routing"`

	// Flat/standalone JSON keys supported seamlessly
	HTTPPort          int             `json:"http_port"`
	SOCKSPort         int             `json:"socks_port"`
	EnableWSLBridge   *bool           `json:"wsl_bridge"`
	Address           string          `json:"address"`
	ID                string          `json:"id"`
	ServerName        string          `json:"serverName"`
	ServerNameSnake   string          `json:"server_name"`
	PWPSecret         string          `json:"pwpSecret"`
	PWPSecretSnake    string          `json:"pwp_secret"`
	PWPPort           int             `json:"pwpPort"`
	PWPPortSnake      int             `json:"pwp_port"`
	PWPTLS            *bool           `json:"pwpTls"`
	PWPTLSSnake       *bool           `json:"pwp_tls"`
	PWPMux            *bool           `json:"pwpMux"`
	PWPMuxSnake       *bool           `json:"pwp_mux"`
	PWP4Path          string          `json:"pwp4Path"`
	PWP4PathSnake     string          `json:"pwp4_path"`
	PreferredRegion   string          `json:"preferredRegion"`
	SubLink           string          `json:"subLink"`
	ClientUUID        string          `json:"client_uuid"`
	ProxyAll          *bool           `json:"proxy_all"`
	Categories        map[string]bool `json:"categories"`
	CustomProxy       []string        `json:"custom_proxy_domains"`
	CustomDirect      []string        `json:"custom_direct_domains"`
	CustomProxyShort  []string        `json:"custom_proxy"`
	CustomDirectShort []string        `json:"custom_direct"`
	PinnedSPKI        []string        `json:"pinned_spki"`
	Nodes             []NodeConfig    `json:"nodes"`
}

// LoadConfig loads active_config.json or standalone config JSON from path.
func LoadConfig(path string) (*EngineConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadConfigBytes(raw)
	if err != nil {
		return nil, err
	}
	cfg.ConfigPath = path
	cfg.RawSourceJSON = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	return cfg, nil
}

// LoadConfigBytes parses active_config.json or standalone config JSON bytes.
func LoadConfigBytes(raw []byte) (*EngineConfig, error) {
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	cfg := DefaultEngineConfig()
	if len(strings.TrimSpace(string(raw))) == 0 {
		cfg.ApplyFallbackManifestIfNeeded()
		cfg.RebuildEffectiveRules()
		return cfg, nil
	}
	var doc activeConfigRaw
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config json: %w", err)
	}

	if doc.HTTPPort > 0 {
		cfg.HTTPPort = doc.HTTPPort
	}
	if doc.SOCKSPort > 0 {
		cfg.SOCKSPort = doc.SOCKSPort
	}
	if doc.HTTPIn != nil {
		if doc.HTTPIn.Port > 0 {
			cfg.HTTPPort = doc.HTTPIn.Port
		}
		if doc.HTTPIn.AllowLan {
			cfg.EnableWSLBridge = true
		}
	}
	if doc.SOCKSIn != nil {
		if doc.SOCKSIn.Port > 0 {
			cfg.SOCKSPort = doc.SOCKSIn.Port
		}
		if doc.SOCKSIn.AllowLan {
			cfg.EnableWSLBridge = true
		}
	}
	if doc.EnableWSLBridge != nil {
		cfg.EnableWSLBridge = *doc.EnableWSLBridge
	}
	if doc.PreferredRegion != "" {
		cfg.PreferredRegion = strings.TrimSpace(doc.PreferredRegion)
	}
	if doc.SubLink != "" {
		cfg.SubLink = strings.TrimSpace(doc.SubLink)
	}
	if doc.ClientUUID != "" {
		cfg.ClientUUID = strings.TrimSpace(doc.ClientUUID)
	}
	if doc.ID != "" && cfg.ClientUUID == "" {
		cfg.ClientUUID = strings.TrimSpace(doc.ID)
	}

	hasExplicitEndpoint := false
	hasExplicitPWPPort := false
	hasExplicitSecret := false
	hasExplicitSNI := false

	// Outbound node extraction matching PixelCoreEngineV3.LoadCompatibleJsonString
	if len(doc.Outbounds) > 0 {
		for _, ob := range doc.Outbounds {
			if ob.Tag != "" && !strings.EqualFold(ob.Tag, "proxy") && !strings.EqualFold(ob.Tag, "out") {
				continue
			}
			ss := ob.StreamSettings
			if len(ob.Settings.Vnext) > 0 {
				vn := ob.Settings.Vnext[0]
				if vn.Address != "" {
					cfg.ActiveNode.Host = strings.TrimSpace(vn.Address)
					hasExplicitEndpoint = true
				}
				if vn.Port > 0 && ss.PWPPort <= 0 {
					cfg.ActiveNode.Port = vn.Port
					hasExplicitEndpoint = true
				}
				if len(vn.Users) > 0 && vn.Users[0].ID != "" {
					cfg.ClientUUID = strings.TrimSpace(vn.Users[0].ID)
					cfg.ActiveNode.UUID = cfg.ClientUUID
				}
			}
			if ss.PWPPort > 0 {
				cfg.ActiveNode.Port = ss.PWPPort
				hasExplicitEndpoint = true
				hasExplicitPWPPort = true
			}
			if ss.PWPSecret != "" {
				cfg.ActiveNode.Secret = ss.PWPSecret
				hasExplicitSecret = true
			}
			if ss.PWPTLS != nil {
				cfg.ActiveNode.TLS = *ss.PWPTLS
			}
			if ss.PWPMux != nil {
				cfg.ActiveNode.Mux = *ss.PWPMux
			}
			if ss.PWP4Path != "" {
				cfg.ActiveNode.PWP4Path = ss.PWP4Path
			}
			if ss.FragProfile != nil {
				cfg.ActiveNode.FragProfile = *ss.FragProfile
				cfg.V2.DPIProfile = *ss.FragProfile
			}
			if len(ss.Roles) > 0 {
				cfg.ActiveNode.Roles = append([]string(nil), ss.Roles...)
			}
			if ss.TLSSettings != nil && ss.TLSSettings.ServerName != "" {
				cfg.ActiveNode.SNI = strings.TrimSpace(ss.TLSSettings.ServerName)
				hasExplicitSNI = true
			}
			if ss.PreferredRegion != "" {
				cfg.PreferredRegion = strings.TrimSpace(ss.PreferredRegion)
			}
			break
		}
	}

	// Top-level overrides if supplied
	if doc.Address != "" {
		cfg.ActiveNode.Host = strings.TrimSpace(doc.Address)
		hasExplicitEndpoint = true
	}
	if doc.ServerName != "" {
		cfg.ActiveNode.SNI = strings.TrimSpace(doc.ServerName)
		hasExplicitSNI = true
	} else if doc.ServerNameSnake != "" {
		cfg.ActiveNode.SNI = strings.TrimSpace(doc.ServerNameSnake)
		hasExplicitSNI = true
	}
	if doc.PWPSecret != "" {
		cfg.ActiveNode.Secret = doc.PWPSecret
		hasExplicitSecret = true
	} else if doc.PWPSecretSnake != "" {
		cfg.ActiveNode.Secret = doc.PWPSecretSnake
		hasExplicitSecret = true
	}
	if doc.PWPPort > 0 {
		cfg.ActiveNode.Port = doc.PWPPort
		hasExplicitEndpoint = true
		hasExplicitPWPPort = true
	} else if doc.PWPPortSnake > 0 {
		cfg.ActiveNode.Port = doc.PWPPortSnake
		hasExplicitEndpoint = true
		hasExplicitPWPPort = true
	}
	if doc.PWPTLS != nil {
		cfg.ActiveNode.TLS = *doc.PWPTLS
	} else if doc.PWPTLSSnake != nil {
		cfg.ActiveNode.TLS = *doc.PWPTLSSnake
	}
	if doc.PWPMux != nil {
		cfg.ActiveNode.Mux = *doc.PWPMux
	} else if doc.PWPMuxSnake != nil {
		cfg.ActiveNode.Mux = *doc.PWPMuxSnake
	}
	effectiveTopPWP4Path := doc.PWP4Path
	if effectiveTopPWP4Path == "" {
		effectiveTopPWP4Path = doc.PWP4PathSnake
	}
	if effectiveTopPWP4Path != "" {
		cfg.ActiveNode.PWP4Path = effectiveTopPWP4Path
	}

	// Normalize legacy Reality cluster keys (e.g., node.pixelstore.space:8443 with SNI www.amd.com)
	// when no explicit PWP port or secret was supplied.
	if hasExplicitEndpoint && isClusterHost(cfg.ActiveNode.Host) && !hasExplicitPWPPort && !hasExplicitSecret {
		cfg.ActiveNode.Port = 443
		if strings.HasPrefix(strings.ToLower(cfg.ActiveNode.Host), "ws.") {
			cfg.ActiveNode.SNI = "ws.pixelstore.space"
		} else if !strings.HasSuffix(strings.ToLower(cfg.ActiveNode.SNI), ".pixelstore.space") {
			cfg.ActiveNode.SNI = DefaultSNI
		}
	}

	if len(doc.Nodes) > 0 {
		cfg.Nodes = doc.Nodes
		if !hasExplicitEndpoint {
			chosen := doc.Nodes[0]
			if chosen.Port <= 0 {
				chosen.Port = 443
			}
			if chosen.SNI == "" {
				chosen.SNI = cfg.ActiveNode.SNI
			}
			if chosen.Path == "" {
				chosen.Path = cfg.ActiveNode.Path
			}
			if chosen.PWP4Path == "" {
				chosen.PWP4Path = cfg.ActiveNode.PWP4Path
			}
			if chosen.Secret == "" {
				chosen.Secret = cfg.ActiveNode.Secret
			}
			if chosen.UUID == "" {
				chosen.UUID = cfg.ClientUUID
			}
			cfg.ActiveNode = chosen
		} else if cfg.ActiveNode.Name == "" || cfg.ActiveNode.Name == "Default-Edge" {
			for _, n := range doc.Nodes {
				if sameEndpoint(n, cfg.ActiveNode) {
					if n.Name != "" {
						cfg.ActiveNode.Name = n.Name
					}
					if n.Region != "" {
						cfg.ActiveNode.Region = n.Region
					}
					if len(cfg.ActiveNode.Roles) == 0 && len(n.Roles) > 0 {
						cfg.ActiveNode.Roles = append([]string(nil), n.Roles...)
					}
					if effectiveTopPWP4Path == "" && n.PWP4Path != "" {
						cfg.ActiveNode.PWP4Path = n.PWP4Path
					}
					if n.Path != "" && cfg.ActiveNode.Path == DefaultPWP3Path {
						cfg.ActiveNode.Path = n.Path
					}
					if cfg.ActiveNode.Secret == "" && n.Secret != "" {
						cfg.ActiveNode.Secret = n.Secret
					}
					if !hasExplicitSNI && n.SNI != "" {
						cfg.ActiveNode.SNI = n.SNI
					}
					if cfg.ActiveNode.UUID == "" && n.UUID != "" {
						cfg.ActiveNode.UUID = n.UUID
					}
					break
				}
			}
		}
		cfg.fillClusterSecretsFromFallback()
	} else if !hasExplicitEndpoint || isClusterHost(cfg.ActiveNode.Host) {
		cfg.applyManifestFallback(hasExplicitEndpoint, hasExplicitPWPPort, hasExplicitSecret, hasExplicitSNI, len(doc.PinnedSPKI) > 0)
	}
	if len(doc.PinnedSPKI) > 0 {
		var validPins []string
		for _, p := range doc.PinnedSPKI {
			norm := strings.ToLower(strings.TrimSpace(p))
			if len(norm) == 64 {
				if _, hErr := hex.DecodeString(norm); hErr == nil {
					validPins = append(validPins, norm)
				}
			}
		}
		if len(validPins) > 0 {
			cfg.PinnedSPKI = validPins
		}
	}

	hasExplicitCats := (doc.V2 != nil && doc.V2.Categories != nil) || doc.Categories != nil
	if hasExplicitCats {
		cfg.Categories = make(map[string]bool)
	}

	// V2 block overrides
	if doc.V2 != nil {
		if doc.V2.PreferPWP4 != nil {
			cfg.V2.PreferPWP4 = *doc.V2.PreferPWP4
		}
		if doc.V2.UTLSProfile != "" {
			cfg.V2.UTLSProfile = strings.ToLower(strings.TrimSpace(doc.V2.UTLSProfile))
		}
		if doc.V2.DPIProfile != nil {
			cfg.V2.DPIProfile = *doc.V2.DPIProfile
		}
		if doc.V2.StandbyEnabled != nil {
			cfg.V2.StandbyEnabled = *doc.V2.StandbyEnabled
		}
		if doc.V2.FailoverTimeoutMs != nil && *doc.V2.FailoverTimeoutMs > 0 {
			cfg.V2.FailoverTimeoutMs = *doc.V2.FailoverTimeoutMs
		}
		if doc.V2.WSLBridge != nil {
			cfg.EnableWSLBridge = *doc.V2.WSLBridge
			cfg.V2.WSLBridge = *doc.V2.WSLBridge
		}
		if doc.V2.SmartPAC != nil {
			cfg.V2.SmartPAC = *doc.V2.SmartPAC
		}
		if doc.V2.PACRev > 0 {
			cfg.V2.PACRev = doc.V2.PACRev
		}
		if doc.V2.ProxyAll != nil {
			cfg.ProxyAll = *doc.V2.ProxyAll
			cfg.V2.ProxyAll = *doc.V2.ProxyAll
		}
		if doc.V2.RoleRouting != nil {
			cfg.V2.PreferRoleRouting = *doc.V2.RoleRouting
		}
		for k, v := range doc.V2.Categories {
			cfg.Categories[strings.ToLower(strings.TrimSpace(k))] = v
		}
		if len(doc.V2.CustomProxy) > 0 {
			cfg.CustomProxy = append(cfg.CustomProxy, doc.V2.CustomProxy...)
		} else if len(doc.V2.CustomProxyShort) > 0 {
			cfg.CustomProxy = append(cfg.CustomProxy, doc.V2.CustomProxyShort...)
		}
		if len(doc.V2.CustomDirect) > 0 {
			cfg.CustomDirect = append(cfg.CustomDirect, doc.V2.CustomDirect...)
		} else if len(doc.V2.CustomDirectShort) > 0 {
			cfg.CustomDirect = append(cfg.CustomDirect, doc.V2.CustomDirectShort...)
		}
	}

	if doc.ProxyAll != nil {
		cfg.ProxyAll = *doc.ProxyAll
	}
	for k, v := range doc.Categories {
		cfg.Categories[strings.ToLower(strings.TrimSpace(k))] = v
	}
	if len(doc.CustomProxy) > 0 {
		cfg.CustomProxy = append(cfg.CustomProxy, doc.CustomProxy...)
	} else if len(doc.CustomProxyShort) > 0 {
		cfg.CustomProxy = append(cfg.CustomProxy, doc.CustomProxyShort...)
	}
	if len(doc.CustomDirect) > 0 {
		cfg.CustomDirect = append(cfg.CustomDirect, doc.CustomDirect...)
	} else if len(doc.CustomDirectShort) > 0 {
		cfg.CustomDirect = append(cfg.CustomDirect, doc.CustomDirectShort...)
	}

	// Routing rules matching C# active_config.json
	if doc.Routing != nil {
		if strings.EqualFold(doc.Routing.DefaultOutbound, "proxy") {
			cfg.ProxyAll = true
		}
		for _, r := range doc.Routing.Rules {
			tag := strings.ToLower(strings.TrimSpace(r.OutboundTag))
			for _, d := range r.Domain {
				norm := normalizeDomainPattern(d)
				if norm == "" {
					continue
				}
				switch tag {
				case "direct":
					cfg.DirectDomains = append(cfg.DirectDomains, norm)
				case "proxy":
					cfg.ProxyDomains = append(cfg.ProxyDomains, norm)
				}
			}
		}
	}

	cfg.RebuildEffectiveRules()
	return cfg, nil
}

func isClusterHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	return h == "node.pixelstore.space" ||
		h == "ai.pixelstore.space" ||
		h == "dns.pixelstore.space" ||
		h == "ws.pixelstore.space" ||
		h == DefaultHost ||
		h == "185.103.103.162" ||
		strings.HasSuffix(h, ".pixelstore.space")
}

// ApplyFallbackManifestIfNeeded populates Nodes and ActiveNode.Secret from the cached or embedded
// signed manifest when no usable secret or node list is configured yet.
func (cfg *EngineConfig) ApplyFallbackManifestIfNeeded() {
	if cfg == nil {
		return
	}
	if len(cfg.Nodes) == 0 || (cfg.ActiveNode.Secret == "" && (cfg.ActiveNode.Host == "" || isClusterHost(cfg.ActiveNode.Host))) {
		cfg.applyManifestFallback(false, false, cfg.ActiveNode.Secret != "", cfg.ActiveNode.SNI != "", false)
	}
}

func (cfg *EngineConfig) fillClusterSecretsFromFallback() {
	if cfg == nil {
		return
	}
	needsSecret := cfg.ActiveNode.Secret == "" && isClusterHost(cfg.ActiveNode.Host)
	if !needsSecret {
		for _, n := range cfg.Nodes {
			if n.Secret == "" && isClusterHost(n.Host) {
				needsSecret = true
				break
			}
		}
	}
	if !needsSecret {
		return
	}
	doc, _, err := LoadCachedOrEmbeddedManifest(ManifestVerifierOptions{})
	if err != nil || doc == nil {
		return
	}
	fallbackSecret := strings.TrimSpace(doc.Secret)
	if fallbackSecret == "" && len(doc.Nodes) > 0 {
		fallbackSecret = strings.TrimSpace(doc.Nodes[0].Secret)
	}
	if fallbackSecret == "" {
		return
	}
	if cfg.ActiveNode.Secret == "" && isClusterHost(cfg.ActiveNode.Host) {
		cfg.ActiveNode.Secret = fallbackSecret
	}
	for i := range cfg.Nodes {
		if cfg.Nodes[i].Secret == "" && isClusterHost(cfg.Nodes[i].Host) {
			cfg.Nodes[i].Secret = fallbackSecret
		}
	}
}

func (cfg *EngineConfig) applyManifestFallback(hasExplicitEndpoint, hasExplicitPWPPort, hasExplicitSecret, hasExplicitSNI, hasExplicitPins bool) {
	if cfg == nil {
		return
	}
	doc, _, err := LoadCachedOrEmbeddedManifest(ManifestVerifierOptions{})
	if err != nil || doc == nil || len(doc.Nodes) == 0 {
		return
	}

	if !hasExplicitPins && (len(doc.SPKISHA256) > 0 || len(doc.CertPins) > 0) {
		pinSet := make(map[string]struct{})
		addPin := func(p string) {
			if norm := normalizeHexPin(p); norm != "" {
				pinSet[norm] = struct{}{}
			}
		}
		addPin(DefaultPinnedSPKISHA256)
		for _, p := range cfg.PinnedSPKI {
			addPin(p)
		}
		for _, p := range doc.SPKISHA256 {
			addPin(p)
		}
		for _, p := range doc.CertPins {
			addPin(p)
		}
		cfg.PinnedSPKI = sortedSetKeys(pinSet)
	}
	if len(doc.EdgeSNIs) > 0 {
		cfg.EdgeSNIs = append([]string(nil), doc.EdgeSNIs...)
	}
	if len(doc.DecoySNIs) > 0 {
		cfg.DecoySNIs = append([]string(nil), doc.DecoySNIs...)
	}

	nodes := make([]NodeConfig, len(doc.Nodes))
	copy(nodes, doc.Nodes)
	for i := range nodes {
		if nodes[i].UUID == "" {
			nodes[i].UUID = cfg.ClientUUID
		}
		if nodes[i].Secret == "" && doc.Secret != "" {
			nodes[i].Secret = doc.Secret
		}
	}
	cfg.Nodes = nodes

	if !hasExplicitEndpoint || (isClusterHost(cfg.ActiveNode.Host) && !hasExplicitPWPPort && !hasExplicitSecret) {
		chosen := nodes[0]
		if cfg.PreferredRegion != "" && !strings.EqualFold(cfg.PreferredRegion, "auto") {
			for _, n := range nodes {
				if strings.EqualFold(n.Region, cfg.PreferredRegion) || strings.EqualFold(n.Name, cfg.PreferredRegion) {
					chosen = n
					break
				}
			}
		} else if hasExplicitEndpoint && cfg.ActiveNode.Host != "" {
			for _, n := range nodes {
				if sameEndpoint(n, cfg.ActiveNode) {
					chosen = n
					break
				}
			}
		}
		if hasExplicitSecret && cfg.ActiveNode.Secret != "" {
			chosen.Secret = cfg.ActiveNode.Secret
		}
		if hasExplicitSNI && strings.HasSuffix(strings.ToLower(cfg.ActiveNode.SNI), ".pixelstore.space") {
			chosen.SNI = cfg.ActiveNode.SNI
		}
		if chosen.UUID == "" {
			chosen.UUID = cfg.ClientUUID
		}
		cfg.ActiveNode = chosen
		return
	}

	// Explicit PWP port or secret on a cluster host: preserve explicit endpoint & fill missing secret/path.
	if cfg.ActiveNode.Secret == "" {
		for _, n := range nodes {
			if sameEndpoint(n, cfg.ActiveNode) && n.Secret != "" {
				cfg.ActiveNode.Secret = n.Secret
				break
			}
		}
		if cfg.ActiveNode.Secret == "" {
			if strings.TrimSpace(doc.Secret) != "" {
				cfg.ActiveNode.Secret = strings.TrimSpace(doc.Secret)
			} else if len(nodes) > 0 {
				cfg.ActiveNode.Secret = nodes[0].Secret
			}
		}
	}
	if cfg.ActiveNode.PWP4Path == "" {
		cfg.ActiveNode.PWP4Path = DefaultPWP4Path
	}
}

// SaveConfig writes standalone configuration JSON cleanly to path.
func SaveConfig(path string, cfg *EngineConfig) error {
	if path == "" || cfg == nil {
		return errors.New("invalid path or config")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	cfg.V2.WSLBridge = cfg.EnableWSLBridge
	cfg.V2.ProxyAll = cfg.ProxyAll
	cfg.V2.Categories = cfg.Categories
	cfg.V2.CustomProxy = cfg.CustomProxy
	cfg.V2.CustomDirect = cfg.CustomDirect
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RebuildEffectiveRules computes deduplicated ProxyDomains and DirectDomains from categories + custom lists.
func (cfg *EngineConfig) RebuildEffectiveRules() {
	proxySet := make(map[string]struct{})
	directSet := make(map[string]struct{})

	addProxy := func(s string) {
		n := normalizeDomainPattern(s)
		if n != "" {
			proxySet[n] = struct{}{}
		}
	}
	addDirect := func(s string) {
		n := normalizeDomainPattern(s)
		if n != "" {
			directSet[n] = struct{}{}
		}
	}

	for _, d := range BuiltinDirectDomains {
		addDirect(d)
	}
	for _, d := range cfg.DirectDomains {
		addDirect(d)
	}
	for _, d := range cfg.CustomDirect {
		addDirect(d)
	}

	for cat, enabled := range cfg.Categories {
		if !enabled {
			continue
		}
		for _, d := range CategoryDomains[strings.ToLower(cat)] {
			addProxy(d)
		}
	}
	for _, d := range cfg.ProxyDomains {
		addProxy(d)
	}
	for _, d := range cfg.CustomProxy {
		addProxy(d)
	}
	if cfg.ActiveNode.Host != "" {
		addDirect(cfg.ActiveNode.Host)
	}
	if cfg.ActiveNode.SNI != "" {
		addDirect(cfg.ActiveNode.SNI)
	}

	cfg.ProxyDomains = sortedSetKeys(proxySet)
	cfg.DirectDomains = sortedSetKeys(directSet)
}

func sortedSetKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// deterministic simple insertion/bubble or sort without pulling extra package;
	// Wait: use small in-place sort helper
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1] > out[j] {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func normalizeDomainPattern(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	for _, prefix := range []string{"domain:", "full:", "geosite:"} {
		if strings.HasPrefix(s, prefix) {
			s = strings.TrimSpace(strings.TrimPrefix(s, prefix))
			break
		}
	}
	if strings.HasPrefix(s, "*.") {
		s = "." + strings.TrimPrefix(s, "*.")
	}
	return s
}

// ParsedKey represents a validated PRO activation key or URI.
type ParsedKey struct {
	Raw      string
	Format   string // "uuid", "vless", "pwp4", "pwp3", "pwp1", "sub"
	UUID     string
	SubLink  string
	Host     string
	Port     int
	SNI      string
	Secret   string
	Path     string
	PWP4Path string
	TLS      bool
	Mux      bool
}

// ApplyParsedKey updates cfg fields (including custom node Path/PWP4Path) from a validated PRO key.
func (cfg *EngineConfig) ApplyParsedKey(pk *ParsedKey) {
	if cfg == nil || pk == nil {
		return
	}
	if pk.UUID != "" {
		cfg.ClientUUID = pk.UUID
		cfg.ActiveNode.UUID = pk.UUID
	}
	if pk.SubLink != "" {
		cfg.SubLink = pk.SubLink
	}
	if pk.Host != "" && pk.Format != "uuid" && pk.Format != "sub" {
		cfg.ActiveNode.Host = pk.Host
		if pk.Port > 0 {
			cfg.ActiveNode.Port = pk.Port
		}
		if pk.SNI != "" {
			cfg.ActiveNode.SNI = pk.SNI
		}
		if pk.Secret != "" {
			cfg.ActiveNode.Secret = pk.Secret
		}
		if pk.Path != "" {
			cfg.ActiveNode.Path = pk.Path
		}
		if pk.PWP4Path != "" {
			cfg.ActiveNode.PWP4Path = pk.PWP4Path
		}
		cfg.ActiveNode.TLS = pk.TLS
		cfg.ActiveNode.Mux = pk.Mux
	}
	cfg.RebuildEffectiveRules()
}

// IsTrialOrFreeKey returns true for blank keys, "free", and the 3 legacy trial UUIDs.
func IsTrialOrFreeKey(raw string) bool {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" || s == "free" {
		return true
	}
	_, isTrial := legacyTrialUUIDs[s]
	return isTrial
}

// ParseKeyInput validates and parses PRO keys matching bot.py + auth.go + PixelTunnelNext.cs:
//   - Bare 36-char UUID (normalized lowercase)
//   - vless://<uuid>@host:port?...
//   - pwp4://<uuid>@host:port?...
//   - pwp3://<uuid>@host:port?...
//   - pwp1://...
//   - https://ai.pixelstore.space/sub/<sub_id>
//   - pixeltunnel://activate?key=<encoded>
func ParseKeyInput(raw string) (*ParsedKey, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return nil, ErrTrialKeyNotPro
	}

	// Unwrap pixeltunnel://activate?key=<encoded>
	if strings.HasPrefix(strings.ToLower(input), "pixeltunnel://") {
		u, err := url.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		q := u.Query()
		if k := strings.TrimSpace(q.Get("key")); k != "" {
			input = k
		} else if sub := strings.TrimSpace(q.Get("sub")); sub != "" {
			input = sub
		} else {
			return nil, fmt.Errorf("%w: missing key param in URI", ErrInvalidKey)
		}
	}

	// Unwrap https://ai.pixelstore.space/activate#<encoded>
	if strings.HasPrefix(strings.ToLower(input), "https://ai.pixelstore.space/activate#") ||
		strings.HasPrefix(strings.ToLower(input), "http://ai.pixelstore.space/activate#") {
		if u, err := url.Parse(input); err == nil && u.Fragment != "" {
			if dec, err := url.PathUnescape(u.Fragment); err == nil && dec != "" {
				input = strings.TrimSpace(dec)
			} else {
				input = strings.TrimSpace(u.Fragment)
			}
		}
	}

	if IsTrialOrFreeKey(input) {
		return nil, ErrTrialKeyNotPro
	}

	// Bare 36-char UUID
	if uuidRegex.MatchString(input) {
		uuid := strings.ToLower(input)
		if IsTrialOrFreeKey(uuid) {
			return nil, ErrTrialKeyNotPro
		}
		return &ParsedKey{
			Raw:      uuid,
			Format:   "uuid",
			UUID:     uuid,
			Host:     DefaultHost,
			Port:     443,
			SNI:      DefaultSNI,
			PWP4Path: DefaultPWP4Path,
			Path:     DefaultPWP3Path,
			TLS:      true,
			Mux:      true,
		}, nil
	}

	// Subscription URL: https://ai.pixelstore.space/sub/<sub_id>
	lower := strings.ToLower(input)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		u, err := url.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		if strings.HasPrefix(u.Path, "/sub/") {
			subID := strings.Trim(strings.TrimPrefix(u.Path, "/sub/"), "/")
			if !subIDRegex.MatchString(subID) {
				return nil, fmt.Errorf("%w: invalid subscription id", ErrInvalidKey)
			}
			return &ParsedKey{
				Raw:     input,
				Format:  "sub",
				SubLink: input,
				Host:    DefaultHost,
				Port:    443,
				SNI:     DefaultSNI,
				TLS:     true,
				Mux:     true,
			}, nil
		}
		return nil, fmt.Errorf("%w: unsupported HTTP URL", ErrInvalidKey)
	}

	// Proxy URIs: vless://, pwp4://, pwp3://, pwp1://
	for _, scheme := range []string{"vless", "pwp4", "pwp3", "pwp1"} {
		if strings.HasPrefix(lower, scheme+"://") {
			u, err := url.Parse(input)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
			}
			uuid := ""
			if u.User != nil {
				uuid = strings.ToLower(strings.TrimSpace(u.User.Username()))
			}
			if !uuidRegex.MatchString(uuid) {
				return nil, fmt.Errorf("%w: invalid UUID in %s URI", ErrInvalidKey, scheme)
			}
			if IsTrialOrFreeKey(uuid) {
				return nil, ErrTrialKeyNotPro
			}
			host := u.Hostname()
			if host == "" {
				host = DefaultHost
			}
			port := 443
			if p := u.Port(); p != "" {
				var parsedPort int
				if _, err := fmt.Sscanf(p, "%d", &parsedPort); err == nil && parsedPort > 0 && parsedPort <= 65535 {
					port = parsedPort
				}
			}
			q := u.Query()
			sni := q.Get("sni")
			if sni == "" {
				sni = q.Get("servername")
			}
			if sni == "" {
				sni = DefaultSNI
			}
			pwp4Path := q.Get("pwp4_path")
			if pwp4Path == "" {
				pwp4Path = q.Get("path")
			}
			if pwp4Path == "" {
				pwp4Path = DefaultPWP4Path
			}
			secret := q.Get("secret")
			if secret == "" {
				secret = q.Get("pwpSecret")
			}
			return &ParsedKey{
				Raw:      input,
				Format:   scheme,
				UUID:     uuid,
				Host:     host,
				Port:     port,
				SNI:      sni,
				Secret:   secret,
				Path:     DefaultPWP3Path,
				PWP4Path: pwp4Path,
				TLS:      true,
				Mux:      true,
			}, nil
		}
	}

	return nil, ErrInvalidKey
}

// RuleAction is the routing decision returned by DomainRuleMatcher.
type RuleAction struct {
	Action string // "PROXY" or "DIRECT"
	Rule   string // e.g. "ai", "direct_builtin", "custom_proxy", "proxy_all", "default"
	Role   string // "ai" or "media"
}

// DomainRuleMatcher decides PROXY vs DIRECT synchronously with zero DNS lookups.
type DomainRuleMatcher struct {
	mu           sync.RWMutex
	proxyAll     bool
	exactDirect  map[string]struct{}
	suffixDirect []string
	exactProxy   map[string]string // domain -> rule label
	suffixProxy  []suffixRule
	aiSuffixes   []string
	mediaSuffix  []string
}

type suffixRule struct {
	suffix string
	rule   string
}

// NewDomainRuleMatcher constructs a matcher from EngineConfig.
func NewDomainRuleMatcher(cfg *EngineConfig) *DomainRuleMatcher {
	aiList := make([]string, 0, len(CategoryDomains["antigravity"])+len(CategoryDomains["ai"]))
	aiList = append(aiList, CategoryDomains["antigravity"]...)
	aiList = append(aiList, CategoryDomains["ai"]...)

	mediaList := make([]string, 0, len(CategoryDomains["media"])+len(CategoryDomains["social"]))
	mediaList = append(mediaList, CategoryDomains["media"]...)
	mediaList = append(mediaList, CategoryDomains["social"]...)

	m := &DomainRuleMatcher{
		aiSuffixes:  aiList,
		mediaSuffix: mediaList,
	}
	m.UpdateFromConfig(cfg)
	return m
}

// UpdateFromConfig rebuilds matcher tables safely under write lock.
func (m *DomainRuleMatcher) UpdateFromConfig(cfg *EngineConfig) {
	exactDirect := map[string]struct{}{
		"localhost":             {},
		"localhost.localdomain": {},
	}
	var suffixDirect []string
	for _, pat := range cfg.DirectDomains {
		p := normalizeDomainPattern(pat)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, ".") {
			suffixDirect = append(suffixDirect, p)
		} else {
			exactDirect[p] = struct{}{}
			suffixDirect = append(suffixDirect, "."+p)
		}
	}

	// Build labeled proxy map from categories + custom + explicit rules
	exactProxy := make(map[string]string)
	var suffixProxy []suffixRule

	addProxyRule := func(pat, label string) {
		p := normalizeDomainPattern(pat)
		if p == "" {
			return
		}
		if strings.HasPrefix(p, ".") {
			suffixProxy = append(suffixProxy, suffixRule{suffix: p, rule: label})
		} else {
			exactProxy[p] = label
			suffixProxy = append(suffixProxy, suffixRule{suffix: "." + p, rule: label})
		}
	}

	for cat, enabled := range cfg.Categories {
		if !enabled {
			continue
		}
		for _, d := range CategoryDomains[strings.ToLower(cat)] {
			addProxyRule(d, strings.ToLower(cat))
		}
	}
	for _, d := range cfg.ProxyDomains {
		p := normalizeDomainPattern(d)
		if _, ok := exactProxy[p]; !ok {
			addProxyRule(p, "config_proxy")
		}
	}
	for _, d := range cfg.CustomProxy {
		addProxyRule(d, "custom_proxy")
	}

	m.mu.Lock()
	m.proxyAll = cfg.ProxyAll
	m.exactDirect = exactDirect
	m.suffixDirect = suffixDirect
	m.exactProxy = exactProxy
	m.suffixProxy = suffixProxy
	m.mu.Unlock()
}

// Classify decides PROXY vs DIRECT and AI vs Media role for host without any DNS call.
func (m *DomainRuleMatcher) Classify(host string) RuleAction {
	h := normalizeHostForMatch(host)
	if h == "" {
		return RuleAction{Action: "DIRECT", Rule: "empty", Role: "ai"}
	}

	// Always direct loopback / private / link-local IP literals
	if ip := net.ParseIP(h); ip != nil {
		if IsPrivateOrReservedIP(ip) {
			return RuleAction{Action: "DIRECT", Rule: "private_ip", Role: "ai"}
		}
	}

	role := m.inferRole(h)

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.exactDirect[h]; ok {
		return RuleAction{Action: "DIRECT", Rule: "direct_rule", Role: role}
	}
	for _, suf := range m.suffixDirect {
		if strings.HasSuffix(h, suf) {
			return RuleAction{Action: "DIRECT", Rule: "direct_suffix", Role: role}
		}
	}

	if lbl, ok := m.exactProxy[h]; ok {
		return RuleAction{Action: "PROXY", Rule: lbl, Role: role}
	}
	for _, sr := range m.suffixProxy {
		if strings.HasSuffix(h, sr.suffix) {
			return RuleAction{Action: "PROXY", Rule: sr.rule, Role: role}
		}
	}

	if m.proxyAll {
		return RuleAction{Action: "PROXY", Rule: "proxy_all", Role: role}
	}
	return RuleAction{Action: "DIRECT", Rule: "default_direct", Role: role}
}

func (m *DomainRuleMatcher) inferRole(h string) string {
	for _, d := range m.mediaSuffix {
		if h == d || strings.HasSuffix(h, "."+d) {
			return "media"
		}
	}
	return "ai"
}

func normalizeHostForMatch(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") && strings.Contains(h, "]") {
		if idx := strings.IndexByte(h, ']'); idx > 1 {
			h = h[1:idx]
		}
	} else if parsedHost, _, err := net.SplitHostPort(h); err == nil {
		h = parsedHost
	}
	return strings.TrimSuffix(strings.Trim(h, "[]"), ".")
}

// IsPrivateOrReservedIP returns true for loopback, unspecified, link-local, RFC1918, ULA, or multicast IPs.
func IsPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 (CGNAT / carrier sinkhole range)
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}

// ComputeDeviceHWID generates a deterministic cross-platform short hardware identifier.
func ComputeDeviceHWID() string {
	h := sha256.New()
	_, _ = h.Write([]byte(runtime.GOOS + "|" + runtime.GOARCH + "|"))
	if hn, err := os.Hostname(); err == nil {
		_, _ = h.Write([]byte(hn))
	}
	if mid, err := os.ReadFile("/etc/machine-id"); err == nil && len(mid) > 0 {
		_, _ = h.Write(mid)
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if (iface.Flags&net.FlagLoopback) != 0 || len(iface.HardwareAddr) == 0 {
				continue
			}
			_, _ = h.Write(iface.HardwareAddr)
			break
		}
	}
	sum := h.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(sum[:8]))
}

// DefaultStateDir returns the per-user PixelTunnel configuration/state directory.
func DefaultStateDir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "PixelTunnel")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "pixeltunnel")
}
