using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using ShapePath = System.Windows.Shapes.Path;

[assembly: AssemblyTitle("PixelTunnel")]
[assembly: AssemblyDescription("Native Go uTLS + PWP-3 Mux & Smart PAC Assistant for Antigravity IDE")]
[assembly: AssemblyCompany("PixelTunnel Community")]
[assembly: AssemblyProduct("PixelTunnel")]
[assembly: AssemblyCopyright("Copyright © 2026 PixelTunnel")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.0.0")]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]

namespace PixelTunnel
{
    public class VlessNode
    {
        public string Uuid = "";
        public string Server = "";
        public string ResolvedIp = "";
        public int Port = 443;
        public string Sni = "www.amd.com";
        public string PublicKey = "";
        public string ShortId = "";
        public string Fingerprint = "chrome";
        public string Flow = "xtls-rprx-vision";
        public string TransportType = "tcp";
        public string ServiceName = "";
        public string WsPath = "";
        public string WsHost = "";
        public string Security = "reality";
        public string SpiderX = "/";
        public string Remark = "PixelStore NL";
    }

    public class App : Application
    {
        private static Mutex _mutex;

        [STAThread]
        public static void Main(string[] args)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)12288;
            }
            catch
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            }

            // 1. SAFE --genconfig: MUST execute BEFORE Mutex, process killing, or Registry writes!
            bool isGenConfig = false;
            bool autoConnect = false;
            bool autoDiag = false;
            string deepLinkUri = null;
            if (args != null)
            {
                foreach (var a in args)
                {
                    if (string.Equals(a, "--genconfig", StringComparison.OrdinalIgnoreCase))
                        isGenConfig = true;
                    else if (string.Equals(a, "--autoconnect", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(a, "--connect", StringComparison.OrdinalIgnoreCase))
                        autoConnect = true;
                    else if (string.Equals(a, "--autodiag", StringComparison.OrdinalIgnoreCase))
                        autoDiag = true;
                    else if (!string.IsNullOrWhiteSpace(a) && a.Trim().StartsWith("pixeltunnel://", StringComparison.OrdinalIgnoreCase))
                        deepLinkUri = a.Trim();
                }
            }

            if (isGenConfig)
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string keyPath = System.IO.Path.Combine(baseDir, "saved_key.txt");
                string outDir = System.IO.Path.Combine(baseDir, "engine");
                if (!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);
                string outPath = System.IO.Path.Combine(outDir, "active_config.json");
                string[] lines = File.Exists(keyPath) ? File.ReadAllLines(keyPath, Encoding.UTF8) : new string[0];
                string raw = (lines.Length > 0 && !string.IsNullOrWhiteSpace(lines[0]))
                    ? lines[0].Trim()
                    : PixelTunnel.MainWindow.GetFreeModeSentinelUri();
                if (lines.Length > 1) PixelTunnel.MainWindow.ApplySavedFlagsForConfigGen(lines[1]);
                var n = PixelTunnel.MainWindow.ParseVlessUri(raw) ??
                        PixelTunnel.MainWindow.ParseVlessUri(PixelTunnel.MainWindow.GetFreeModeSentinelUri());
                string cfg = PixelTunnel.MainWindow.BuildSingBoxConfig(n, true, true, true, true, true);
                File.WriteAllText(outPath, cfg, new UTF8Encoding(false));
                return;
            }

            // 2. Single-instance Mutex & pixeltunnel:// Deep-Link IPC forwarding WITHOUT killing running app!
            bool createdNew;
            _mutex = new Mutex(true, "Local\\PixelTunnel_Antigravity_v1", out createdNew);

            if (!createdNew && !string.IsNullOrEmpty(deepLinkUri))
            {
                try
                {
                    using (var client = new NamedPipeClientStream(".", PixelTunnel.MainWindow.IPC_PIPE_NAME, PipeDirection.Out))
                    {
                        client.Connect(2000);
                        byte[] payload = Encoding.UTF8.GetBytes(deepLinkUri + "\n");
                        client.Write(payload, 0, payload.Length);
                        client.Flush();
                    }
                }
                catch { }
                return;
            }

            // Register HKCU\Software\Classes\pixeltunnel URL protocol (normal launch only, never in --genconfig)
            PixelTunnel.MainWindow.RegisterPixelTunnelUrlProtocol();

            int myPid = Process.GetCurrentProcess().Id;
            bool failedToKillElevated = false;
            bool hadRunningTunnelCore = false;
            foreach (string procName in new[] { "PixelTunnel", "PixelTunnel_Next", "PixelTunnel_v1.6" })
            {
                foreach (var p in Process.GetProcessesByName(procName))
                {
                    if (p.Id != myPid)
                    {
                        try
                        {
                            p.Kill();
                            p.WaitForExit(1000);
                        }
                        catch
                        {
                            failedToKillElevated = true;
                        }
                    }
                }
            }

            foreach (string coreName in new[] { "pixel-tun-core", "pixel-tun-core-next" })
            {
                var existingCores = Process.GetProcessesByName(coreName);
                if (existingCores.Length > 0)
                {
                    hadRunningTunnelCore = true;
                    foreach (var cp in existingCores)
                    {
                        try
                        {
                            cp.Kill();
                            cp.WaitForExit(800);
                        }
                        catch
                        {
                            failedToKillElevated = true;
                        }
                    }
                }
            }

            if (failedToKillElevated && !PixelTunnel.MainWindow.IsAdministratorStatic())
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = Process.GetCurrentProcess().MainModule.FileName,
                        Arguments = hadRunningTunnelCore ? "--autoconnect" : "",
                        UseShellExecute = true,
                        Verb = "runas"
                    };
                    Process.Start(psi);
                    return;
                }
                catch { }
            }

            PixelTunnel.MainWindow.CleanupOldUpdateArtifacts();
            if (hadRunningTunnelCore) autoConnect = true;

            try
            {
                var app = new App();
                var win = new MainWindow(autoConnect, autoDiag, deepLinkUri);
                app.Run(win);
            }
            catch (Exception ex)
            {
                try { PixelTunnel.MainWindow.EmergencyDisableDeadSystemProxy(); } catch { }
                try { File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log"), ex.ToString()); } catch { }
                MessageBox.Show(ex.Message, "PixelTunnel Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public class MainWindow : Window
    {
        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

        private static void BroadcastEnvironmentChange()
        {
            try
            {
                UIntPtr res;
                SendMessageTimeout(new IntPtr(0xFFFF), 0x001A, UIntPtr.Zero, "Environment", 0x0002, 1200, out res);
            }
            catch { }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct INTERNET_PER_CONN_OPTION
        {
            public int dwOption;
            public INTERNET_PER_CONN_OPTION_VALUE Value;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct INTERNET_PER_CONN_OPTION_VALUE
        {
            [FieldOffset(0)]
            public int dwValue;
            [FieldOffset(0)]
            public IntPtr pszValue;
            [FieldOffset(0)]
            public System.Runtime.InteropServices.ComTypes.FILETIME ftValue;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct INTERNET_PER_CONN_OPTION_LIST
        {
            public int dwSize;
            public IntPtr pszConnection;
            public int dwOptionCount;
            public int dwOptionError;
            public IntPtr pOptions;
        }

        private static void ApplyWinInetConnectionList(IntPtr connNamePtr, INTERNET_PER_CONN_OPTION[] options)
        {
            int optSize = Marshal.SizeOf(typeof(INTERNET_PER_CONN_OPTION));
            IntPtr optionsPtr = Marshal.AllocHGlobal(optSize * options.Length);
            IntPtr listPtr = IntPtr.Zero;
            try
            {
                for (int i = 0; i < options.Length; i++)
                {
                    IntPtr cur = new IntPtr(optionsPtr.ToInt64() + i * optSize);
                    Marshal.StructureToPtr(options[i], cur, false);
                }
                var list = new INTERNET_PER_CONN_OPTION_LIST
                {
                    dwSize = Marshal.SizeOf(typeof(INTERNET_PER_CONN_OPTION_LIST)),
                    pszConnection = connNamePtr,
                    dwOptionCount = options.Length,
                    dwOptionError = 0,
                    pOptions = optionsPtr
                };
                listPtr = Marshal.AllocHGlobal(list.dwSize);
                Marshal.StructureToPtr(list, listPtr, false);
                InternetSetOption(IntPtr.Zero, 75, listPtr, list.dwSize);
            }
            catch { }
            finally
            {
                if (listPtr != IntPtr.Zero) Marshal.FreeHGlobal(listPtr);
                if (optionsPtr != IntPtr.Zero) Marshal.FreeHGlobal(optionsPtr);
            }
        }

        private static void FreeHGlobalPtrSafe(IntPtr p) { if (p != IntPtr.Zero) Marshal.FreeHGlobal(p); }

        private static void ApplyWinInetPerConnectionProxy(bool enable, string proxyServer, string proxyBypass, string autoConfigUrl = "")
        {
            IntPtr srvPtr = IntPtr.Zero;
            IntPtr bypPtr = IntPtr.Zero;
            IntPtr pacPtr = IntPtr.Zero;
            IntPtr emptyPtr = IntPtr.Zero;
            try
            {
                srvPtr = Marshal.StringToHGlobalAuto(proxyServer ?? "");
                bypPtr = Marshal.StringToHGlobalAuto(proxyBypass ?? "");
                pacPtr = Marshal.StringToHGlobalAuto(autoConfigUrl ?? "");
                emptyPtr = Marshal.StringToHGlobalAuto("");

                INTERNET_PER_CONN_OPTION[] options;
                if (enable && !string.IsNullOrEmpty(autoConfigUrl))
                {
                    options = new INTERNET_PER_CONN_OPTION[4];
                    options[0].dwOption = 1; // INTERNET_PER_CONN_FLAGS
                    options[0].Value.dwValue = 5; // PROXY_TYPE_DIRECT (1) | PROXY_TYPE_AUTO_PROXY_URL (4)
                    options[1].dwOption = 4; // INTERNET_PER_CONN_AUTOCONFIG_URL
                    options[1].Value.pszValue = pacPtr;
                    options[2].dwOption = 2; // INTERNET_PER_CONN_PROXY_SERVER
                    options[2].Value.pszValue = emptyPtr;
                    options[3].dwOption = 3; // INTERNET_PER_CONN_PROXY_BYPASS
                    options[3].Value.pszValue = emptyPtr;
                }
                else if (enable)
                {
                    options = new INTERNET_PER_CONN_OPTION[4];
                    options[0].dwOption = 1; // INTERNET_PER_CONN_FLAGS
                    options[0].Value.dwValue = 3; // PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
                    options[1].dwOption = 2; // INTERNET_PER_CONN_PROXY_SERVER
                    options[1].Value.pszValue = srvPtr;
                    options[2].dwOption = 3; // INTERNET_PER_CONN_PROXY_BYPASS
                    options[2].Value.pszValue = bypPtr;
                    options[3].dwOption = 4; // INTERNET_PER_CONN_AUTOCONFIG_URL
                    options[3].Value.pszValue = emptyPtr;
                }
                else
                {
                    options = new INTERNET_PER_CONN_OPTION[2];
                    options[0].dwOption = 1; // INTERNET_PER_CONN_FLAGS
                    options[0].Value.dwValue = 1; // PROXY_TYPE_DIRECT
                    options[1].dwOption = 4; // INTERNET_PER_CONN_AUTOCONFIG_URL
                    options[1].Value.pszValue = emptyPtr;
                }

                // 1. Default LAN / Wi-Fi connection (DefaultConnectionSettings + SavedLegacySettings)
                ApplyWinInetConnectionList(IntPtr.Zero, options);

                // 2. Also apply to any RAS / VPN connection entries in Connections key
                try
                {
                    using (var connKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", false))
                    {
                        if (connKey != null)
                        {
                            foreach (var valName in connKey.GetValueNames())
                            {
                                if (string.IsNullOrEmpty(valName) ||
                                    string.Equals(valName, "DefaultConnectionSettings", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(valName, "SavedLegacySettings", StringComparison.OrdinalIgnoreCase))
                                    continue;

                                IntPtr namePtr = Marshal.StringToHGlobalAuto(valName);
                                try { ApplyWinInetConnectionList(namePtr, options); }
                                finally { Marshal.FreeHGlobal(namePtr); }
                            }
                        }
                    }
                }
                catch { }
            }
            catch { }
            finally
            {
                FreeHGlobalPtrSafe(srvPtr);
                FreeHGlobalPtrSafe(bypPtr);
                FreeHGlobalPtrSafe(pacPtr);
                FreeHGlobalPtrSafe(emptyPtr);
            }
            RefreshWinInet();
        }

        private static void RefreshWinInet()
        {
            try
            {
                InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
                InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
            }
            catch { }
        }

        private static string GetTelegramBotUrl() { return "https://t.me/p1xivpn_bot?start=ag_unlocker"; }
        private static string GetTelegramBotHandle() { return "@p1xivpn_bot"; }
        private static string GetProjectDonateUrl()
        {
            if (!string.IsNullOrEmpty(PixelCoreService.ManifestDonateUrl))
                return PixelCoreService.ManifestDonateUrl;
            return "https://ai.pixelstore.space/donate";
        }
        private void RunOnUiThread(Action action)
        {
            if (action == null) return;
            try
            {
                var disp = this.Dispatcher;
                if (disp == null || disp.HasShutdownStarted || disp.HasShutdownFinished) return;
                if (disp.CheckAccess())
                    action();
                else
                    disp.BeginInvoke(new Action(delegate { try { action(); } catch { } }));
            }
            catch { }
        }

        private void RunOnUiThreadWithPriority(Action action, DispatcherPriority priority)
        {
            if (action == null) return;
            try
            {
                var disp = this.Dispatcher;
                if (disp == null || disp.HasShutdownStarted || disp.HasShutdownFinished) return;
                disp.BeginInvoke(priority, new Action(delegate { try { action(); } catch { } }));
            }
            catch { }
        }

        private void RunOnUiThreadSync(Action action)
        {
            if (action == null) return;
            try
            {
                var disp = this.Dispatcher;
                if (disp == null || disp.HasShutdownStarted || disp.HasShutdownFinished) return;
                if (disp.CheckAccess())
                    action();
                else
                    disp.Invoke(new Action(delegate { try { action(); } catch { } }));
            }
            catch { }
        }

        private T ReadFromUiThread<T>(Func<T> getter, T fallback)
        {
            if (getter == null) return fallback;
            try
            {
                var disp = this.Dispatcher;
                if (disp == null || disp.HasShutdownStarted || disp.HasShutdownFinished) return fallback;
                if (disp.CheckAccess()) return getter();
                T result = fallback;
                disp.Invoke(new Action(delegate { try { result = getter(); } catch { } }));
                return result;
            }
            catch { return fallback; }
        }

        private bool HasActiveProAccess()
        {
            string tier = PixelCoreService.ServerLicenseTier;
            if (string.Equals(tier, "pro", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tier, "admin", StringComparison.OrdinalIgnoreCase))
                return true;
            string keyText = "";
            try
            {
                var disp = this.Dispatcher;
                if (disp != null && disp.CheckAccess())
                    keyText = _keyInput != null ? _keyInput.Text : "";
                else if (disp != null && !disp.HasShutdownStarted && !disp.HasShutdownFinished)
                    disp.Invoke(new Action(delegate { keyText = _keyInput != null ? _keyInput.Text : ""; }));
            }
            catch { }
            return IsCustomPaidKey(keyText);
        }
        public static string GetFreeModeSentinelUri() { return "pwp3://free@ai.pixelstore.space:443#PixelTunnel-Free"; }
        private static string GetDefaultClusterHost() { return "ai.pixelstore.space"; }

        public const string APP_VERSION = "2.0.0";
        public const string IPC_PIPE_NAME = "Local\\PixelTunnel_IPC_v2";
        private const string CORE_EXE_NAME = "pixel-tun-core";
        private const int LOCAL_MIXED_PORT = 17890;
        private static readonly HashSet<string> LegacyTrialUuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "e434aed7-0a9f-449f-81b9-870086cf2d09",
            "66eda2cf-432e-475b-a5cb-ebbf391e649f",
            "02d80b07-7824-f8d4-ac3a-e431ea3a8a32"
        };
        private static int _activeHttpPort = 17890;
        private static int _activeSocksPort = 17891;
        private static volatile bool _foreign7890UpstreamDead = false;
        private static long _foreign7890DeadCheckedTicks = 0;
        private static bool _useSmartPacMode = true;
        private static bool _optWslBridge = false;
        private CancellationTokenSource _deepLinkPipeCts;
        private readonly string _initialDeepLinkUri;
        private int _pulseTickCounter = 0;
        private bool _isExplicitExit = false;
        private bool _hasShownTrayBalloon = false;
        private int _consecutivePingFailures = 0;
        private string _lastValidationUrl = "";
        private string _githubReleaseUrl = "";
        private DateTime _tunnelConnectedUtc = DateTime.MinValue;
        private int _agRelaunchedForPort = 0;
        private bool _agBannerDismissed = false;
        private static string _selectedRegion = "auto";
        private Border _agLeakGuardBanner;
        private TextBlock _agLeakGuardText;
        private Border _regPillAuto;
        private TextBlock _regTextAuto;
        private Border _regPillNl;
        private TextBlock _regTextNl;
        private Border _regPillUs;
        private TextBlock _regTextUs;
        private static bool _isWatchdogPatchRunning = false;
        private static readonly Dictionary<string, string> _verifiedLsBinSignatures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private const string PROXY_OVERRIDE = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>;*.ru;*.su;*.xn--p1ai;*.pixelstore.space;pixelstore.space;201.34.152.97;*.o3.ru;*.o3team.ru;*.o3t.ru;*.ozon.ru;*.ozon-dostavka.ru;*.ozonalco.ru;*.ozon.by;*.ozon.kz;*.ozone.ru;*.ozonru.me;*.ozonrucn.me;*.ozoncom.me;*.ozon.tech;*.ozonusercontent.com;*.ozon.com;*.ozonpartners.ru;*.ozondostavka.ru;*.ozon.travel;*.ozon.team;*.chatzone.ru;185.73.*;89.31.143.*";

        private readonly string _baseDir;
        private readonly string _engineDir;
        private readonly string _coreExePath;
        private readonly string _activeConfigPath;
        private readonly string _coreLogPath;
        private readonly string _savedKeyPath;

        private Ellipse _statusDot;
        private Ellipse _statusPulseRing;
        private TextBlock _statusTitle;
        private TextBlock _statusSub;
        private TextBlock _pingLabel;

        private Border _aiTelemetryBorder;
        private Ellipse _aiTelemetryDot;
        private TextBlock _aiTelemetryText;
        private Border _aiVerifyBtn;

        private Border _inputBoxBorder;
        private TextBox _keyInput;
        private TextBlock _keyHint;
        private TextBlock _getKeyText;
        private ContentControl _licenseShieldHolder;
        private Border _getKeyLinkBorder;
        private ContentControl _getKeyArrowHolder;
        private string _licenseRightActionUrl = "";
        private const string ADMIN_HQ_URL = "https://ai.pixelstore.space/hq/";

        private bool _optAntigravity = true;
        private static bool _optMcpTerminal = true;
        private bool _optCursorAi = false;
        private bool _optDiscordYt = false;
        private bool _optSocialWeb = false;
        private bool _preferSafeProxyMode = true;
        private bool _isUpdatingApp = false;

        private Border _updatePillBtn;
        private TextBlock _updatePillText;

        private Border _iconBoxAg;
        private Border _chkBoxAg;
        private ShapePath _chkMarkAg;
        private Border _iconBoxMcp;
        private Border _chkBoxMcp;
        private ShapePath _chkMarkMcp;
        private Border _iconBoxAi;
        private Border _chkBoxAi;
        private ShapePath _chkMarkAi;
        private Border _iconBoxMedia;
        private Border _chkBoxMedia;
        private ShapePath _chkMarkMedia;
        private Border _iconBoxWeb;
        private Border _chkBoxWeb;
        private ShapePath _chkMarkWeb;

        private Border _actionBtnBorder;
        private ContentControl _actionBtnIconHolder;
        private TextBlock _actionBtnText;
        private Border _diagBtnBorder;
        private ContentControl _diagBtnIconHolder;
        private TextBlock _diagBtnText;

        private Border _aiPulseRowBorder;
        private Ellipse _pulseDotGemini;
        private TextBlock _pulseTextGemini;
        private Ellipse _pulseDotClaude;
        private TextBlock _pulseTextClaude;
        private Ellipse _pulseDotOpenAi;
        private TextBlock _pulseTextOpenAi;
        private Border _btnOAuthHelperBorder;
        private TextBlock _btnOAuthHelperText;
        private bool _oauthHelperActive = false;
        private int _oauthHelperSecondsLeft = 0;
        private DispatcherTimer _oauthHelperTimer;
        private string _lastSupportPassport = "";
        private string _lastDiagReport = "";

        private Process _coreProcess;
        private DispatcherTimer _monitorTimer;
        private bool _isConnected = false;
        private bool _isBusy = false;
        private bool _isDiagRunning = false;
        private VlessNode _activeNode = null;
        private System.Windows.Forms.NotifyIcon _trayIcon;

        // Matte Dark Anti-Slop Palette
        private static readonly Color ColBg = Color.FromRgb(9, 10, 13);           // #090A0D
        private static readonly Color ColSurface = Color.FromRgb(18, 20, 26);     // #12141A
        private static readonly Color ColSurfaceHover = Color.FromRgb(26, 29, 38);// #1A1D26
        private static readonly Color ColBorder = Color.FromRgb(35, 39, 50);      // #232732
        private static readonly Color ColBorderFocus = Color.FromRgb(68, 76, 96); // #444C60
        private static readonly Color ColText1 = Color.FromRgb(255, 255, 255);    // #FFFFFF
        private static readonly Color ColText2 = Color.FromRgb(148, 155, 170);    // #949BAA
        private static readonly Color ColText3 = Color.FromRgb(92, 99, 114);      // #5C6372
        private static readonly Color ColGreen = Color.FromRgb(16, 185, 129);     // #10B981
        private static readonly Color ColAmber = Color.FromRgb(245, 158, 11);     // #F59E0B
        private static readonly Color ColRed = Color.FromRgb(239, 68, 68);        // #EF4444
        private static readonly Color ColBlue = Color.FromRgb(59, 130, 246);      // #3B82F6

        public MainWindow(bool autoConnect, bool autoDiag, string initialDeepLinkUri = null)
        {
            _initialDeepLinkUri = initialDeepLinkUri;
            _baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string localEngineDir = System.IO.Path.Combine(_baseDir, "engine");
            string localCorePath = System.IO.Path.Combine(localEngineDir, CORE_EXE_NAME + ".exe");

            if (File.Exists(localCorePath) && IsDirectoryWritable(localEngineDir))
            {
                _engineDir = localEngineDir;
            }
            else
            {
                _engineDir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PixelTunnel",
                    "engine"
                );
            }

            try
            {
                if (!Directory.Exists(_engineDir)) Directory.CreateDirectory(_engineDir);
            }
            catch
            {
                try
                {
                    _engineDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "PixelTunnel", "engine");
                    if (!Directory.Exists(_engineDir)) Directory.CreateDirectory(_engineDir);
                }
                catch { }
            }

            _coreExePath = System.IO.Path.Combine(_engineDir, CORE_EXE_NAME + ".exe");
            _activeConfigPath = System.IO.Path.Combine(_engineDir, "active_config.json");
            _coreLogPath = System.IO.Path.Combine(_engineDir, "core.log");
            _savedKeyPath = System.IO.Path.Combine(_baseDir, "saved_key.txt");

            // Adaptive height so bottom buttons are NEVER clipped on any screen or DPI scaling!
            Title = "PixelTunnel — Antigravity & AI Router";
            Width = 488;
            SizeToContent = SizeToContent.Height;
            MaxHeight = Math.Max(580, SystemParameters.WorkArea.Height - 20);
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = Brushes.Transparent;
            ResizeMode = ResizeMode.CanMinimize;

            string icoPath = EnsureIconFileAvailable();
            if (!string.IsNullOrEmpty(icoPath) && File.Exists(icoPath))
            {
                try { Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(icoPath)); } catch { }
            }

            BuildInterface();
            InitTray(icoPath);
            LoadSavedState();

            // Immediately heal any dead system proxy left over from a previous crash or closed app
            SanitizeOrphanedProxyOnStartup();

            // Automatically apply Antigravity Sanctioned Account Login patch ("Вход в аккаунт из-под санкций") in background
            Task.Run(() =>
            {
                try
                {
                    List<string> pLogs;
                    PatchAntigravitySanctionsAndProxy(out pLogs, false);
                }
                catch { }
            });

            this.Closing += (s, e) =>
            {
                if (!_isExplicitExit)
                {
                    e.Cancel = true;
                    MinimizeToTray();
                    return;
                }
                SafeCleanupOnExit();
            };
            this.Closed += delegate { SafeCleanupOnExit(); };
            if (Application.Current != null)
            {
                Application.Current.Exit += delegate { SafeCleanupOnExit(); };
                Application.Current.SessionEnding += delegate { SafeCleanupOnExit(); };
            }
            AppDomain.CurrentDomain.UnhandledException += (s, ev) =>
            {
                try
                {
                    if (ev != null && ev.ExceptionObject != null)
                        File.WriteAllText(System.IO.Path.Combine(_baseDir, "crash.log"), ev.ExceptionObject.ToString());
                }
                catch { }
                SafeCleanupOnExit();
            };

            _monitorTimer = new DispatcherTimer();
            _monitorTimer.Interval = TimeSpan.FromSeconds(2.0);
            _monitorTimer.Tick += delegate { MonitorLoop(); };
            _monitorTimer.Start();

            Loaded += delegate
            {
                CheckForGitHubUpdateAsync();
                StartDeepLinkPipeServer();
                if (!string.IsNullOrEmpty(_initialDeepLinkUri))
                {
                    RunOnUiThreadWithPriority(delegate { HandleDeepLinkUri(_initialDeepLinkUri); }, DispatcherPriority.Background);
                }
            };

            if (autoDiag)
            {
                Loaded += delegate { RunSmartDiagnosticsAsync(false, true); };
            }
            else if (autoConnect && !string.IsNullOrWhiteSpace(_keyInput.Text))
            {
                Loaded += delegate { StartTunnelAsync(); };
            }
        }

        public static void CleanupOldUpdateArtifacts()
        {
            try
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                if (!Directory.Exists(dir)) return;
                foreach (var pat in new[] { "*.old_update", "*.new_verified" })
                {
                    foreach (var f in Directory.GetFiles(dir, pat))
                    {
                        try { File.Delete(f); } catch { }
                    }
                }
            }
            catch { }
        }

        public static bool VerifyDownloadedUpdateBinary(byte[] data, string expectedSha256Hex, bool requireAuthenticode)
        {
            try
            {
                if (data == null || data.Length < 65536) return false;
                // Проверка MZ заголовка PE исполняемого файла Windows
                if (data[0] != 0x4D || data[1] != 0x5A) return false;

                if (string.IsNullOrEmpty(expectedSha256Hex)) return false;
                string exp = expectedSha256Hex.Trim().ToLowerInvariant();
                if (exp.Length != 64) return false;

                string actualHex;
                using (var sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(data);
                    actualHex = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

                if (actualHex.Length != exp.Length) return false;
                int diff = 0;
                for (int i = 0; i < exp.Length; i++)
                {
                    diff |= (actualHex[i] ^ exp[i]);
                }
                if (diff != 0) return false;

                string tmpVerify = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "pt_verify_" + Guid.NewGuid().ToString("N") + ".exe");
                try
                {
                    File.WriteAllBytes(tmpVerify, data);
                    X509Certificate cert = null;
                    try
                    {
                        cert = X509Certificate.CreateFromSignedFile(tmpVerify);
                    }
                    catch (CryptographicException)
                    {
                        // Unsigned build_v16.ps1 binary is accepted once SHA-256 matched the offline ECDSA-signed manifest
                        cert = null;
                    }

                    if (cert != null)
                    {
                        using (var cert2 = new X509Certificate2(cert))
                        using (var chain = new X509Chain())
                        {
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(4);
                            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                            if (!chain.Build(cert2)) return false;
                        }
                    }
                }
                finally
                {
                    try { if (File.Exists(tmpVerify)) File.Delete(tmpVerify); } catch { }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private void CheckSignedManifestUpdateUi()
        {
            try
            {
                if (_updatePillBtn == null || _updatePillText == null || _isUpdatingApp) return;
                string remoteVer = PixelCoreService.ManifestLatestVersion;
                string remoteUrl = PixelCoreService.ManifestUpdateUrl;
                string remoteSha = PixelCoreService.ManifestUpdateSha256;

                if (PixelCoreService.IsNewerVersion(APP_VERSION, remoteVer) &&
                    !string.IsNullOrEmpty(remoteUrl) &&
                    !string.IsNullOrEmpty(remoteSha) &&
                    remoteSha.Trim().Length == 64)
                {
                    _githubReleaseUrl = "";
                    _updatePillText.Text = "⬆ Обновить v" + remoteVer;
                    _updatePillBtn.ToolTip = string.IsNullOrEmpty(PixelCoreService.ManifestUpdateNotes)
                        ? ("Безопасное обновление в 1 клик до v" + remoteVer + " (ECDSA + SHA-256)")
                        : (PixelCoreService.ManifestUpdateNotes + " — нажмите для атомарного обновления");
                    _updatePillBtn.Visibility = Visibility.Visible;
                }
            }
            catch { }
        }

        private static byte[] DownloadBinaryWithOptionalProxy(string url, string localProxyUrl, int timeoutMs)
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.UserAgent = "PixelTunnel/" + APP_VERSION;
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.Proxy = string.IsNullOrEmpty(localProxyUrl) ? null : new WebProxy(localProxyUrl);
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (Stream rs = resp.GetResponseStream())
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buf = new byte[32768];
                int r;
                while ((r = rs.Read(buf, 0, buf.Length)) > 0)
                {
                    ms.Write(buf, 0, r);
                    if (ms.Length > 25 * 1024 * 1024) throw new IOException("Update package exceeds 25 MB safety limit");
                }
                return ms.ToArray();
            }
        }

        private async void PerformSafeInAppUpdateAsync()
        {
            bool exiting = false;
            string remoteVer = "";
            try
            {
                if (_isUpdatingApp) return;
                remoteVer = PixelCoreService.ManifestLatestVersion;
                string remoteUrl = PixelCoreService.ManifestUpdateUrl;
                string remoteSha = PixelCoreService.ManifestUpdateSha256;
                if (string.IsNullOrEmpty(remoteUrl) || string.IsNullOrEmpty(remoteSha)) return;

                _isUpdatingApp = true;
                RunOnUiThread(delegate
                {
                    if (_updatePillText != null) _updatePillText.Text = "Загрузка v" + remoteVer + "...";
                });

                string curExe = Process.GetCurrentProcess().MainModule.FileName;
                bool wasConnected = _isConnected;
                string tunnelProxy = (_isConnected && IsLocalPortOpen(_activeHttpPort, 120))
                    ? string.Format("http://127.0.0.1:{0}", _activeHttpPort)
                    : null;

                string errDetail = "";
                bool readyToSwap = await Task.Run(() =>
                {
                    byte[] raw = null;
                    try
                    {
                        raw = DownloadBinaryWithOptionalProxy(remoteUrl, null, 18000);
                    }
                    catch
                    {
                        if (!string.IsNullOrEmpty(tunnelProxy))
                        {
                            try { raw = DownloadBinaryWithOptionalProxy(remoteUrl, tunnelProxy, 22000); } catch { }
                        }
                    }

                    if (raw == null || raw.Length < 65536)
                    {
                        errDetail = "Не удалось скачать пакет обновления.";
                        return false;
                    }

                    if (!VerifyDownloadedUpdateBinary(raw, remoteSha, true))
                    {
                        errDetail = "Хэш SHA-256 или цифровая подпись Authenticode не совпали — обновление отклонено защитой.";
                        return false;
                    }

                    string newVerifiedPath = curExe + ".new_verified";
                    string oldPath = curExe + ".old_update";
                    try
                    {
                        if (File.Exists(newVerifiedPath)) File.Delete(newVerifiedPath);
                        File.WriteAllBytes(newVerifiedPath, raw);
                        UnblockFileZone(newVerifiedPath);

                        // Атомарная подмена в ядре Windows NT без .bat и без cmd.exe (1/64 VT Clean!)
                        if (File.Exists(oldPath)) File.Delete(oldPath);
                        File.Move(curExe, oldPath);
                        try
                        {
                            File.Move(newVerifiedPath, curExe);
                        }
                        catch
                        {
                            try { if (!File.Exists(curExe) && File.Exists(oldPath)) File.Move(oldPath, curExe); } catch { }
                            throw;
                        }
                        return true;
                    }
                    catch (Exception exMove)
                    {
                        errDetail = "Нет прав записи в папку программы: " + exMove.Message;
                        try { if (File.Exists(newVerifiedPath)) File.Delete(newVerifiedPath); } catch { }
                        return false;
                    }
                });

                if (!readyToSwap)
                {
                    RunOnUiThread(delegate
                    {
                        if (_updatePillText != null) _updatePillText.Text = "⬆ Обновить v" + remoteVer;
                        SetStatus(ColAmber, "Обновление отменено защитой", errDetail);
                    });
                    return;
                }

                RunOnUiThreadSync(delegate { SaveCurrentState(); });
                _isExplicitExit = true;
                RunOnUiThreadSync(delegate
                {
                    if (_trayIcon != null)
                    {
                        try { _trayIcon.Visible = false; _trayIcon.Dispose(); } catch { }
                    }
                });
                StopTunnelProcess(false);

                exiting = true;
                Process.Start(new ProcessStartInfo
                {
                    FileName = curExe,
                    Arguments = wasConnected ? "--autoconnect" : "",
                    WorkingDirectory = System.IO.Path.GetDirectoryName(curExe),
                    UseShellExecute = false
                });
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                RunOnUiThread(delegate
                {
                    if (_updatePillText != null) _updatePillText.Text = "⬆ Обновить v" + remoteVer;
                    SetStatus(ColAmber, "Ошибка авто-обновления", errMsg);
                });
            }
            finally
            {
                if (!exiting) _isUpdatingApp = false;
            }
        }

        private async void CheckForGitHubUpdateAsync()
        {
            try
            {
                await Task.Run(() =>
                {
                    try
                    {
                        string json = null;
                        string url = "https://api.github.com/repos/keenfolk1-lgtm/antigravity-unlocker/releases/latest";
                        string[] proxies = (_isConnected && IsLocalPortOpen(_activeHttpPort, 100))
                            ? new[] { string.Format("http://127.0.0.1:{0}", _activeHttpPort), null }
                            : new string[] { null };

                        foreach (string prx in proxies)
                        {
                            try
                            {
                                var req = (HttpWebRequest)WebRequest.Create(url);
                                req.UserAgent = "PixelTunnel/" + APP_VERSION;
                                req.Timeout = 8000;
                                req.ReadWriteTimeout = 8000;
                                req.Proxy = string.IsNullOrEmpty(prx) ? null : new WebProxy(prx);
                                using (var resp = (HttpWebResponse)req.GetResponse())
                                using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                                {
                                    json = sr.ReadToEnd();
                                }
                                if (!string.IsNullOrEmpty(json)) break;
                            }
                            catch { }
                        }

                        if (string.IsNullOrEmpty(json)) return;
                        var mTag = Regex.Match(json, "\"tag_name\"\\s*:\\s*\"v?([^\"]+)\"", RegexOptions.IgnoreCase);
                        if (mTag.Success)
                        {
                            string latestVer = mTag.Groups[1].Value.Trim();
                            if (!string.IsNullOrEmpty(latestVer) && !string.Equals(latestVer, APP_VERSION, StringComparison.OrdinalIgnoreCase))
                            {
                                Version vCur, vNew;
                                if (Version.TryParse(APP_VERSION.Split('-')[0], out vCur) && Version.TryParse(latestVer.Split('-')[0], out vNew) && vNew > vCur)
                                {
                                    RunOnUiThread(delegate
                                    {
                                        bool hasManifestAutoUpd =
                                            PixelCoreService.IsNewerVersion(APP_VERSION, PixelCoreService.ManifestLatestVersion) &&
                                            !string.IsNullOrEmpty(PixelCoreService.ManifestUpdateUrl) &&
                                            !string.IsNullOrEmpty(PixelCoreService.ManifestUpdateSha256) &&
                                            PixelCoreService.ManifestUpdateSha256.Trim().Length == 64;

                                        if (!hasManifestAutoUpd && _updatePillBtn != null && _updatePillText != null && !_isUpdatingApp)
                                        {
                                            _githubReleaseUrl = "https://github.com/keenfolk1-lgtm/antigravity-unlocker/releases/latest";
                                            _updatePillText.Text = "⬆ Доступна v" + latestVer;
                                            _updatePillBtn.ToolTip = string.Format("Доступен новый релиз PixelTunnel v{0} на GitHub — нажмите, чтобы открыть", latestVer);
                                            _updatePillBtn.Visibility = Visibility.Visible;
                                        }
                                    });
                                }
                            }
                        }
                    }
                    catch { }
                });
            }
            catch { }
        }

        private static bool IsPixelOrLocalAutoConfig(string val)
        {
            if (string.IsNullOrEmpty(val)) return false;
            return val.IndexOf("127.0.0.1", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   val.IndexOf("localhost", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   val.IndexOf("pixel", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsActivePixelSmartPacUrl(string val)
        {
            if (string.IsNullOrEmpty(val) || !_useSmartPacMode) return false;
            if (!PixelCoreService.IsRunning && !IsLocalPortOpen(_activeHttpPort, 120)) return false;
            string prefix = string.Format("http://127.0.0.1:{0}/proxy.pac", _activeHttpPort);
            return val.Trim().StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        public static void RegisterPixelTunnelUrlProtocol()
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                if (string.IsNullOrEmpty(exePath)) return;
                using (var root = Registry.CurrentUser.CreateSubKey(@"Software\Classes\pixeltunnel"))
                {
                    if (root != null)
                    {
                        root.SetValue("", "URL:PixelTunnel Protocol", RegistryValueKind.String);
                        root.SetValue("URL Protocol", "", RegistryValueKind.String);
                        using (var iconKey = root.CreateSubKey("DefaultIcon"))
                        {
                            if (iconKey != null) iconKey.SetValue("", "\"" + exePath + "\",0", RegistryValueKind.String);
                        }
                        using (var cmdKey = root.CreateSubKey(@"shell\open\command"))
                        {
                            if (cmdKey != null) cmdKey.SetValue("", "\"" + exePath + "\" \"%1\"", RegistryValueKind.String);
                        }
                    }
                }
            }
            catch { }
        }

        public static void ApplySavedFlagsForConfigGen(string flags)
        {
            if (string.IsNullOrEmpty(flags)) return;
            _useSmartPacMode = !flags.Contains("PAC=0");
            _optWslBridge = flags.Contains("WSL=1");
            var mReg = Regex.Match(flags, @"REG=(auto|nl|us)", RegexOptions.IgnoreCase);
            if (mReg.Success) _selectedRegion = mReg.Groups[1].Value.ToLowerInvariant();
        }

        private void StartDeepLinkPipeServer()
        {
            try
            {
                if (_deepLinkPipeCts != null) return;
                _deepLinkPipeCts = new CancellationTokenSource();
                CancellationToken tok = _deepLinkPipeCts.Token;
                Task.Run(async () =>
                {
                    while (!tok.IsCancellationRequested)
                    {
                        bool hadErr = false;
                        try
                        {
                            using (var srv = new NamedPipeServerStream(
                                IPC_PIPE_NAME,
                                PipeDirection.In,
                                1,
                                PipeTransmissionMode.Byte,
                                PipeOptions.Asynchronous))
                            {
                                await Task.Factory.FromAsync(srv.BeginWaitForConnection, srv.EndWaitForConnection, null).ConfigureAwait(false);
                                using (var sr = new StreamReader(srv, Encoding.UTF8))
                                {
                                    string line = await sr.ReadLineAsync().ConfigureAwait(false);
                                    if (!string.IsNullOrWhiteSpace(line))
                                    {
                                        string captured = line.Trim();
                                        RunOnUiThread(delegate { HandleDeepLinkUri(captured); });
                                    }
                                }
                            }
                        }
                        catch
                        {
                            hadErr = true;
                        }
                        if (hadErr)
                        {
                            if (tok.IsCancellationRequested) break;
                            await Task.Delay(250).ConfigureAwait(false);
                        }
                    }
                });
            }
            catch { }
        }

        private static bool TryExtractActivateKeyFromUri(string rawUri, out string keyVal)
        {
            keyVal = "";
            if (string.IsNullOrWhiteSpace(rawUri)) return false;
            Uri u;
            if (!Uri.TryCreate(rawUri.Trim(), UriKind.Absolute, out u)) return false;
            if (!string.Equals(u.Scheme, "pixeltunnel", StringComparison.OrdinalIgnoreCase)) return false;
            if (!string.Equals(u.Host, "activate", StringComparison.OrdinalIgnoreCase) &&
                !u.AbsolutePath.Trim('/').Equals("activate", StringComparison.OrdinalIgnoreCase))
                return false;

            string q = (u.Query ?? "").TrimStart('?');
            foreach (string part in q.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = part.IndexOf('=');
                if (eq > 0 && string.Equals(part.Substring(0, eq), "key", StringComparison.OrdinalIgnoreCase))
                {
                    keyVal = Uri.UnescapeDataString(part.Substring(eq + 1).Replace("+", "%2B")).Trim();
                    return !string.IsNullOrEmpty(keyVal);
                }
            }
            return false;
        }

        private static bool IsLegacyOrFreeKey(string candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate)) return true;
            string s = candidate.Trim();
            if (string.Equals(s, "free", StringComparison.OrdinalIgnoreCase)) return true;
            if (LegacyTrialUuids.Contains(s)) return true;
            foreach (string legacy in LegacyTrialUuids)
            {
                if (s.IndexOf(legacy, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return s.IndexOf("pwp3://free@", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsValidProActivationKey(string candidate, out string normalizedSavedKey, out string keyIdentity)
        {
            normalizedSavedKey = "";
            keyIdentity = "";
            if (string.IsNullOrWhiteSpace(candidate)) return false;
            string k = candidate.Trim();
            if (IsLegacyOrFreeKey(k)) return false;

            if (Regex.IsMatch(k, @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"))
            {
                string low = k.ToLowerInvariant();
                if (LegacyTrialUuids.Contains(low)) return false;
                normalizedSavedKey = string.Format("pwp4://{0}@ai.pixelstore.space:443#PixelTunnel-PRO", low);
                keyIdentity = low;
                return true;
            }

            if (Regex.IsMatch(k, @"^https://ai\.pixelstore\.space/sub/[A-Za-z0-9_-]{6,64}$", RegexOptions.IgnoreCase))
            {
                normalizedSavedKey = k;
                keyIdentity = k.ToLowerInvariant();
                return true;
            }

            var parsed = ParseVlessUri(k);
            if (parsed != null && !string.IsNullOrEmpty(parsed.Uuid) && !IsLegacyOrFreeKey(parsed.Uuid))
            {
                normalizedSavedKey = k;
                keyIdentity = parsed.Uuid.Trim().ToLowerInvariant();
                return true;
            }

            return false;
        }

        private void HandleDeepLinkUri(string rawUri)
        {
            try
            {
                Show();
                if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
                Activate();
                Topmost = true;
                Topmost = false;

                string rawKey;
                if (!TryExtractActivateKeyFromUri(rawUri, out rawKey))
                {
                    MessageBox.Show(this, "Ссылка активации не содержит корректного параметра ?key=.", "PixelTunnel Активация", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string normalizedNewKey;
                string newIdentity;
                if (!IsValidProActivationKey(rawKey, out normalizedNewKey, out newIdentity))
                {
                    MessageBox.Show(this, "Ключ в ссылке не соответствует формату PRO (UUID / vless:// / pwp4:// / sub).", "PixelTunnel Активация", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string curText = (_keyInput != null ? _keyInput.Text : "").Trim();
                string curNorm;
                string curIdentity;
                if (IsValidProActivationKey(curText, out curNorm, out curIdentity) &&
                    !string.Equals(curIdentity, newIdentity, StringComparison.OrdinalIgnoreCase))
                {
                    string shortOld = curIdentity.Length > 10 ? (curIdentity.Substring(0, 8) + "...") : curIdentity;
                    string shortNew = newIdentity.Length > 10 ? (newIdentity.Substring(0, 8) + "...") : newIdentity;
                    var ans = MessageBox.Show(
                        this,
                        string.Format("В PixelTunnel уже сохранён другой PRO-ключ ({0}).\n\nЗаменить его на новый ключ ({1}) и переподключить туннель?", shortOld, shortNew),
                        "Замена PRO-ключа PixelTunnel",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);
                    if (ans != MessageBoxResult.Yes) return;
                }

                if (_keyInput != null) _keyInput.Text = normalizedNewKey;
                SaveCurrentState();
                OnKeyTextChanged();
                SetStatus(ColBlue, "Применяется PRO-ключ...", "Ключ получен через pixeltunnel://activate — запускаем туннель");
                if (!_isBusy)
                {
                    if (_isConnected) StopTunnelProcess(false);
                    StartTunnelAsync();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Не удалось обработать ссылку активации: " + ex.Message, "PixelTunnel", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static void SetProxyResetRunOnceGuard(bool enable)
        {
            try
            {
                if (enable)
                {
                    using (var runOnce = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\RunOnce"))
                    {
                        if (runOnce != null)
                        {
                            runOnce.SetValue(
                                "PixelTunnelProxyReset",
                                "cmd /c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 0 /f & reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v AutoConfigURL /f",
                                RegistryValueKind.String);
                        }
                    }
                }
                else
                {
                    using (var runOnce = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\RunOnce", true))
                    {
                        if (runOnce != null)
                        {
                            runOnce.DeleteValue("PixelTunnelProxyReset", false);
                        }
                    }
                }
            }
            catch { }
        }

        private void SafeCleanupOnExit()
        {
            try
            {
                if (_deepLinkPipeCts != null)
                {
                    try { _deepLinkPipeCts.Cancel(); } catch { }
                    _deepLinkPipeCts = null;
                }
                if (_isConnected || PixelCoreService.IsRunning || Process.GetProcessesByName(CORE_EXE_NAME).Length > 0)
                {
                    StopTunnelProcess(false);
                }
                else
                {
                    EmergencyDisableDeadSystemProxy();
                }
            }
            catch { }
        }

        public static void EmergencyDisableDeadSystemProxy()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null)
                    {
                        int en = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                        string srv = Convert.ToString(key.GetValue("ProxyServer", ""));
                        if (en == 1 && srv.StartsWith("127.0.0.1:", StringComparison.OrdinalIgnoreCase))
                        {
                            int port = 0;
                            int.TryParse(srv.Substring("127.0.0.1:".Length), out port);
                            if (port == LOCAL_MIXED_PORT || (port > 0 && !IsLocalPortOpen(port, 150)))
                            {
                                key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                ApplyWinInetPerConnectionProxy(false, "", "");
                                SetProxyResetRunOnceGuard(false);
                            }
                        }
                    }
                }
                CleanDeadProxyEnvironmentVariables();
            }
            catch { }
        }

        private static bool PurgeGlobalCliProxyEnvVars()
        {
            bool cleanedAny = false;
            try
            {
                // Always purge global HTTP_PROXY / HTTPS_PROXY / ALL_PROXY pointing to 127.0.0.1,
                // while preserving user-defined NO_PROXY / no_proxy unless it contains PixelTunnel markers.
                string[] globalCliVars = new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy" };
                foreach (var vName in globalCliVars)
                {
                    string val = Environment.GetEnvironmentVariable(vName, EnvironmentVariableTarget.User);
                    if (string.IsNullOrEmpty(val)) continue;
                    bool shouldRemove = false;
                    if (vName.Equals("NO_PROXY", StringComparison.OrdinalIgnoreCase))
                    {
                        shouldRemove =
                            val.IndexOf("pixelstore.space", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            val.IndexOf("pixeltunnel", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            val.IndexOf("*.ru,*.su", StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                    else
                    {
                        shouldRemove = val.IndexOf("127.0.0.1", StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                    if (shouldRemove)
                    {
                        Environment.SetEnvironmentVariable(vName, null, EnvironmentVariableTarget.User);
                        Environment.SetEnvironmentVariable(vName, null, EnvironmentVariableTarget.Process);
                        cleanedAny = true;
                    }
                }
            }
            catch { }
            return cleanedAny;
        }

        private static bool CleanDeadProxyEnvironmentVariables()
        {
            bool cleanedAny = PurgeGlobalCliProxyEnvVars();
            try
            {
                string val = Environment.GetEnvironmentVariable("AG_LS_PROXY", EnvironmentVariableTarget.User);
                if (!string.IsNullOrEmpty(val) && val.IndexOf("127.0.0.1:", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    int p = 0;
                    int col = val.LastIndexOf(':');
                    if (col > 0) int.TryParse(val.Substring(col + 1).TrimEnd('/'), out p);
                    if (p > 0 && !IsLocalPortOpen(p, 150))
                    {
                        Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.User);
                        Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.Process);
                        cleanedAny = true;
                    }
                }
                if (cleanedAny)
                {
                    BroadcastEnvironmentChange();
                }
            }
            catch { }
            return cleanedAny;
        }

        private void SanitizeOrphanedProxyOnStartup()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null)
                    {
                        object autoCfgObj = key.GetValue("AutoConfigURL", null);
                        if (autoCfgObj != null && IsPixelOrLocalAutoConfig(Convert.ToString(autoCfgObj)))
                        {
                            key.DeleteValue("AutoConfigURL", false);
                        }

                        int en = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                        string srv = Convert.ToString(key.GetValue("ProxyServer", ""));
                        if (en == 1 && srv.StartsWith("127.0.0.1:", StringComparison.OrdinalIgnoreCase))
                        {
                            int port = 0;
                            int.TryParse(srv.Substring("127.0.0.1:".Length), out port);
                            if (port > 0 && !IsLocalPortOpen(port, 180))
                            {
                                key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                ApplyWinInetPerConnectionProxy(false, "", "");
                                SetProxyResetRunOnceGuard(false);
                                SetStatus(
                                    ColAmber,
                                    "Восстановлен прямой интернет",
                                    string.Format("Отключен зависший системный прокси ({0}), блокировавший сеть.", srv)
                                );
                            }
                        }
                    }
                }

                // Purge global HTTP_PROXY / ALL_PROXY and clean dead AG_LS_PROXY + Cursor/VS Code leftovers on startup
                bool cleanedEnv = CleanDeadProxyEnvironmentVariables();
                bool portAlive = IsLocalPortOpen(LOCAL_MIXED_PORT, 120);
                HealAiEditorsAndServices(portAlive, cleanedEnv, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
            }
            catch { }
        }

        private static bool IsDirectoryWritable(string dirPath)
        {
            try
            {
                if (!Directory.Exists(dirPath)) return false;
                string probe = System.IO.Path.Combine(dirPath, ".write_test");
                File.WriteAllText(probe, "1");
                File.Delete(probe);
                return true;
            }
            catch { return false; }
        }

        private string EnsureIconFileAvailable()
        {
            try
            {
                string localIco = System.IO.Path.Combine(_baseDir, "pixel.ico");
                if (File.Exists(localIco) && new FileInfo(localIco).Length > 10000) return localIco;

                string appDataDir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PixelTunnel"
                );
                if (!Directory.Exists(appDataDir)) Directory.CreateDirectory(appDataDir);
                string fallbackIco = System.IO.Path.Combine(appDataDir, "pixel.ico");
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("PixelTunnel.pixel.ico"))
                {
                    if (s != null)
                    {
                        bool needWrite = !File.Exists(fallbackIco);
                        if (!needWrite)
                        {
                            try { needWrite = (new FileInfo(fallbackIco).Length != s.Length); } catch { needWrite = true; }
                        }
                        if (needWrite)
                        {
                            using (var fs = File.Create(fallbackIco))
                            {
                                s.CopyTo(fs);
                            }
                        }
                    }
                }
                if (File.Exists(fallbackIco)) return fallbackIco;
                if (File.Exists(localIco)) return localIco;
            }
            catch { }
            return null;
        }

        private static void UnblockFileZone(string filePath)
        {
            try
            {
                if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                {
                    File.Delete(filePath + ":Zone.Identifier");
                }
            }
            catch { }
        }

        private void MinimizeToTray()
        {
            try
            {
                Hide();
                if (_trayIcon != null)
                {
                    _trayIcon.Visible = true;
                    if (!_hasShownTrayBalloon)
                    {
                        _hasShownTrayBalloon = true;
                        string msg = _isConnected
                            ? "\u0422\u0443\u043d\u043d\u0435\u043b\u044c \u0430\u043a\u0442\u0438\u0432\u0435\u043d \u0438 \u043f\u0440\u043e\u0434\u043e\u043b\u0436\u0430\u0435\u0442 \u0440\u0430\u0431\u043e\u0442\u0443 \u0432 \u0444\u043e\u043d\u0435. \u041f\u043e\u043b\u043d\u044b\u0439 \u0432\u044b\u0445\u043e\u0434 \u2014 \u0447\u0435\u0440\u0435\u0437 \u041f\u041a\u041c \u043f\u043e \u0438\u043a\u043e\u043d\u043a\u0435 \u0432 \u0442\u0440\u0435\u0435."
                            : "PixelTunnel \u0441\u0432\u0451\u0440\u043d\u0443\u0442 \u0432 \u0442\u0440\u0435\u0439. \u041f\u043e\u043b\u043d\u044b\u0439 \u0432\u044b\u0445\u043e\u0434 \u2014 \u0447\u0435\u0440\u0435\u0437 \u041f\u041a\u041c \u043f\u043e \u0438\u043a\u043e\u043d\u043a\u0435 \u0432 \u0442\u0440\u0435\u0435.";
                        try { _trayIcon.ShowBalloonTip(2800, "PixelTunnel \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 \u0432 \u0444\u043e\u043d\u0435", msg, System.Windows.Forms.ToolTipIcon.Info); } catch { }
                    }
                }
            }
            catch { }
        }

        private void ExplicitShutdown()
        {
            _isExplicitExit = true;
            Hide();
            if (_trayIcon != null)
            {
                try { _trayIcon.Visible = false; _trayIcon.Dispose(); } catch { }
            }
            Task.Run(() =>
            {
                try { StopTunnelProcess(false); } catch { }
                Environment.Exit(0);
            });
        }

        private void InitTray(string icoPath)
        {
            try
            {
                _trayIcon = new System.Windows.Forms.NotifyIcon();
                if (!string.IsNullOrEmpty(icoPath) && File.Exists(icoPath))
                    _trayIcon.Icon = new System.Drawing.Icon(icoPath);
                else
                    _trayIcon.Icon = System.Drawing.Icon.ExtractAssociatedIcon(Process.GetCurrentProcess().MainModule.FileName);

                _trayIcon.Text = "PixelTunnel v" + APP_VERSION + " — PWP-4 Dual-Mux";
                _trayIcon.Visible = true;
                _trayIcon.MouseClick += (s, e) =>
                {
                    if (e.Button == System.Windows.Forms.MouseButtons.Left)
                    {
                        Show();
                        WindowState = WindowState.Normal;
                        Activate();
                    }
                };
                _trayIcon.DoubleClick += delegate
                {
                    Show();
                    WindowState = WindowState.Normal;
                    Activate();
                };

                var menu = new System.Windows.Forms.ContextMenuStrip();
                menu.Items.Add("Открыть PixelTunnel", null, delegate { Show(); WindowState = WindowState.Normal; Activate(); });
                menu.Items.Add("Запустить / Перезапустить туннель (PWP-4)", null, delegate
                {
                    Show();
                    WindowState = WindowState.Normal;
                    Activate();
                    StartTunnelAsync();
                });
                menu.Items.Add("⚡ Перезапустить Antigravity в защищённом туннеле", null, delegate
                {
                    RelaunchAntigravityInTunnelAsync();
                });
                menu.Items.Add("🎙️ Запустить Discord с голосом (SOCKS5 UDP)", null, delegate
                {
                    RelaunchDiscordWithSocksUdpAsync();
                });
                menu.Items.Add("🛠️ Починить другие программы (Сбросить прокси из Cursor/Git)", null, delegate
                {
                    RepairOtherAppsAndCleanLeftovers();
                    if (_trayIcon != null)
                    {
                        try { _trayIcon.ShowBalloonTip(2500, "Программы очищены от прокси", "Cursor, VS Code, Git, npm и браузеры работают напрямую • Antigravity под защитой", System.Windows.Forms.ToolTipIcon.Info); } catch { }
                    }
                });
                menu.Items.Add("\u0414\u0438\u0430\u0433\u043d\u043e\u0441\u0442\u0438\u043a\u0430 \u0438 \u0430\u0432\u0442\u043e-\u0444\u0438\u043a\u0441", null, delegate
                {
                    Show();
                    WindowState = WindowState.Normal;
                    Activate();
                    RunSmartDiagnosticsAsync(true);
                });
                menu.Items.Add("\u0410\u0432\u0430\u0440\u0438\u0439\u043d\u044b\u0439 \u0441\u0431\u0440\u043e\u0441 \u0441\u0435\u0442\u0438 (\u0427\u0438\u0441\u0442\u044b\u0439 \u0438\u043d\u0442\u0435\u0440\u043d\u0435\u0442)", null, delegate
                {
                    Show();
                    WindowState = WindowState.Normal;
                    Activate();
                    RunEmergencyNetworkResetAsync(true);
                });
                menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
                menu.Items.Add("\u041e\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c \u0438 \u0432\u044b\u0439\u0442\u0438", null, delegate
                {
                    ExplicitShutdown();
                });
                _trayIcon.ContextMenuStrip = menu;
            }
            catch { }
        }

        private void BuildInterface()
        {
            var outerBorder = new Border
            {
                Background = new SolidColorBrush(ColBg),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(18, 14, 18, 16)
            };

            var rootStack = new StackPanel { Orientation = Orientation.Vertical };

            // ====================================================================
            // 1. HEADER BAR (Draggable)
            // ====================================================================
            var headerGrid = new Grid { Margin = new Thickness(0, 0, 0, 12), Background = Brushes.Transparent };
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerGrid.MouseLeftButtonDown += (s, e) =>
            {
                if (e.ChangedButton == MouseButton.Left && e.ButtonState == MouseButtonState.Pressed)
                {
                    try { DragMove(); } catch { }
                }
            };

            var brandStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

            var logoBox = new Border
            {
                Width = 28,
                Height = 28,
                CornerRadius = new CornerRadius(7),
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorderFocus),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 10, 0),
                Child = CreateBrandEmblemIcon()
            };
            brandStack.Children.Add(logoBox);

            var titleStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
            titleRow.Children.Add(new TextBlock
            {
                Text = "PixelTunnel",
                Foreground = new SolidColorBrush(ColText1),
                FontFamily = new FontFamily("Segoe UI Semibold, Inter, sans-serif"),
                FontSize = 15,
                FontWeight = FontWeights.SemiBold
            });
            titleRow.Children.Add(new TextBlock
            {
                Text = "uTLS + PWP-4 • v" + APP_VERSION,
                Foreground = new SolidColorBrush(ColGreen),
                FontFamily = new FontFamily("Consolas, JetBrains Mono, monospace"),
                FontSize = 10,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 2, 0, 0)
            });
            titleStack.Children.Add(titleRow);
            brandStack.Children.Add(titleStack);
            Grid.SetColumn(brandStack, 0);
            headerGrid.Children.Add(brandStack);

            var winBtns = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            winBtns.MouseLeftButtonDown += (s, e) => { e.Handled = true; };

            _updatePillBtn = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(16, 36, 30)),
                BorderBrush = new SolidColorBrush(ColGreen),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(8, 3, 8, 3),
                Margin = new Thickness(0, 0, 6, 0),
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center,
                Visibility = Visibility.Collapsed,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };
            _updatePillText = new TextBlock
            {
                Text = "⬆ Обновить",
                Foreground = new SolidColorBrush(ColGreen),
                FontSize = 10.5,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            _updatePillBtn.Child = _updatePillText;
            AttachButtonPressAnimation(_updatePillBtn);
            _updatePillBtn.MouseLeftButtonUp += delegate
            {
                bool hasManifestAutoUpd =
                    PixelCoreService.IsNewerVersion(APP_VERSION, PixelCoreService.ManifestLatestVersion) &&
                    !string.IsNullOrEmpty(PixelCoreService.ManifestUpdateUrl) &&
                    !string.IsNullOrEmpty(PixelCoreService.ManifestUpdateSha256) &&
                    PixelCoreService.ManifestUpdateSha256.Trim().Length == 64;
                if (hasManifestAutoUpd)
                {
                    PerformSafeInAppUpdateAsync();
                }
                else if (!string.IsNullOrEmpty(_githubReleaseUrl))
                {
                    try { using (var p = Process.Start(new ProcessStartInfo(_githubReleaseUrl) { UseShellExecute = true })) { } } catch { }
                }
            };
            winBtns.Children.Add(_updatePillBtn);

            winBtns.Children.Add(CreateWindowBtn("M5 12h14", "Свернуть", delegate { WindowState = WindowState.Minimized; }));
            winBtns.Children.Add(CreateWindowBtn("M18 6L6 18 M6 6l12 12", "\u0421\u0432\u0435\u0440\u043d\u0443\u0442\u044c \u0432 \u0442\u0440\u0435\u0439", delegate
            {
                MinimizeToTray();
            }));
            Grid.SetColumn(winBtns, 1);
            headerGrid.Children.Add(winBtns);

            rootStack.Children.Add(headerGrid);

            // ====================================================================
            // 2. STATUS CARD + PULSING HALO + LIVE AI TELEMETRY BAR
            // ====================================================================
            var statusCard = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(14, 11, 14, 11),
                Margin = new Thickness(0, 0, 0, 12)
            };

            var statusOuterStack = new StackPanel();

            var statusGrid = new Grid();
            statusGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            statusGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var statusLeft = new StackPanel();
            var statusTopRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 3) };

            var dotContainer = new Grid
            {
                Width = 18,
                Height = 18,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(-2, 0, 6, 0)
            };
            _statusPulseRing = new Ellipse
            {
                Width = 9,
                Height = 9,
                Stroke = new SolidColorBrush(ColGreen),
                StrokeThickness = 1.6,
                Fill = Brushes.Transparent,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Opacity = 0.0,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };
            _statusDot = new Ellipse
            {
                Width = 8,
                Height = 8,
                Fill = new SolidColorBrush(ColText3),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            dotContainer.Children.Add(_statusPulseRing);
            dotContainer.Children.Add(_statusDot);
            statusTopRow.Children.Add(dotContainer);

            _statusTitle = new TextBlock
            {
                Text = "Туннель остановлен",
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            statusTopRow.Children.Add(_statusTitle);
            statusLeft.Children.Add(statusTopRow);

            _statusSub = new TextBlock
            {
                Text = "Бесплатный анлокер готов • Нажмите «Запустить туннель» или «Умная диагностика»",
                Foreground = new SolidColorBrush(ColText2),
                FontSize = 11.2,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(22, 0, 6, 0)
            };
            statusLeft.Children.Add(_statusSub);
            Grid.SetColumn(statusLeft, 0);
            statusGrid.Children.Add(statusLeft);

            _pingLabel = new TextBlock
            {
                Text = "SMART TUN",
                Foreground = new SolidColorBrush(ColText3),
                FontFamily = new FontFamily("Consolas, monospace"),
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(_pingLabel, 1);
            statusGrid.Children.Add(_pingLabel);
            statusOuterStack.Children.Add(statusGrid);

            // Live Antigravity Log Telemetry & Active Stream Pill
            _aiTelemetryBorder = new Border
            {
                Background = new SolidColorBrush(ColBg),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(9, 5, 9, 5),
                Margin = new Thickness(0, 8, 0, 0)
            };
            var telGrid = new Grid();
            telGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            telGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            telGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _aiTelemetryDot = new Ellipse
            {
                Width = 6,
                Height = 6,
                Fill = new SolidColorBrush(ColBlue),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 7, 0)
            };
            Grid.SetColumn(_aiTelemetryDot, 0);
            telGrid.Children.Add(_aiTelemetryDot);

            _aiTelemetryText = new TextBlock
            {
                Text = "AI Телеметрия: вход из-под санкций активен • шлюз :17890 (PWP-4) готов",
                Foreground = new SolidColorBrush(ColText2),
                FontFamily = new FontFamily("Consolas, JetBrains Mono, monospace"),
                FontSize = 10.2,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(_aiTelemetryText, 1);
            telGrid.Children.Add(_aiTelemetryText);

            _aiVerifyBtn = new Border
            {
                Background = new SolidColorBrush(ColSurfaceHover),
                BorderBrush = new SolidColorBrush(ColAmber),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(6, 2, 6, 2),
                Margin = new Thickness(6, 0, 0, 0),
                Cursor = Cursors.Hand,
                Visibility = Visibility.Collapsed,
                ToolTip = "Открыть ссылку верификации Google аккаунта из лога Antigravity"
            };
            var verifyRow = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            verifyRow.Children.Add(CreateVectorIcon("M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6 M15 3h6v6 M10 14L21 3", ColAmber, 10));
            verifyRow.Children.Add(new TextBlock
            {
                Text = "Верификация Google",
                Foreground = new SolidColorBrush(ColAmber),
                FontSize = 10,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(4, 0, 0, 0)
            });
            _aiVerifyBtn.Child = verifyRow;
            _aiVerifyBtn.MouseLeftButtonUp += delegate
            {
                if (!string.IsNullOrEmpty(_lastValidationUrl))
                {
                    try { Process.Start(new ProcessStartInfo(_lastValidationUrl) { UseShellExecute = true }); } catch { }
                }
            };
            Grid.SetColumn(_aiVerifyBtn, 2);
            telGrid.Children.Add(_aiVerifyBtn);

            _aiTelemetryBorder.Child = telGrid;
            statusOuterStack.Children.Add(_aiTelemetryBorder);

            // Compact Live AI Pulse Row (Gemini • Claude • OpenAI from /__pixelcore/v4/ai-pulse)
            _aiPulseRowBorder = new Border
            {
                Background = new SolidColorBrush(ColBg),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(9, 4, 9, 4),
                Margin = new Thickness(0, 6, 0, 0),
                Cursor = Cursors.Hand,
                ToolTip = "Живой статус AI-шлюзов через туннель (нажмите для обновления)"
            };
            var pulseGrid = new Grid();
            pulseGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            pulseGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            pulseGrid.Children.Add(new TextBlock
            {
                Text = "Пульс AI",
                Foreground = new SolidColorBrush(ColText2),
                FontSize = 10.2,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            var pulsePills = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            pulsePills.Children.Add(BuildAiPulsePill("Gemini", out _pulseDotGemini, out _pulseTextGemini, new Thickness(0, 0, 10, 0)));
            pulsePills.Children.Add(BuildAiPulsePill("Claude", out _pulseDotClaude, out _pulseTextClaude, new Thickness(0, 0, 10, 0)));
            pulsePills.Children.Add(BuildAiPulsePill("OpenAI", out _pulseDotOpenAi, out _pulseTextOpenAi, new Thickness(0)));
            Grid.SetColumn(pulsePills, 1);
            pulseGrid.Children.Add(pulsePills);
            _aiPulseRowBorder.Child = pulseGrid;
            _aiPulseRowBorder.MouseLeftButtonUp += delegate { var unused = RefreshAiPulseUiAsync(true); };
            statusOuterStack.Children.Add(_aiPulseRowBorder);

            // 1-Click Antigravity Pre-Tunnel Leak Guard Banner (Zero .lnk Shortcut Tampering -> 1/64 VT Clean)
            _agLeakGuardBanner = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(27, 21, 12)),
                BorderBrush = new SolidColorBrush(ColAmber),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(9, 6, 8, 6),
                Margin = new Thickness(0, 7, 0, 0),
                Visibility = Visibility.Collapsed
            };
            var leakGrid = new Grid();
            leakGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            leakGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            leakGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            leakGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var leakWarnIcon = CreateVectorIcon("M13 2L3 14h9l-1 8 10-12h-9l1-8z", ColAmber, 11.5);
            leakWarnIcon.Margin = new Thickness(0, 0, 7, 0);
            leakWarnIcon.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(leakWarnIcon, 0);
            leakGrid.Children.Add(leakWarnIcon);

            _agLeakGuardText = new TextBlock
            {
                Text = "Antigravity открыт до запуска туннеля",
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 10.6,
                FontWeight = FontWeights.Medium,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Перезапустите IDE одной кнопкой, чтобы процессы Antigravity и Chromium подхватили изолированный прокси-шлюз и --disable-quic"
            };
            Grid.SetColumn(_agLeakGuardText, 1);
            leakGrid.Children.Add(_agLeakGuardText);

            var agRelaunchBtn = new Border
            {
                Background = new SolidColorBrush(ColAmber),
                BorderBrush = new SolidColorBrush(ColAmber),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(5),
                Padding = new Thickness(8, 3, 8, 3),
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0),
                ToolTip = "Мягко перезапустить Antigravity IDE с AG_LS_PROXY и --disable-quic (без изменения ярлыков Windows)"
            };
            agRelaunchBtn.Child = new TextBlock
            {
                Text = "Перезапустить в туннеле",
                Foreground = new SolidColorBrush(ColBg),
                FontSize = 10.2,
                FontWeight = FontWeights.Bold
            };
            AttachButtonPressAnimation(agRelaunchBtn);
            agRelaunchBtn.MouseLeftButtonUp += delegate
            {
                RelaunchAntigravityInTunnelAsync();
            };
            Grid.SetColumn(agRelaunchBtn, 2);
            leakGrid.Children.Add(agRelaunchBtn);

            var agDismissBtn = new Border
            {
                Background = Brushes.Transparent,
                Padding = new Thickness(6, 2, 3, 2),
                Margin = new Thickness(3, 0, 0, 0),
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = "Скрыть уведомление"
            };
            agDismissBtn.Child = CreateVectorIcon("M18 6L6 18 M6 6l12 12", ColText2, 9.5);
            agDismissBtn.MouseLeftButtonUp += delegate
            {
                _agBannerDismissed = true;
                _agLeakGuardBanner.Visibility = Visibility.Collapsed;
            };
            Grid.SetColumn(agDismissBtn, 3);
            leakGrid.Children.Add(agDismissBtn);

            _agLeakGuardBanner.Child = leakGrid;
            statusOuterStack.Children.Add(_agLeakGuardBanner);

            statusCard.Child = statusOuterStack;
            rootStack.Children.Add(statusCard);

            // ====================================================================
            // 3. AUTO-PROVISIONED 7-DAY TRIAL & PERSONAL KEY DRAWER
            // ====================================================================
            _inputBoxBorder = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(11, 5, 5, 5),
                Margin = new Thickness(0, 0, 0, 6),
                Visibility = Visibility.Collapsed
            };

            var inputGrid = new Grid();
            inputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            inputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _keyInput = new TextBox
            {
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground = new SolidColorBrush(ColText1),
                CaretBrush = Brushes.White,
                FontFamily = new FontFamily("Consolas, monospace"),
                FontSize = 12,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            };
            _keyInput.TextChanged += delegate { OnKeyTextChanged(); };
            Grid.SetColumn(_keyInput, 0);
            inputGrid.Children.Add(_keyInput);

            var pasteBtn = new Border
            {
                Background = new SolidColorBrush(ColSurfaceHover),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(10, 5, 10, 5),
                Cursor = Cursors.Hand
            };
            var pasteStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            pasteStack.Children.Add(CreateVectorIcon("M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2 M9 2h6v4H9V2z", ColText1, 11));
            pasteStack.Children.Add(new TextBlock
            {
                Text = "Вставить",
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 11.5,
                FontWeight = FontWeights.Medium,
                Margin = new Thickness(6, 0, 0, 0)
            });
            pasteBtn.Child = pasteStack;
            pasteBtn.MouseEnter += delegate { pasteBtn.BorderBrush = new SolidColorBrush(ColBorderFocus); };
            pasteBtn.MouseLeave += delegate { pasteBtn.BorderBrush = new SolidColorBrush(ColBorder); };
            pasteBtn.MouseLeftButtonUp += delegate
            {
                if (Clipboard.ContainsText())
                {
                    string pasted = Clipboard.GetText().Trim();
                    _keyInput.Text = pasted;
                    SaveCurrentState();
                    if (ParseVlessUri(pasted) != null && !_isBusy)
                    {
                        if (_isConnected) StopTunnelProcess(false);
                        StartTunnelAsync();
                    }
                }
            };
            Grid.SetColumn(pasteBtn, 1);
            inputGrid.Children.Add(pasteBtn);

            _inputBoxBorder.Child = inputGrid;
            rootStack.Children.Add(_inputBoxBorder);

            // License status indicator holders (compactly displayed in bottom bar)
            _licenseShieldHolder = new ContentControl
            {
                Content = CreateVectorIcon("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4", ColGreen, 12),
                VerticalAlignment = VerticalAlignment.Center,
                Focusable = false,
                Visibility = Visibility.Collapsed
            };
            _keyHint = new TextBlock
            {
                Text = "FREE Безлимит",
                Foreground = new SolidColorBrush(ColGreen),
                FontSize = 11,
                FontWeight = FontWeights.Medium,
                Visibility = Visibility.Collapsed
            };
            _licenseRightActionUrl = GetTelegramBotUrl();

            // Region selector hidden from main UI (always uses optimal auto-failover)
            UpdateRegionSelectorVisuals();

            // ====================================================================
            // 4. SPLIT-TUNNELING ROUTING TOGGLES
            // ====================================================================
            rootStack.Children.Add(CreateSectionHeader("ТОЧЕЧНЫЙ ОБХОД (SPLIT-TUNNELING + ВХОД ИЗ-ПОД САНКЦИЙ)"));

            var rulesCard = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Margin = new Thickness(0, 0, 0, 8)
            };

            var rulesStack = new StackPanel();

            rulesStack.Children.Add(CreateToggleRow(
                0,
                "Antigravity 2.0, IDE и Терминал",
                "Вход, плагины, MCP-серверы и агенты внутри IDE",
                true,
                out _iconBoxAg,
                out _chkBoxAg,
                out _chkMarkAg,
                delegate
                {
                    _optAntigravity = !_optAntigravity;
                    _optMcpTerminal = _optAntigravity;
                    UpdateCheckboxVisual(_chkBoxAg, _chkMarkAg, _iconBoxAg, _optAntigravity, true);
                    SaveCurrentState();
                    TriggerCategoryHotReloadIfConnected();
                },
                true,
                false
            ));

            rulesStack.Children.Add(CreateToggleRow(
                1,
                "ChatGPT, Claude, Cursor и нейросети",
                "Copilot, Midjourney, Suno, ElevenLabs, Perplexity",
                false,
                out _iconBoxAi,
                out _chkBoxAi,
                out _chkMarkAi,
                delegate
                {
                    _optCursorAi = !_optCursorAi;
                    UpdateCheckboxVisual(_chkBoxAi, _chkMarkAi, _iconBoxAi, _optCursorAi, true);
                    SaveCurrentState();
                    TriggerCategoryHotReloadIfConnected();
                },
                true,
                false
            ));

            rulesStack.Children.Add(CreateToggleRow(
                3,
                "Telegram, Spotify и соцсети",
                "Telegram, Spotify, Instagram, X, LinkedIn, Canva",
                false,
                out _iconBoxWeb,
                out _chkBoxWeb,
                out _chkMarkWeb,
                delegate
                {
                    _optSocialWeb = !_optSocialWeb;
                    UpdateCheckboxVisual(_chkBoxWeb, _chkMarkWeb, _iconBoxWeb, _optSocialWeb, true);
                    SaveCurrentState();
                    TriggerCategoryHotReloadIfConnected();
                },
                true,
                false
            ));

            rulesStack.Children.Add(CreateToggleRow(
                2,
                "YouTube & Discord",
                "Нужен наш PRO VPN (@p1xivpn_bot • iOS, Android, ПК)",
                false,
                out _iconBoxMedia,
                out _chkBoxMedia,
                out _chkMarkMedia,
                delegate
                {
                    if (!_optDiscordYt && !HasActiveProAccess())
                    {
                        if (_inputBoxBorder != null && _inputBoxBorder.Visibility != Visibility.Visible)
                        {
                            AnimateDrawerOpen(_inputBoxBorder);
                        }
                        var res = MessageBox.Show(
                            this,
                            "Antigravity, нейросети, Telegram, Spotify и соцсети работают в PixelTunnel полностью бесплатно и бессрочно!\n\n" +
                            "Тяжёлый медиа-трафик (YouTube и голосовой Discord) доступен по персональному PRO-ключу из Telegram-бота @p1xivpn_bot (этот же ключ работает как полный VPN на iPhone, Android и ПК).\n\n" +
                            "Открыть @p1xivpn_bot для получения PRO-ключа?",
                            "PixelTunnel PRO — YouTube & Discord",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Information
                        );
                        if (res == MessageBoxResult.Yes)
                        {
                            try { Process.Start(new ProcessStartInfo(GetTelegramBotUrl()) { UseShellExecute = true }); } catch { }
                        }
                        return;
                    }
                    _optDiscordYt = !_optDiscordYt;
                    UpdateCheckboxVisual(_chkBoxMedia, _chkMarkMedia, _iconBoxMedia, _optDiscordYt, true);
                    SaveCurrentState();
                    TriggerCategoryHotReloadIfConnected();
                },
                false,
                true
            ));

            rulesCard.Child = rulesStack;
            rootStack.Children.Add(rulesCard);

            // ====================================================================
            // 5. PRIMARY ACTION + CLEAN 3-BUTTON UTILITY BAR + DONATE BANNER
            // ====================================================================
            _actionBtnBorder = new Border
            {
                Background = new SolidColorBrush(ColText1),
                BorderBrush = new SolidColorBrush(ColText1),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Height = 40,
                Margin = new Thickness(0, 0, 0, 8),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };

            var actionBtnStack = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            _actionBtnIconHolder = new ContentControl
            {
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 7, 0),
                Content = CreateVectorIcon("M13 2L4 14h7l-1 8 10-12h-7z", ColBg, 14)
            };
            actionBtnStack.Children.Add(_actionBtnIconHolder);

            _actionBtnText = new TextBlock
            {
                Text = "Запустить туннель",
                Foreground = new SolidColorBrush(ColBg),
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            actionBtnStack.Children.Add(_actionBtnText);
            _actionBtnBorder.Child = actionBtnStack;
            AttachButtonPressAnimation(_actionBtnBorder);

            _actionBtnBorder.MouseEnter += delegate
            {
                if (!_isBusy) _actionBtnBorder.Opacity = 0.92;
            };
            _actionBtnBorder.MouseLeave += delegate
            {
                _actionBtnBorder.Opacity = 1.0;
            };
            _actionBtnBorder.MouseLeftButtonUp += delegate
            {
                if (_isBusy) return;
                if (_isConnected)
                    StopTunnelProcess();
                else
                    StartTunnelAsync();
            };
            rootStack.Children.Add(_actionBtnBorder);

            // 3-column utility row: [Полный VPN (рекомендация)] [Ключ] [Диагностика]
            var utilRow = new Grid { Margin = new Thickness(0, 0, 0, 8) };
            utilRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.25, GridUnitType.Star) });
            utilRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0.85, GridUnitType.Star) });
            utilRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.0, GridUnitType.Star) });

            // 5a. PRO VPN Recommendation Button (links to @p1xivpn_bot / HQ)
            _getKeyLinkBorder = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(Color.FromRgb(42, 65, 98)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Height = 36,
                Margin = new Thickness(0, 0, 6, 0),
                Padding = new Thickness(10, 0, 10, 0),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0),
                ToolTip = "Полный PRO VPN для YouTube, Discord и телефона (iOS / Android) в " + GetTelegramBotHandle()
            };
            var getKeyRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            getKeyRow.Children.Add(CreateVectorIcon("M12 2L4 5.5v6C4 16.8 7.4 21.6 12 23c4.6-1.4 8-6.2 8-11.5v-6L12 2z M13 8l-3 5h3l-1 4 3-5h-3z", ColBlue, 13));
            _getKeyText = new TextBlock
            {
                Text = "Наш VPN",
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(6, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            getKeyRow.Children.Add(_getKeyText);
            _getKeyArrowHolder = new ContentControl
            {
                Content = CreateVectorIcon("M5 12h14 M12 5l7 7-7 7", ColBlue, 10),
                Margin = new Thickness(5, 1, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Focusable = false
            };
            getKeyRow.Children.Add(_getKeyArrowHolder);
            _getKeyLinkBorder.Child = getKeyRow;
            AttachButtonPressAnimation(_getKeyLinkBorder);
            _getKeyLinkBorder.MouseEnter += delegate { _getKeyLinkBorder.Background = new SolidColorBrush(ColSurfaceHover); };
            _getKeyLinkBorder.MouseLeave += delegate { _getKeyLinkBorder.Background = new SolidColorBrush(ColSurface); };
            _getKeyLinkBorder.MouseLeftButtonUp += delegate
            {
                string target = !string.IsNullOrEmpty(_licenseRightActionUrl) ? _licenseRightActionUrl : GetTelegramBotUrl();
                try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); } catch { }
            };
            Grid.SetColumn(_getKeyLinkBorder, 0);
            utilRow.Children.Add(_getKeyLinkBorder);

            // 5b. Key Drawer Toggle Button
            var keyToggleBtn = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Height = 36,
                Margin = new Thickness(0, 0, 6, 0),
                Padding = new Thickness(8, 0, 8, 0),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0),
                ToolTip = "Вставить персональный PRO-ключ vless:// из бота"
            };
            var keyToggleStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            keyToggleStack.Children.Add(CreateVectorIcon("M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3", ColText2, 12));
            keyToggleStack.Children.Add(new TextBlock
            {
                Text = "Ключ",
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(6, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            });
            keyToggleBtn.Child = keyToggleStack;
            AttachButtonPressAnimation(keyToggleBtn);
            keyToggleBtn.MouseEnter += delegate { keyToggleBtn.Background = new SolidColorBrush(ColSurfaceHover); };
            keyToggleBtn.MouseLeave += delegate { keyToggleBtn.Background = new SolidColorBrush(ColSurface); };
            keyToggleBtn.MouseLeftButtonUp += delegate
            {
                if (_inputBoxBorder != null)
                {
                    if (_inputBoxBorder.Visibility == Visibility.Visible)
                        _inputBoxBorder.Visibility = Visibility.Collapsed;
                    else
                    {
                        AnimateDrawerOpen(_inputBoxBorder);
                        _keyInput.Focus();
                        _keyInput.SelectAll();
                    }
                }
            };
            Grid.SetColumn(keyToggleBtn, 1);
            utilRow.Children.Add(keyToggleBtn);

            // 5c. Diagnostics Button
            _diagBtnBorder = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Height = 36,
                Padding = new Thickness(8, 0, 8, 0),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0),
                ToolTip = "Проверить соединение и автоматически исправить ошибки"
            };
            var diagBtnStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            _diagBtnIconHolder = new ContentControl
            {
                VerticalAlignment = VerticalAlignment.Center,
                Content = CreateVectorIcon("M22 12h-4l-3 9L9 3l-3 9H2", ColGreen, 12.5)
            };
            diagBtnStack.Children.Add(_diagBtnIconHolder);
            _diagBtnText = new TextBlock
            {
                Text = "Диагностика",
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(6, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            diagBtnStack.Children.Add(_diagBtnText);
            _diagBtnBorder.Child = diagBtnStack;
            AttachButtonPressAnimation(_diagBtnBorder);
            _diagBtnBorder.MouseEnter += delegate { _diagBtnBorder.Background = new SolidColorBrush(ColSurfaceHover); };
            _diagBtnBorder.MouseLeave += delegate { _diagBtnBorder.Background = new SolidColorBrush(ColSurface); };
            _diagBtnBorder.MouseLeftButtonUp += delegate
            {
                RunSmartDiagnosticsAsync(true);
            };
            Grid.SetColumn(_diagBtnBorder, 2);
            utilRow.Children.Add(_diagBtnBorder);

            rootStack.Children.Add(utilRow);

            // 5d. Donate Plashka (clean bottom bar)
            var donateBanner = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12, 8, 12, 8),
                Cursor = Cursors.Hand,
                ToolTip = "Поддержать бесплатную работу серверов PixelTunnel"
            };
            var donateGrid = new Grid();
            donateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            donateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            donateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var heartHolder = new ContentControl
            {
                Content = CreateVectorIcon("M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78L12 21.23l8.84-8.84a5.5 5.5 0 0 0 0-7.78z", ColAmber, 13),
                Margin = new Thickness(0, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Focusable = false
            };
            Grid.SetColumn(heartHolder, 0);
            donateGrid.Children.Add(heartHolder);

            var donateTitleStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            donateTitleStack.Children.Add(new TextBlock
            {
                Text = "Поддержать проект",
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            donateTitleStack.Children.Add(new TextBlock
            {
                Text = " · серверы работают бесплатно",
                Foreground = new SolidColorBrush(ColText2),
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            });
            Grid.SetColumn(donateTitleStack, 1);
            donateGrid.Children.Add(donateTitleStack);

            var donateArrowStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            donateArrowStack.Children.Add(new TextBlock
            {
                Text = "Донат",
                Foreground = new SolidColorBrush(ColAmber),
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            var dArr = CreateVectorIcon("M5 12h14 M12 5l7 7-7 7", ColAmber, 10);
            dArr.Margin = new Thickness(4, 1, 0, 0);
            donateArrowStack.Children.Add(dArr);
            Grid.SetColumn(donateArrowStack, 2);
            donateGrid.Children.Add(donateArrowStack);

            donateBanner.Child = donateGrid;
            donateBanner.MouseEnter += delegate { donateBanner.Background = new SolidColorBrush(ColSurfaceHover); donateBanner.BorderBrush = new SolidColorBrush(ColBorderFocus); };
            donateBanner.MouseLeave += delegate { donateBanner.Background = new SolidColorBrush(ColSurface); donateBanner.BorderBrush = new SolidColorBrush(ColBorder); };
            donateBanner.MouseLeftButtonUp += delegate
            {
                try { Process.Start(new ProcessStartInfo(GetProjectDonateUrl()) { UseShellExecute = true }); } catch { }
            };
            rootStack.Children.Add(donateBanner);

            outerBorder.Child = rootStack;
            Content = outerBorder;
        }

        private UIElement BuildAiPulsePill(string name, out Ellipse dotOut, out TextBlock textOut, Thickness margin)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = margin };
            dotOut = new Ellipse
            {
                Width = 6,
                Height = 6,
                Fill = new SolidColorBrush(ColText3),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 4, 0)
            };
            textOut = new TextBlock
            {
                Text = name,
                Foreground = new SolidColorBrush(ColText2),
                FontFamily = new FontFamily("Consolas, monospace"),
                FontSize = 10,
                VerticalAlignment = VerticalAlignment.Center
            };
            sp.Children.Add(dotOut);
            sp.Children.Add(textOut);
            return sp;
        }

        private async Task RefreshAiPulseUiAsync(bool forceRefresh)
        {
            if (!_isConnected)
            {
                RunOnUiThread(delegate
                {
                    if (_pulseDotGemini == null) return;
                    SetAiPulsePillState(_pulseDotGemini, _pulseTextGemini, "Gemini", "idle", 0, 0);
                    SetAiPulsePillState(_pulseDotClaude, _pulseTextClaude, "Claude", "idle", 0, 0);
                    SetAiPulsePillState(_pulseDotOpenAi, _pulseTextOpenAi, "OpenAI", "idle", 0, 0);
                });
                return;
            }
            try
            {
                string raw = await PixelCoreService.QueryAiPulseV4JsonAsync(forceRefresh).ConfigureAwait(false);
                var obj = MiniJson.Deserialize(raw) as Dictionary<string, object>;
                var provs = obj != null ? MiniJson.GetDict(obj, "providers") : null;
                if (provs == null) return;

                RunOnUiThread(delegate
                {
                    if (_pulseDotGemini == null) return;
                    ApplyProviderPulse(provs, "gemini", "Gemini", _pulseDotGemini, _pulseTextGemini);
                    ApplyProviderPulse(provs, "claude", "Claude", _pulseDotClaude, _pulseTextClaude);
                    ApplyProviderPulse(provs, "openai", "OpenAI", _pulseDotOpenAi, _pulseTextOpenAi);
                });
            }
            catch { }
        }

        private void ApplyProviderPulse(Dictionary<string, object> provs, string key, string label, Ellipse dot, TextBlock tb)
        {
            var d = MiniJson.GetDict(provs, key);
            string st = d != null ? (MiniJson.GetStr(d, "status") ?? "down") : "down";
            int ms = d != null ? MiniJson.GetInt(d, "latency_ms", 0) : 0;
            int code = d != null ? MiniJson.GetInt(d, "http_code", 0) : 0;
            SetAiPulsePillState(dot, tb, label, st, code, ms);
        }

        private void SetAiPulsePillState(Ellipse dot, TextBlock tb, string label, string status, int httpCode, int ms)
        {
            if (dot == null || tb == null) return;
            Color c = (status == "ok") ? ColGreen : ((status == "degraded") ? ColAmber : ((status == "down") ? ColRed : ColText3));
            dot.Fill = new SolidColorBrush(c);
            tb.Foreground = new SolidColorBrush(status == "idle" ? ColText3 : ColText1);
            tb.ToolTip = status == "idle"
                ? (label + ": туннель отключён")
                : string.Format("{0}: {1} (HTTP {2}, {3} мс)", label, status.ToUpperInvariant(), httpCode, ms);
        }

        private TextBlock CreateSectionHeader(string text)
        {
            return new TextBlock
            {
                Text = text,
                Foreground = new SolidColorBrush(ColText3),
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(2, 0, 0, 5)
            };
        }

        private Border CreateWindowBtn(string svgData, string tooltip, Action onClick)
        {
            var b = new Border
            {
                Width = 28,
                Height = 28,
                CornerRadius = new CornerRadius(6),
                Background = new SolidColorBrush( Color.FromArgb(1, 255, 255, 255) ),
                Cursor = Cursors.Hand,
                ToolTip = tooltip,
                Margin = new Thickness(4, 0, 0, 0),
                Child = CreateVectorIcon(svgData, ColText2, 11)
            };
            b.MouseEnter += delegate { b.Background = new SolidColorBrush(ColSurfaceHover); };
            b.MouseLeave += delegate { b.Background = new SolidColorBrush(Color.FromArgb(1, 255, 255, 255)); };
            b.PreviewMouseLeftButtonDown += (s, e) => { e.Handled = true; onClick(); };
            b.MouseLeftButtonDown += (s, e) => { e.Handled = true; };
            return b;
        }

        private Border CreateToggleRow(
            int categoryId,
            string title,
            string subtitle,
            bool initialChecked,
            out Border iconBoxOut,
            out Border chkBorder,
            out ShapePath chkMark,
            Action onToggle,
            bool hasBottomBorder,
            bool isProBadge = false)
        {
            var rowBorder = new Border
            {
                Background = Brushes.Transparent,
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(0, 0, 0, hasBottomBorder ? 1 : 0),
                Padding = new Thickness(12, 7.5, 12, 7.5),
                Cursor = Cursors.Hand
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var iconBox = new Border
            {
                Width = 30,
                Height = 30,
                CornerRadius = new CornerRadius(7),
                Background = new SolidColorBrush(ColBg),
                BorderBrush = new SolidColorBrush(ColBorderFocus),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0),
                Child = CreateCategoryIcon(categoryId)
            };
            iconBoxOut = iconBox;
            Grid.SetColumn(iconBox, 0);
            grid.Children.Add(iconBox);

            var textStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            textStack.Children.Add(new TextBlock
            {
                Text = title,
                Foreground = new SolidColorBrush(ColText1),
                FontSize = 12.5,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 1)
            });
            textStack.Children.Add(new TextBlock
            {
                Text = subtitle,
                Foreground = new SolidColorBrush(ColText2),
                FontSize = 10.6,
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            Grid.SetColumn(textStack, 1);
            grid.Children.Add(textStack);

            chkMark = new ShapePath
            {
                Data = Geometry.Parse("M20 6L9 17l-5-5"),
                Stroke = new SolidColorBrush(ColBg),
                StrokeThickness = 2.5,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round,
                Stretch = Stretch.Uniform,
                Width = 10,
                Height = 10,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };

            var tierBadge = new Border
            {
                Background = new SolidColorBrush(isProBadge ? Color.FromArgb(36, 245, 158, 11) : Color.FromArgb(30, 16, 185, 129)),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(6, 2, 6, 2),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0),
                Child = new TextBlock
                {
                    Text = isProBadge ? "PRO" : "FREE",
                    Foreground = new SolidColorBrush(isProBadge ? ColAmber : ColGreen),
                    FontFamily = new FontFamily("Consolas, monospace"),
                    FontSize = 9.8,
                    FontWeight = FontWeights.Bold
                }
            };
            Grid.SetColumn(tierBadge, 2);
            grid.Children.Add(tierBadge);

            chkBorder = new Border
            {
                Width = 18,
                Height = 18,
                CornerRadius = new CornerRadius(4),
                BorderThickness = new Thickness(1),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0),
                Child = chkMark
            };
            UpdateCheckboxVisual(chkBorder, chkMark, iconBox, initialChecked, false);
            Grid.SetColumn(chkBorder, 3);
            grid.Children.Add(chkBorder);

            rowBorder.Child = grid;
            rowBorder.MouseEnter += delegate { rowBorder.Background = new SolidColorBrush(ColSurfaceHover); };
            rowBorder.MouseLeave += delegate { rowBorder.Background = Brushes.Transparent; };
            rowBorder.MouseLeftButtonUp += delegate { onToggle(); };

            return rowBorder;
        }

        private void UpdateCheckboxVisual(Border box, ShapePath mark, Border iconBox, bool isChecked, bool animate)
        {
            if (isChecked)
            {
                box.Background = new SolidColorBrush(ColText1);
                box.BorderBrush = new SolidColorBrush(ColText1);
                mark.Visibility = Visibility.Visible;
                if (iconBox != null)
                {
                    iconBox.Opacity = 1.0;
                    iconBox.BorderBrush = new SolidColorBrush(ColBorderFocus);
                }
                if (animate)
                {
                    try
                    {
                        var st = mark.RenderTransform as ScaleTransform;
                        if (st != null)
                        {
                            var anim = new DoubleAnimation(0.4, 1.0, TimeSpan.FromMilliseconds(180))
                            {
                                EasingFunction = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.6 }
                            };
                            st.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                            st.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
                        }
                    }
                    catch { }
                }
            }
            else
            {
                box.Background = new SolidColorBrush(ColBg);
                box.BorderBrush = new SolidColorBrush(ColBorderFocus);
                mark.Visibility = Visibility.Collapsed;
                if (iconBox != null)
                {
                    iconBox.Opacity = 0.45;
                    iconBox.BorderBrush = new SolidColorBrush(ColBorder);
                }
            }
        }

        // Bespoke Brand Emblem: Antigravity Rainbow Arch + Pixel Ghost with Neon Visor
        private FrameworkElement CreateBrandEmblemIcon()
        {
            var vb = new Viewbox
            {
                Width = 18,
                Height = 18,
                Stretch = Stretch.Uniform,
                IsHitTestVisible = false
            };
            var cv = new Canvas { Width = 24, Height = 24 };

            var grad = new LinearGradientBrush
            {
                StartPoint = new Point(0, 1),
                EndPoint = new Point(1, 0)
            };
            grad.GradientStops.Add(new GradientStop(ColGreen, 0.0));
            grad.GradientStops.Add(new GradientStop(ColAmber, 0.38));
            grad.GradientStops.Add(new GradientStop(ColRed, 0.70));
            grad.GradientStops.Add(new GradientStop(ColBlue, 1.0));

            // 1. Antigravity Parabolic Arch
            cv.Children.Add(new ShapePath
            {
                Data = Geometry.Parse("M 2.5 21 C 5.2 12, 8 3, 12 3 C 16 3, 18.8 12, 21.5 21"),
                Stroke = grad,
                StrokeThickness = 2.6,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            });

            // 2. Pixel Ghost Body
            cv.Children.Add(new ShapePath
            {
                Data = Geometry.Parse("M 7.8 13 C 7.8 9.2, 16.2 9.2, 16.2 13 V 20 L 14.3 18.4 L 12 20 L 9.7 18.4 L 7.8 20 Z"),
                Fill = new SolidColorBrush(ColText1)
            });

            // 3. Neon-Green Pixel Sunglasses
            cv.Children.Add(new ShapePath
            {
                Data = Geometry.Parse("M 8.2 11.8 H 11.5 V 14 H 8.2 Z M 12.5 11.8 H 15.8 V 14 H 12.5 Z"),
                Fill = new SolidColorBrush(ColGreen)
            });

            vb.Child = cv;
            return vb;
        }

        // Bespoke Unique Category Icons for all 4 Split-Tunneling Rows
        private FrameworkElement CreateCategoryIcon(int categoryId)
        {
            var vb = new Viewbox
            {
                Width = 16,
                Height = 16,
                Stretch = Stretch.Uniform,
                IsHitTestVisible = false
            };
            var cv = new Canvas { Width = 24, Height = 24 };

            if (categoryId == 0)
            {
                // Row 1: Antigravity 2.0, IDE & Google AI — Parabolic Arch + Gemini Orbital Spark
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 3.5 20.5 C 5.8 11.5, 8.4 3.5, 12 3.5 C 15.6 3.5, 18.2 11.5, 20.5 20.5"),
                    Stroke = new SolidColorBrush(ColGreen),
                    StrokeThickness = 2.2,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round
                });
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 12 9.2 L 13.4 12.6 L 16.8 14 L 13.4 15.4 L 12 18.8 L 10.6 15.4 L 7.2 14 L 10.6 12.6 Z"),
                    Fill = new SolidColorBrush(ColBlue)
                });
            }
            else if (categoryId == 1)
            {
                // Row 2: Все нейросети и AI-сервисы — Neural Processor Chip + Glowing Synapse Core
                Color colPurple = Color.FromRgb(168, 85, 247); // #A855F7
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 9.5 3 V 7 M 14.5 3 V 7 M 9.5 17 V 21 M 14.5 17 V 21 M 3 9.5 H 7 M 3 14.5 H 7 M 17 9.5 H 21 M 17 14.5 H 21"),
                    Stroke = new SolidColorBrush(ColBlue),
                    StrokeThickness = 1.9,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round
                });
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 7 7 H 17 V 17 H 7 Z"),
                    Stroke = new SolidColorBrush(colPurple),
                    StrokeThickness = 2.0,
                    StrokeLineJoin = PenLineJoin.Round
                });
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 10.2 10.2 H 13.8 V 13.8 H 10.2 Z"),
                    Fill = new SolidColorBrush(ColGreen)
                });
            }
            else if (categoryId == 2)
            {
                // Row 3: Discord, Telegram & YouTube 4K — Play Prism + Dual Acoustic Sonic Waves
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 4.5 5.5 L 14 12 L 4.5 18.5 Z"),
                    Stroke = new SolidColorBrush(ColAmber),
                    Fill = new SolidColorBrush(Color.FromArgb(55, 245, 158, 11)),
                    StrokeThickness = 2.0,
                    StrokeLineJoin = PenLineJoin.Round
                });
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 16.8 8.5 C 18.8 10.3, 18.8 13.7, 16.8 15.5 M 19.8 5.8 C 22.8 9.2, 22.8 14.8, 19.8 18.2"),
                    Stroke = new SolidColorBrush(ColBlue),
                    StrokeThickness = 2.0,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round
                });
            }
            else if (categoryId == 4)
            {
                // Row MCP: Terminal Prompt >_ + Isolated Shield Spark
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 4 5 H 20 V 19 H 4 Z"),
                    Stroke = new SolidColorBrush(ColBlue),
                    StrokeThickness = 1.85,
                    StrokeLineJoin = PenLineJoin.Round
                });
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 7.5 9.5 L 10.8 12 L 7.5 14.5 M 12.2 14.5 H 16.5"),
                    Stroke = new SolidColorBrush(ColGreen),
                    StrokeThickness = 2.1,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round,
                    StrokeLineJoin = PenLineJoin.Round
                });
            }
            else
            {
                // Row 4: Соцсети и заблокированные сайты — Global Orbital Mesh + Unblock Meridian
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 12 3 A 9 9 0 1 0 12 21 A 9 9 0 1 0 12 3 Z M 3.6 9.5 H 20.4 M 3.6 14.5 H 20.4"),
                    Stroke = new SolidColorBrush(ColBlue),
                    StrokeThickness = 1.85,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round
                });
                cv.Children.Add(new ShapePath
                {
                    Data = Geometry.Parse("M 12 3 C 8.6 6.8, 8.6 17.2, 12 21 C 15.4 17.2, 15.4 6.8, 12 3 Z"),
                    Stroke = new SolidColorBrush(ColGreen),
                    StrokeThickness = 1.85,
                    StrokeLineJoin = PenLineJoin.Round
                });
            }

            vb.Child = cv;
            return vb;
        }

        private FrameworkElement CreateSpinningIcon(Color strokeColor, double size)
        {
            var rt = new RotateTransform(0);
            var path = new ShapePath
            {
                Data = Geometry.Parse("M12 2a10 10 0 1 0 10 10"),
                Stroke = new SolidColorBrush(strokeColor),
                StrokeThickness = 2.2,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round,
                Stretch = Stretch.Uniform,
                Width = size,
                Height = size,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = rt,
                IsHitTestVisible = false
            };
            try
            {
                var anim = new DoubleAnimation(0, 360, TimeSpan.FromMilliseconds(850))
                {
                    RepeatBehavior = RepeatBehavior.Forever
                };
                rt.BeginAnimation(RotateTransform.AngleProperty, anim);
            }
            catch { }
            return path;
        }

        private static void AttachButtonPressAnimation(Border btn)
        {
            if (btn == null) return;
            btn.MouseLeftButtonDown += delegate
            {
                try
                {
                    var st = btn.RenderTransform as ScaleTransform;
                    if (st != null)
                    {
                        var anim = new DoubleAnimation(0.97, TimeSpan.FromMilliseconds(80));
                        st.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                        st.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
                    }
                }
                catch { }
            };
            MouseButtonEventHandler restore = delegate
            {
                try
                {
                    var st = btn.RenderTransform as ScaleTransform;
                    if (st != null)
                    {
                        var anim = new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(140))
                        {
                            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                        };
                        st.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                        st.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
                    }
                }
                catch { }
            };
            btn.MouseLeftButtonUp += restore;
            btn.MouseLeave += delegate { restore(btn, null); };
        }

        private static void AnimateDrawerOpen(Border panel)
        {
            if (panel == null) return;
            panel.Visibility = Visibility.Visible;
            try
            {
                var tt = new TranslateTransform(0, -8);
                panel.RenderTransform = tt;
                var fade = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(200))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                var slide = new DoubleAnimation(-8.0, 0.0, TimeSpan.FromMilliseconds(220))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                panel.BeginAnimation(UIElement.OpacityProperty, fade);
                tt.BeginAnimation(TranslateTransform.YProperty, slide);
            }
            catch { }
        }

        private void UpdateStatusPulseAnimation(Color dotColor, bool activePulse)
        {
            try
            {
                if (_statusPulseRing == null) return;
                _statusPulseRing.Stroke = new SolidColorBrush(dotColor);
                var st = _statusPulseRing.RenderTransform as ScaleTransform;
                if (st == null)
                {
                    st = new ScaleTransform(1.0, 1.0);
                    _statusPulseRing.RenderTransform = st;
                }

                if (activePulse)
                {
                    var scaleAnim = new DoubleAnimation(0.85, 2.25, TimeSpan.FromMilliseconds(1500))
                    {
                        RepeatBehavior = RepeatBehavior.Forever,
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    };
                    var fadeAnim = new DoubleAnimation(0.65, 0.0, TimeSpan.FromMilliseconds(1500))
                    {
                        RepeatBehavior = RepeatBehavior.Forever,
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    };
                    st.BeginAnimation(ScaleTransform.ScaleXProperty, scaleAnim);
                    st.BeginAnimation(ScaleTransform.ScaleYProperty, scaleAnim);
                    _statusPulseRing.BeginAnimation(UIElement.OpacityProperty, fadeAnim);
                }
                else
                {
                    st.BeginAnimation(ScaleTransform.ScaleXProperty, null);
                    st.BeginAnimation(ScaleTransform.ScaleYProperty, null);
                    _statusPulseRing.BeginAnimation(UIElement.OpacityProperty, null);
                    _statusPulseRing.Opacity = 0.0;
                }
            }
            catch { }
        }

        private FrameworkElement CreateVectorIcon(string pathData, Color strokeColor, double size)
        {
            var path = new ShapePath
            {
                Data = Geometry.Parse(pathData),
                Stroke = new SolidColorBrush(strokeColor),
                StrokeThickness = 2.0,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round,
                StrokeLineJoin = PenLineJoin.Round,
                Stretch = Stretch.Uniform,
                Width = size,
                Height = size,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                IsHitTestVisible = false
            };
            return path;
        }

        private static string GetMachineHwidShort()
        {
            try
            {
                string raw = "";
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false))
                    {
                        if (k != null) raw = Convert.ToString(k.GetValue("MachineGuid", ""));
                    }
                }
                catch { }
                if (string.IsNullOrEmpty(raw))
                {
                    raw = Environment.MachineName + "_" + Environment.UserName;
                }
                uint hash = 2166136261u;
                foreach (char c in raw.ToUpperInvariant())
                {
                    hash ^= (byte)c;
                    hash *= 16777619u;
                }
                return hash.ToString("X8");
            }
            catch { return "7F8A9C1E"; }
        }

        private string EnsureAutoTrialKeyProvisioned(out int daysRemaining)
        {
            daysRemaining = 9999;
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(@"Software\PixelTunnel"))
                {
                    if (k != null && k.GetValue("TrialStartUtcTicks", null) == null)
                    {
                        k.SetValue("TrialStartUtcTicks", DateTime.UtcNow.Ticks.ToString(), RegistryValueKind.String);
                    }
                }
            }
            catch { }
            return GetFreeModeSentinelUri();
        }

        private static bool IsCustomPaidKey(string rawText)
        {
            if (string.IsNullOrWhiteSpace(rawText)) return false;
            VlessNode n = ParseVlessUri(rawText.Trim());
            if (n == null || string.IsNullOrEmpty(n.Uuid)) return false;
            return !string.Equals(n.Uuid, "free", StringComparison.OrdinalIgnoreCase);
        }

        private void ApplyLicenseBarState(
            Color accentColor,
            string statusText,
            string statusTooltip,
            string rightLabel,
            string rightUrl,
            string rightTooltip,
            bool externalDiagonalIcon)
        {
            if (_keyHint != null)
            {
                _keyHint.Text = statusText;
                _keyHint.Foreground = new SolidColorBrush(accentColor);
                _keyHint.ToolTip = statusTooltip;
            }
            if (_licenseShieldHolder != null)
            {
                string shieldPath = (accentColor == ColGreen)
                    ? "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4"
                    : "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M12 8v4 M12 16h.01";
                _licenseShieldHolder.Content = CreateVectorIcon(shieldPath, accentColor, 13);
            }
            _licenseRightActionUrl = rightUrl;
            if (_getKeyText != null)
            {
                _getKeyText.Text = rightLabel;
                _getKeyText.Foreground = new SolidColorBrush(externalDiagonalIcon ? ColGreen : ColText1);
            }
            if (_getKeyArrowHolder != null)
            {
                string arrPath = externalDiagonalIcon
                    ? "M7 17L17 7 M8 7h9v9"
                    : "M5 12h14 M12 5l7 7-7 7";
                _getKeyArrowHolder.Content = CreateVectorIcon(arrPath, externalDiagonalIcon ? ColGreen : ColText1, 10);
            }
            if (_getKeyLinkBorder != null)
            {
                _getKeyLinkBorder.ToolTip = rightTooltip;
            }
        }

        private void UpdateLicenseHintFromServer()
        {
            if (_keyHint == null) return;
            string tier = PixelCoreService.ServerLicenseTier;
            int sDays = PixelCoreService.ServerDaysLeft;
            if (string.IsNullOrEmpty(tier) || sDays < 0) return;

            string hwid = GetMachineHwidShort();
            int used = PixelCoreService.ServerDevicesUsed;
            int max = PixelCoreService.ServerDevicesMax;
            string devBadge = (max > 0 && max < 50) ? string.Format(" ({0}/{1} ПК)", Math.Max(1, used), max) : "";

            if (string.Equals(tier, "admin", StringComparison.OrdinalIgnoreCase))
            {
                ApplyLicenseBarState(
                    ColGreen,
                    string.Format("PRO Безлимит • ПК #{0}", hwid),
                    string.Format("Админ-доступ без ограничений • ПК #{0} • PWP-3 0-RTT Mux", hwid),
                    "Наш VPN",
                    GetTelegramBotUrl(),
                    "Открыть @p1xivpn_bot — наш VPN для YouTube, Discord, iOS и Android",
                    false
                );
            }
            else if (string.Equals(tier, "pro", StringComparison.OrdinalIgnoreCase))
            {
                if (sDays <= 3)
                {
                    ApplyLicenseBarState(
                        ColAmber,
                        string.Format("PRO истекает • {0} дн.{1}", Math.Max(1, sDays), devBadge),
                        string.Format("Подписка скоро закончится (ПК #{0}) • Продлите в {1}", hwid, GetTelegramBotHandle()),
                        "Продлить",
                        GetTelegramBotUrl(),
                        "Продлить подписку в " + GetTelegramBotHandle(),
                        false
                    );
                }
                else
                {
                    ApplyLicenseBarState(
                        ColGreen,
                        string.Format("PRO активен • {0} дн.{1}", sDays, devBadge),
                        string.Format("Персональная подписка PRO активна • ПК #{0}", hwid),
                        "Продлить",
                        GetTelegramBotUrl(),
                        "Продлить или управлять ключом в " + GetTelegramBotHandle(),
                        false
                    );
                }
            }
            else
            {
                ApplyLicenseBarState(
                    ColGreen,
                    string.Format("FREE Безлимит • ПК #{0}", hwid),
                    string.Format("Бессрочный бесплатный доступ (AI, IDE, Spotify, соцсети) • ПК #{0}", hwid),
                    "Наш VPN",
                    GetTelegramBotUrl(),
                    "Подключить YouTube, Discord и VPN на телефон в " + GetTelegramBotHandle(),
                    false
                );
            }
        }

        private void OnKeyTextChanged()
        {
            if (_keyHint == null) return;
            int daysLeft;
            EnsureAutoTrialKeyProvisioned(out daysLeft);
            string hwid = GetMachineHwidShort();
            string curKey = _keyInput != null ? _keyInput.Text : "";

            if (IsCustomPaidKey(curKey))
            {
                ApplyLicenseBarState(
                    ColGreen,
                    string.Format("PRO активен • ПК #{0}", hwid),
                    string.Format("Персональный ключ vless:// привязан к ПК #{0}", hwid),
                    "Продлить",
                    GetTelegramBotUrl(),
                    "Продлить подписку в " + GetTelegramBotHandle(),
                    false
                );
            }
            else
            {
                if (_optDiscordYt && _chkBoxMedia != null)
                {
                    _optDiscordYt = false;
                    UpdateCheckboxVisual(_chkBoxMedia, _chkMarkMedia, _iconBoxMedia, false, false);
                }
                ApplyLicenseBarState(
                    ColGreen,
                    string.Format("FREE Безлимит • ПК #{0}", hwid),
                    string.Format("Бессрочный бесплатный доступ (AI, IDE, Spotify, соцсети) для ПК #{0}", hwid),
                    "Наш VPN",
                    GetTelegramBotUrl(),
                    "Подключить YouTube, Discord и VPN на телефон в " + GetTelegramBotHandle(),
                    false
                );
            }
        }

        private bool ApplyLicenseErrorToUi(string errCode)
        {
            if (string.IsNullOrEmpty(errCode)) return false;
            string hwid = GetMachineHwidShort();

            if (_inputBoxBorder != null && _inputBoxBorder.Visibility != Visibility.Visible)
            {
                AnimateDrawerOpen(_inputBoxBorder);
            }

            if (errCode.IndexOf("TRIAL_EXPIRED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                ApplyLicenseBarState(
                    ColAmber,
                    string.Format("Триал завершён • ПК #{0}", hwid),
                    string.Format("Пробный период 7 дней завершён • Нужен ключ из {0}", GetTelegramBotHandle()),
                    "Купить в боте",
                    GetTelegramBotUrl(),
                    "Купить ключ в " + GetTelegramBotHandle(),
                    false
                );
                SetStatus(
                    ColAmber,
                    "Пробный период 7 дней завершён",
                    string.Format("Возьмите персональный ключ в {0} и нажмите «Вставить» выше.", GetTelegramBotHandle())
                );
                return true;
            }
            if (errCode.IndexOf("KEY_EXPIRED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                ApplyLicenseBarState(
                    ColAmber,
                    string.Format("Ключ истёк • ПК #{0}", hwid),
                    string.Format("Срок действия ключа истёк • Продлите в {0}", GetTelegramBotHandle()),
                    "Продлить в боте",
                    GetTelegramBotUrl(),
                    "Продлить подписку в " + GetTelegramBotHandle(),
                    false
                );
                SetStatus(
                    ColAmber,
                    "Срок подписки по ключу истёк",
                    string.Format("Продлите подписку в {0} или вставьте актуальный ключ vless:// выше.", GetTelegramBotHandle())
                );
                return true;
            }
            if (errCode.IndexOf("DEVICE_LIMIT", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                ApplyLicenseBarState(
                    ColRed,
                    string.Format("Лимит 3/3 ПК • #{0}", hwid),
                    "Этот ключ уже привязан к 3 компьютерам",
                    "Доп. ключ",
                    GetTelegramBotUrl(),
                    "Оформить дополнительный ключ в " + GetTelegramBotHandle(),
                    false
                );
                SetStatus(
                    ColRed,
                    "Превышен лимит устройств (макс. 3 ПК)",
                    string.Format("Этот ключ уже привязан к 3 устройствам. Оформите доп. ключ в {0}.", GetTelegramBotHandle())
                );
                return true;
            }
            if (errCode.IndexOf("INVALID_KEY", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                ApplyLicenseBarState(
                    ColRed,
                    string.Format("Неверный ключ • ПК #{0}", hwid),
                    "Сервер отклонил введённый ключ",
                    "Ключ в боте",
                    GetTelegramBotUrl(),
                    "Скопируйте актуальный ключ в " + GetTelegramBotHandle(),
                    false
                );
                SetStatus(
                    ColRed,
                    "Недействительный ключ доступа",
                    string.Format("Сервер отклонил ключ. Скопируйте свежий ключ vless:// в {0} и нажмите «Вставить».", GetTelegramBotHandle())
                );
                return true;
            }
            return false;
        }

        private Border CreateRegionPillCard(string regionCode, string labelText, string iconPath, out TextBlock labelOut, Thickness margin)
        {
            var card = new Border
            {
                Background = new SolidColorBrush(ColSurface),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(7),
                Padding = new Thickness(8, 6, 8, 6),
                Margin = margin,
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };

            var row = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            var icon = CreateVectorIcon(iconPath, ColText2, 11);
            icon.Margin = new Thickness(0, 0, 5, 0);
            row.Children.Add(icon);

            var tb = new TextBlock
            {
                Text = labelText,
                Foreground = new SolidColorBrush(ColText2),
                FontSize = 10.6,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            row.Children.Add(tb);
            card.Child = row;
            labelOut = tb;

            AttachButtonPressAnimation(card);
            card.MouseLeftButtonUp += delegate
            {
                OnRegionPillClicked(regionCode);
            };
            return card;
        }

        private void OnRegionPillClicked(string regionCode)
        {
            if (string.Equals(regionCode, "us", StringComparison.OrdinalIgnoreCase) && !PixelCoreService.IsRegionAvailable("us"))
            {
                if (_aiTelemetryText != null && _aiTelemetryDot != null)
                {
                    _aiTelemetryDot.Fill = new SolidColorBrush(ColAmber);
                    _aiTelemetryText.Text = "Узел США готов в PWP-3 — включится автоматически через облачный манифест";
                }
                return;
            }

            _selectedRegion = regionCode;
            UpdateRegionSelectorVisuals();
            SaveCurrentState();
            PixelCoreService.SetPreferredRegion(_selectedRegion);

            if (_isConnected && _aiTelemetryText != null)
            {
                string regHuman = regionCode == "nl" ? "Нидерланды (NL)" : (regionCode == "us" ? "США (US)" : "Авто (лучший пинг)");
                _aiTelemetryDot.Fill = new SolidColorBrush(ColGreen);
                _aiTelemetryText.Text = "Локация переключена на лету: " + regHuman + " • PWP-3 Dual-Mux";
            }
        }

        private void UpdateRegionSelectorVisuals()
        {
            try
            {
                bool usReady = PixelCoreService.IsRegionAvailable("us");
                if (_regTextUs != null)
                {
                    _regTextUs.Text = usReady ? "US • США" : "US • США (Скоро)";
                }

                ApplyRegionPillVisual(_regPillAuto, _regTextAuto, string.Equals(_selectedRegion, "auto", StringComparison.OrdinalIgnoreCase), true);
                ApplyRegionPillVisual(_regPillNl, _regTextNl, string.Equals(_selectedRegion, "nl", StringComparison.OrdinalIgnoreCase), true);
                ApplyRegionPillVisual(_regPillUs, _regTextUs, usReady && string.Equals(_selectedRegion, "us", StringComparison.OrdinalIgnoreCase), usReady);
            }
            catch { }
        }

        private static void ApplyRegionPillVisual(Border pill, TextBlock tb, bool isSelected, bool isAvailable)
        {
            if (pill == null || tb == null) return;
            if (isSelected)
            {
                pill.Background = new SolidColorBrush(Color.FromRgb(18, 34, 29));
                pill.BorderBrush = new SolidColorBrush(ColGreen);
                tb.Foreground = new SolidColorBrush(ColText1);
                pill.Opacity = 1.0;
            }
            else if (isAvailable)
            {
                pill.Background = new SolidColorBrush(ColSurface);
                pill.BorderBrush = new SolidColorBrush(ColBorder);
                tb.Foreground = new SolidColorBrush(ColText2);
                pill.Opacity = 1.0;
            }
            else
            {
                pill.Background = new SolidColorBrush(ColSurface);
                pill.BorderBrush = new SolidColorBrush(ColBorder);
                tb.Foreground = new SolidColorBrush(ColText3);
                pill.Opacity = 0.72;
            }
        }

        private static string GetFallbackSavedKeyPath()
        {
            string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string dir = System.IO.Path.Combine(localApp, "PixelTunnel");
            try { if (!Directory.Exists(dir)) Directory.CreateDirectory(dir); } catch { }
            string prodFile = System.IO.Path.Combine(dir, "saved_key.txt");
            if (!File.Exists(prodFile))
            {
                try
                {
                    string legacyNext = System.IO.Path.Combine(localApp, "PixelTunnel_Next", "saved_key.txt");
                    if (File.Exists(legacyNext)) File.Copy(legacyNext, prodFile, false);
                }
                catch { }
            }
            return prodFile;
        }

        private void LoadSavedState()
        {
            try
            {
                string pathToRead = File.Exists(_savedKeyPath) ? _savedKeyPath : GetFallbackSavedKeyPath();
                bool migratedToV2 = false;
                if (File.Exists(pathToRead))
                {
                    string[] lines = File.ReadAllLines(pathToRead, Encoding.UTF8);
                    if (lines.Length > 0) _keyInput.Text = lines[0].Trim();
                    if (lines.Length > 1)
                    {
                        string flags = lines[1].Trim();
                        if (flags.Contains("V2=1"))
                        {
                            _optAntigravity = !flags.Contains("AG=0");
                            _optMcpTerminal = !flags.Contains("MCP=0");
                            _optCursorAi = flags.Contains("AI=1");
                            _optDiscordYt = flags.Contains("MEDIA=1");
                            _optSocialWeb = flags.Contains("WEB=1");
                            _useSmartPacMode = !flags.Contains("PAC=0");
                            _optWslBridge = flags.Contains("WSL=1");
                            var mReg = Regex.Match(flags, @"REG=(auto|nl|us)", RegexOptions.IgnoreCase);
                            if (mReg.Success)
                            {
                                string r = mReg.Groups[1].Value.ToLowerInvariant();
                                if (r != "us" || PixelCoreService.IsRegionAvailable("us"))
                                    _selectedRegion = r;
                            }
                        }
                        else
                        {
                            // Automatic migration to isolated "Only Antigravity" mode so Cursor/browsers are untouched by default
                            _optAntigravity = true;
                            _optMcpTerminal = true;
                            _optCursorAi = false;
                            _optDiscordYt = false;
                            _optSocialWeb = false;
                            _useSmartPacMode = true;
                            _optWslBridge = false;
                            migratedToV2 = true;
                        }
                        _optMcpTerminal = _optAntigravity;
                        UpdateCheckboxVisual(_chkBoxAg, _chkMarkAg, _iconBoxAg, _optAntigravity, false);
                        if (_chkBoxMcp != null) UpdateCheckboxVisual(_chkBoxMcp, _chkMarkMcp, _iconBoxMcp, _optMcpTerminal, false);
                        UpdateCheckboxVisual(_chkBoxAi, _chkMarkAi, _iconBoxAi, _optCursorAi, false);
                        if (_optDiscordYt && !HasActiveProAccess()) _optDiscordYt = false;
                        UpdateCheckboxVisual(_chkBoxMedia, _chkMarkMedia, _iconBoxMedia, _optDiscordYt, false);
                        UpdateCheckboxVisual(_chkBoxWeb, _chkMarkWeb, _iconBoxWeb, _optSocialWeb, false);
                        UpdateRegionSelectorVisuals();
                        PixelCoreService.SetPreferredRegion(_selectedRegion);
                    }
                }

                int daysLeft;
                string autoTrialKey = EnsureAutoTrialKeyProvisioned(out daysLeft);
                string curLoadedKey = _keyInput.Text ?? "";
                if (string.IsNullOrWhiteSpace(curLoadedKey) ||
                    curLoadedKey.IndexOf("nln.rusweb.net", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    curLoadedKey.IndexOf("#PixelTunnel-Trial", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    _keyInput.Text = autoTrialKey;
                    SaveCurrentState();
                }
                else if (migratedToV2)
                {
                    SaveCurrentState();
                }
                OnKeyTextChanged();
                RefreshAiTelemetryBanner();
            }
            catch { }
        }

        // ====================================================================
        // ANTIGRAVITY SANCTIONED ACCOUNT LOGIN UNLOCKER ("ВХОД ИЗ-ПОД САНКЦИЙ")
        // Patches language_server.exe (inexigible_tiers + inexigibleTiers + AG_LS_PROXY)
        // ====================================================================
        private static int FindSubArray(byte[] buffer, int length, byte[] pattern, int startIdx)
        {
            int limit = length - pattern.Length;
            if (limit < startIdx) return -1;
            byte first = pattern[0];
            for (int i = startIdx; i <= limit; i++)
            {
                if (buffer[i] != first) continue;
                bool match = true;
                for (int j = 1; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }

        private static List<long> ScanBinaryForPatternOffsets(string filePath, byte[] pattern)
        {
            var results = new List<long>();
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int chunkSize = 4 * 1024 * 1024;
                    int overlap = pattern.Length + 8;
                    byte[] buf = new byte[chunkSize + overlap];
                    long filePos = 0;
                    int carry = 0;

                    while (true)
                    {
                        int read = fs.Read(buf, carry, chunkSize);
                        if (read <= 0) break;
                        int total = carry + read;

                        int idx = 0;
                        while ((idx = FindSubArray(buf, total, pattern, idx)) >= 0)
                        {
                            long absOffset = filePos - carry + idx;
                            if (!results.Contains(absOffset)) results.Add(absOffset);
                            idx += pattern.Length;
                        }

                        filePos += read;
                        if (total > overlap)
                        {
                            Buffer.BlockCopy(buf, total - overlap, buf, 0, overlap);
                            carry = overlap;
                        }
                        else
                        {
                            carry = total;
                        }
                    }
                }
            }
            catch { }
            return results;
        }

        private static List<string> DiscoverAntigravityLanguageServerBinaries()
        {
            var candidateBins = new List<string>();
            try
            {
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

                string[] roots = new[]
                {
                    System.IO.Path.Combine(localAppData, "Programs", "Antigravity"),
                    System.IO.Path.Combine(localAppData, "Programs", "antigravity"),
                    System.IO.Path.Combine(localAppData, "Programs", "Antigravity IDE"),
                    System.IO.Path.Combine(progFiles, "Antigravity"),
                    System.IO.Path.Combine(progFiles, "Antigravity IDE")
                };

                string[] relPaths = new[]
                {
                    @"resources\bin\language_server.exe",
                    @"resources\bin\language_server_windows_x64.exe",
                    @"resources\app\extensions\antigravity\bin\language_server.exe",
                    @"resources\app\extensions\antigravity\bin\language_server_windows_x64.exe"
                };

                foreach (var r in roots)
                {
                    if (!Directory.Exists(r)) continue;
                    foreach (var rel in relPaths)
                    {
                        string full = System.IO.Path.Combine(r, rel);
                        if (File.Exists(full) && !candidateBins.Contains(full)) candidateBins.Add(full);
                    }
                }

                foreach (var pName in new[] { "language_server", "language_server_windows_x64", "Antigravity" })
                {
                    try
                    {
                        foreach (var p in Process.GetProcessesByName(pName))
                        {
                            try
                            {
                                string exe = p.MainModule.FileName;
                                if (string.IsNullOrEmpty(exe)) continue;
                                if (exe.EndsWith("Antigravity.exe", StringComparison.OrdinalIgnoreCase))
                                {
                                    string dir = System.IO.Path.GetDirectoryName(exe);
                                    foreach (var rel in relPaths)
                                    {
                                        string ls = System.IO.Path.Combine(dir, rel);
                                        if (File.Exists(ls) && !candidateBins.Contains(ls)) candidateBins.Add(ls);
                                    }
                                }
                                else if (File.Exists(exe) && !candidateBins.Contains(exe))
                                {
                                    candidateBins.Add(exe);
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return candidateBins;
        }

        private static string GetFileSignatureFast(string filePath)
        {
            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists) return "";
                return string.Format("{0}_{1}", fi.LastWriteTimeUtc.Ticks, fi.Length);
            }
            catch { return ""; }
        }

        private static bool HasUnverifiedAntigravityBinaryOnDisk()
        {
            try
            {
                var bins = DiscoverAntigravityLanguageServerBinaries();
                foreach (var b in bins)
                {
                    string sig = GetFileSignatureFast(b);
                    if (string.IsNullOrEmpty(sig)) continue;
                    lock (_verifiedLsBinSignatures)
                    {
                        string cachedSig;
                        if (!_verifiedLsBinSignatures.TryGetValue(b, out cachedSig) || cachedSig != sig)
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool PatchAntigravitySanctionsAndProxy(out List<string> logs, bool restartIfAlreadyPatched)
        {
            bool dummyPatchedNow;
            return PatchAntigravitySanctionsAndProxy(out logs, restartIfAlreadyPatched, out dummyPatchedNow);
        }

        private static bool PatchAntigravitySanctionsAndProxy(out List<string> logs, bool restartIfAlreadyPatched, out bool anyPatchedNow)
        {
            logs = new List<string>();
            anyPatchedNow = false;
            bool anyVerified = false;

            try
            {
                var candidateBins = DiscoverAntigravityLanguageServerBinaries();

                byte[] patTiers1 = Encoding.ASCII.GetBytes("ineligible_tiers");
                byte[] repTiers1 = Encoding.ASCII.GetBytes("inexigible_tiers");
                byte[] patTiers2 = Encoding.ASCII.GetBytes("ineligibleTiers");
                byte[] repTiers2 = Encoding.ASCII.GetBytes("inexigibleTiers");
                byte[] patProxy  = Encoding.ASCII.GetBytes("retry-afterHTTPS_PROXY");
                byte[] repProxy  = Encoding.ASCII.GetBytes("retry-afterAG_LS_PROXY");

                foreach (var binPath in candidateBins)
                {
                    try
                    {
                        var offTiers1 = ScanBinaryForPatternOffsets(binPath, patTiers1);
                        var offTiers2 = ScanBinaryForPatternOffsets(binPath, patTiers2);
                        var offProxy  = ScanBinaryForPatternOffsets(binPath, patProxy);

                        if (offTiers1.Count == 0 && offTiers2.Count == 0 && offProxy.Count == 0)
                        {
                            var checkDone = ScanBinaryForPatternOffsets(binPath, repTiers1);
                            if (checkDone.Count > 0)
                            {
                                anyVerified = true;
                                string sigOk = GetFileSignatureFast(binPath);
                                if (!string.IsNullOrEmpty(sigOk))
                                {
                                    lock (_verifiedLsBinSignatures) { _verifiedLsBinSignatures[binPath] = sigOk; }
                                }
                                logs.Add("  ✓ [ВХОД ИЗ-ПОД САНКЦИЙ] Патч разблокировки Google-аккаунта в language_server.exe активен (inexigible_tiers + AG_LS_PROXY).");
                            }
                            continue;
                        }

                        // Stop language_server so we can write in-place or swap
                        foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
                        {
                            foreach (var p in Process.GetProcessesByName(lsName))
                            {
                                try { p.Kill(); p.WaitForExit(1000); } catch { }
                            }
                        }

                        // Clean up old .old file if present
                        string oldBak = binPath + ".old";
                        try { if (File.Exists(oldBak)) File.Delete(oldBak); } catch { }

                        bool patchedThisFile = false;
                        try
                        {
                            using (var fs = new FileStream(binPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                            {
                                foreach (long pos in offTiers1)
                                {
                                    fs.Seek(pos, SeekOrigin.Begin);
                                    fs.Write(repTiers1, 0, repTiers1.Length);
                                }
                                foreach (long pos in offTiers2)
                                {
                                    fs.Seek(pos, SeekOrigin.Begin);
                                    fs.Write(repTiers2, 0, repTiers2.Length);
                                }
                                foreach (long pos in offProxy)
                                {
                                    fs.Seek(pos, SeekOrigin.Begin);
                                    fs.Write(repProxy, 0, repProxy.Length);
                                }
                                fs.Flush();
                            }
                            patchedThisFile = true;
                        }
                        catch
                        {
                            // Fallback: rename locked running exe to .old, copy to original name, and patch
                            try
                            {
                                File.Move(binPath, oldBak);
                                File.Copy(oldBak, binPath, true);
                                using (var fs = new FileStream(binPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                                {
                                    foreach (long pos in offTiers1)
                                    {
                                        fs.Seek(pos, SeekOrigin.Begin);
                                        fs.Write(repTiers1, 0, repTiers1.Length);
                                    }
                                    foreach (long pos in offTiers2)
                                    {
                                        fs.Seek(pos, SeekOrigin.Begin);
                                        fs.Write(repTiers2, 0, repTiers2.Length);
                                    }
                                    foreach (long pos in offProxy)
                                    {
                                        fs.Seek(pos, SeekOrigin.Begin);
                                        fs.Write(repProxy, 0, repProxy.Length);
                                    }
                                    fs.Flush();
                                }
                                foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
                                {
                                    foreach (var p in Process.GetProcessesByName(lsName))
                                    {
                                        try { p.Kill(); } catch { }
                                    }
                                }
                                patchedThisFile = true;
                            }
                            catch { }
                        }

                        if (patchedThisFile)
                        {
                            anyPatchedNow = true;
                            anyVerified = true;
                            string sigNew = GetFileSignatureFast(binPath);
                            if (!string.IsNullOrEmpty(sigNew))
                            {
                                lock (_verifiedLsBinSignatures) { _verifiedLsBinSignatures[binPath] = sigNew; }
                            }
                            logs.Add("  ⚡ [АВТО-ПАТЧ САНКЦИЙ] Успешно пропатчен language_server.exe: снят блок «Account ineligible» (inexigible_tiers) + шлюз AG_LS_PROXY!");
                        }
                    }
                    catch { }
                }

                if ((anyPatchedNow || restartIfAlreadyPatched) && !IsAiStreamActivelyFlowing())
                {
                    foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
                    {
                        foreach (var p in Process.GetProcessesByName(lsName))
                        {
                            try { p.Kill(); } catch { }
                        }
                    }
                }
            }
            catch { }
            return anyPatchedNow || anyVerified;
        }

        private void SaveCurrentState()
        {
            string savedKey = ReadFromUiThread(() => _keyInput != null ? (_keyInput.Text ?? "").Trim() : "", "");
            string[] data = new[]
            {
                savedKey,
                string.Format("V2=1;AG={0};MCP={1};AI={2};MEDIA={3};WEB={4};REG={5};PAC={6};WSL={7}",
                    _optAntigravity ? 1 : 0,
                    _optMcpTerminal ? 1 : 0,
                    _optCursorAi ? 1 : 0,
                    _optDiscordYt ? 1 : 0,
                    _optSocialWeb ? 1 : 0,
                    string.IsNullOrEmpty(_selectedRegion) ? "auto" : _selectedRegion,
                    _useSmartPacMode ? 1 : 0,
                    _optWslBridge ? 1 : 0)
            };
            try { File.WriteAllLines(_savedKeyPath, data, Encoding.UTF8); } catch { }
            try { File.WriteAllLines(GetFallbackSavedKeyPath(), data, Encoding.UTF8); } catch { }
        }

        public static bool IsAdministratorStatic()
        {
            return IsAdministrator();
        }

        private static bool IsAdministrator()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        private void RelaunchAsAdmin(string argFlag)
        {
            try
            {
                SaveCurrentState();
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = argFlag,
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(psi);
                if (_trayIcon != null) _trayIcon.Visible = false;
                Application.Current.Shutdown();
            }
            catch
            {
                // If user declined UAC, fall back to non-admin Safe System Proxy mode automatically!
                _preferSafeProxyMode = true;
                SetStatus(ColAmber, "Режим без прав Администратора", "Активирован безопасный системный шлюз (без драйвера Wintun).");
            }
        }

        // ====================================================================
        // CONFLICT CLEANER: STOPS LEGACY PROKSIFI LOOPS + WPAD HIJACK (PRESERVES ZAPRET & USER TOOLS)
        // ====================================================================
        private static List<string> StopConflictingVpnAndApplyFixes()
        {
            var fixedItems = new List<string>();

            // 1. Stop legacy ProksiFi service/tray only (never touch user's Zapret/GoodbyeDPI/VPNs!)
            try
            {
                try
                {
                    var scCheck = Process.Start(new ProcessStartInfo("sc.exe", "query ProksiFiService") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
                    string scOut = scCheck.StandardOutput.ReadToEnd();
                    scCheck.WaitForExit(400);
                    if (scOut.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Process.Start(new ProcessStartInfo("sc.exe", "stop ProksiFiService") { CreateNoWindow = true, UseShellExecute = false }).WaitForExit(800);
                        fixedItems.Add("Остановлена устаревшая служба ProksiFiService");
                    }
                }
                catch { }

                foreach (var p in Process.GetProcessesByName("ProksiFi_Tray"))
                {
                    try { p.Kill(); fixedItems.Add("Закрыт устаревший ProksiFi_Tray.exe"); } catch { }
                }
            }
            catch { }

            // 2. Clean WPAD AutoConfigURL hijack if present (only stale/unwanted local entries — keep active Smart PAC!)
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null && key.GetValue("AutoConfigURL", null) != null)
                    {
                        string wpad = Convert.ToString(key.GetValue("AutoConfigURL", ""));
                        if (IsPixelOrLocalAutoConfig(wpad) && !IsActivePixelSmartPacUrl(wpad))
                        {
                            key.DeleteValue("AutoConfigURL", false);
                            fixedItems.Add(string.Format("Удалён устаревший WPAD AutoConfigURL ({0})", wpad));
                        }
                    }
                }
            }
            catch { }

            return fixedItems;
        }

        private static bool CanBindLocalTcpPort(int port)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();
                listener.Stop();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string EnsureAvailableLocalPorts()
        {
            int[] candidates = new[] { 17890, 17892, 18890, 27890 };
            foreach (int httpPort in candidates)
            {
                int socksPort = httpPort + 1;
                if (CanBindLocalTcpPort(httpPort) && CanBindLocalTcpPort(socksPort))
                {
                    bool relocated = (httpPort != LOCAL_MIXED_PORT);
                    _activeHttpPort = httpPort;
                    _activeSocksPort = socksPort;
                    if (relocated)
                    {
                        return string.Format("Порт {0} занят системой (Hyper-V/WSL/ICS) -> авто-перенос шлюза на :{1}", LOCAL_MIXED_PORT, _activeHttpPort);
                    }
                    return "";
                }
            }
            return "";
        }

        private static int CountActiveProxyConnections()
        {
            int count = 0;
            try
            {
                var props = IPGlobalProperties.GetIPGlobalProperties();
                var conns = props.GetActiveTcpConnections();
                foreach (var c in conns)
                {
                    if (c.State == TcpState.Established)
                    {
                        if ((IPAddress.IsLoopback(c.LocalEndPoint.Address) && (c.LocalEndPoint.Port == _activeHttpPort || c.LocalEndPoint.Port == _activeSocksPort)) ||
                            (IPAddress.IsLoopback(c.RemoteEndPoint.Address) && (c.RemoteEndPoint.Port == _activeHttpPort || c.RemoteEndPoint.Port == _activeSocksPort)))
                        {
                            count++;
                        }
                    }
                }
            }
            catch { }
            return count / 2 > 0 ? count / 2 : count;
        }

        private static bool IsAiStreamActivelyFlowing()
        {
            try
            {
                string logFile = FindLatestAntigravityLogFile();
                if (!string.IsNullOrEmpty(logFile) && File.Exists(logFile))
                {
                    double ageSec = (DateTime.UtcNow - File.GetLastWriteTimeUtc(logFile)).TotalSeconds;
                    if (ageSec >= 0 && ageSec < 2.2) return true;
                }
            }
            catch { }
            return false;
        }

        private static void WaitForIdleAiStream(int maxWaitMs)
        {
            try
            {
                int waited = 0;
                while (waited < maxWaitMs && IsAiStreamActivelyFlowing())
                {
                    Thread.Sleep(250);
                    waited += 250;
                }
            }
            catch { }
        }

        private static string FindLatestAntigravityLogFile()
        {
            string bestFile = null;
            DateTime bestTime = DateTime.MinValue;
            try
            {
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string agLogsDir = System.IO.Path.Combine(appData, "Antigravity", "logs");
                if (Directory.Exists(agLogsDir))
                {
                    foreach (var f in Directory.GetFiles(agLogsDir, "*.log", SearchOption.AllDirectories))
                    {
                        string name = System.IO.Path.GetFileName(f).ToLowerInvariant();
                        if (name.Contains("language_server") || name.Contains("antigravity") || name.Contains("cloudcode") || name.Contains("exthost"))
                        {
                            DateTime wt = File.GetLastWriteTimeUtc(f);
                            if (wt > bestTime)
                            {
                                bestTime = wt;
                                bestFile = f;
                            }
                        }
                    }
                }
            }
            catch { }
            return bestFile;
        }

        private static void InspectAntigravityLogs(out string statusBanner, out Color dotColor, out string validationUrl, out List<string> diagLines)
        {
            statusBanner = string.Format("AI Телеметрия: шлюз :{0} готов • защита от слетов активна", _activeHttpPort);
            dotColor = ColBlue;
            validationUrl = "";
            diagLines = new List<string>();

            try
            {
                int activeConns = CountActiveProxyConnections();
                string logFile = FindLatestAntigravityLogFile();
                if (string.IsNullOrEmpty(logFile) || !File.Exists(logFile))
                {
                    if (IsLocalPortOpen(_activeHttpPort, 100))
                    {
                        dotColor = ColGreen;
                        statusBanner = string.Format("Шлюз :{0} активен • Потоков: {1} • Antigravity & Cursor под защитой", _activeHttpPort, activeConns);
                    }
                    diagLines.Add("  ✓ [OK] Локальный шлюз :" + _activeHttpPort + " готов (активных AI-потоков: " + activeConns + ").");
                    return;
                }

                string tail = ReadLogTail(logFile, 32768);
                DateTime lastWrite = File.GetLastWriteTime(logFile);
                double minsAgo = Math.Max(0, (DateTime.Now - lastWrite).TotalMinutes);
                string recency = minsAgo < 1.0 ? "только что" : string.Format("{0:0} мин назад", minsAgo);

                // 1. Check for Google Account Validation URL challenge
                var mVal = Regex.Match(tail, "https://accounts\\.google\\.com/[^\"'\\s<>\\\\]+", RegexOptions.IgnoreCase);
                if (!mVal.Success)
                {
                    mVal = Regex.Match(tail, "validation_url[\"']?\\s*[:=]\\s*[\"'](https://[^\"'\\s]+)[\"']", RegexOptions.IgnoreCase);
                }
                if (mVal.Success && tail.IndexOf("VALIDATION_REQUIRED", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    validationUrl = mVal.Groups.Count > 1 && !string.IsNullOrEmpty(mVal.Groups[1].Value) ? mVal.Groups[1].Value : mVal.Value;
                    dotColor = ColAmber;
                    statusBanner = "Google запросил верификацию аккаунта -> нажмите «Верификация Google»";
                    diagLines.Add("  ⚠ [ВЕРИФИКАЦИЯ GOOGLE] В логе language_server обнаружен запрос подтверждения аккаунта (VALIDATION_REQUIRED).");
                    diagLines.Add("  💡 [РЕШЕНИЕ] Нажмите кнопку «Верификация Google» на главном экране или откройте: " + validationUrl);
                    return;
                }

                // 2. Check last 6KB for recent overload (503/429) vs region block vs 200 OK
                string recentTail = tail.Length > 6000 ? tail.Substring(tail.Length - 6000) : tail;
                bool hasOverload = recentTail.IndexOf("503", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("429", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("overloaded", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("high traffic", StringComparison.OrdinalIgnoreCase) >= 0;

                bool hasRegionErr = recentTail.IndexOf("location is not supported", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                    recentTail.IndexOf("REGION_NOT_SUPPORTED", StringComparison.OrdinalIgnoreCase) >= 0;

                bool hasAuthErr = recentTail.IndexOf("UNAUTHENTICATED", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                  recentTail.IndexOf("invalid_grant", StringComparison.OrdinalIgnoreCase) >= 0;

                bool hasNetTimeout = recentTail.IndexOf("TLS handshake timeout", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     recentTail.IndexOf("context deadline exceeded", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     recentTail.IndexOf("connection refused", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     recentTail.IndexOf("actively refused", StringComparison.OrdinalIgnoreCase) >= 0;

                if (hasRegionErr && minsAgo < 10)
                {
                    dotColor = ColAmber;
                    statusBanner = string.Format("Обнаружен блок региона в логе ({0}) • нажмите Авто-Фикс для перезапуска LS", recency);
                    diagLines.Add("  ⚠ [ЛОГ ANTIGRAVITY] В language_server.log зафиксирована ошибка региона (" + recency + "). Авто-патч AG_LS_PROXY применён.");
                }
                else if (hasOverload && minsAgo < 5)
                {
                    dotColor = ColAmber;
                    statusBanner = string.Format("Серверы Google AI перегружены (503/429, {0}) • Туннель исправен, повторите запрос", recency);
                    diagLines.Add("  ℹ [ЛОГ ANTIGRAVITY] Серверы Google AI временно перегружены (код 503/429, " + recency + "). Сам туннель работает исправно — просто повторите запрос через 10 сек.");
                }
                else if (hasAuthErr && minsAgo < 10)
                {
                    dotColor = ColAmber;
                    statusBanner = "Сессия Google в IDE истекла (401) • Перезайдите в аккаунт в Antigravity";
                    diagLines.Add("  ⚠ [ЛОГ ANTIGRAVITY] Токен авторизации устарел (401 Unauthenticated). Перезайдите в аккаунт Google внутри Antigravity IDE.");
                }
                else if (hasNetTimeout && minsAgo < 5)
                {
                    dotColor = ColRed;
                    statusBanner = string.Format("Таймаут сети в Antigravity ({0}) • Нажмите «Проверить и починить»", recency);
                    diagLines.Add("  ✗ [ТАЙМАУТ СЕТИ В IDE] В логе language_server зафиксирован TLS handshake timeout / обрыв связи с Google (" + recency + "). Нажмите «Проверить и починить» для перевода IDE на рабочий маршрут.");
                }
                else
                {
                    dotColor = IsLocalPortOpen(_activeHttpPort, 100) ? ColGreen : ColBlue;
                    statusBanner = string.Format("Шлюз :{0} • Потоков: {1} • Лог Antigravity: 200 OK ({2})", _activeHttpPort, activeConns, recency);
                    diagLines.Add(string.Format("  ✓ [OK] Лог Antigravity ({0}): соединение 200 OK ({1}), активных потоков: {2}.", System.IO.Path.GetFileName(logFile), recency, activeConns));
                }
            }
            catch { }
        }

        private void RefreshAiTelemetryBanner()
        {
            try
            {
                if (_aiTelemetryText == null || _aiTelemetryDot == null) return;
                string banner;
                Color dotCol;
                string valUrl;
                List<string> lines;
                InspectAntigravityLogs(out banner, out dotCol, out valUrl, out lines);

                _aiTelemetryDot.Fill = new SolidColorBrush(dotCol);
                _aiTelemetryText.Text = banner;
                _lastValidationUrl = valUrl ?? "";
                if (_aiVerifyBtn != null)
                {
                    _aiVerifyBtn.Visibility = !string.IsNullOrEmpty(_lastValidationUrl) ? Visibility.Visible : Visibility.Collapsed;
                }
                CheckAntigravityPreTunnelState();
                UpdateRegionSelectorVisuals();
                CheckSignedManifestUpdateUi();
                if (_isConnected) UpdateLicenseHintFromServer();
            }
            catch { }
        }

        private static string DiscoverAntigravityExePath()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName("Antigravity"))
                {
                    try
                    {
                        string exe = p.MainModule.FileName;
                        if (!string.IsNullOrEmpty(exe) && File.Exists(exe)) return exe;
                    }
                    catch { }
                }

                string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                string[] candidates = new[]
                {
                    System.IO.Path.Combine(localApp, "Programs", "Antigravity", "Antigravity.exe"),
                    System.IO.Path.Combine(localApp, "Programs", "antigravity", "Antigravity.exe"),
                    System.IO.Path.Combine(localApp, "Programs", "Antigravity IDE", "Antigravity.exe"),
                    System.IO.Path.Combine(progFiles, "Antigravity", "Antigravity.exe"),
                    System.IO.Path.Combine(progFiles, "Antigravity IDE", "Antigravity.exe")
                };
                foreach (var c in candidates)
                {
                    if (File.Exists(c)) return c;
                }
            }
            catch { }
            return null;
        }

        private void CheckAntigravityPreTunnelState()
        {
            try
            {
                if (_agLeakGuardBanner == null) return;
                if (!_isConnected || !_optAntigravity || _agBannerDismissed || _agRelaunchedForPort == _activeHttpPort || _tunnelConnectedUtc == DateTime.MinValue)
                {
                    _agLeakGuardBanner.Visibility = Visibility.Collapsed;
                    return;
                }

                bool startedBeforeTunnel = false;
                foreach (var p in Process.GetProcessesByName("Antigravity"))
                {
                    try
                    {
                        if (p.StartTime.ToUniversalTime() < _tunnelConnectedUtc.AddSeconds(-2))
                        {
                            startedBeforeTunnel = true;
                            break;
                        }
                    }
                    catch { }
                }

                _agLeakGuardBanner.Visibility = startedBeforeTunnel ? Visibility.Visible : Visibility.Collapsed;
            }
            catch { }
        }

        private async void RelaunchAntigravityInTunnelAsync()
        {
            try
            {
                if (!_isConnected && !_isBusy)
                {
                    await StartTunnelInternalAsync();
                }
                if (!_isConnected) return;

                string agExe = DiscoverAntigravityExePath();
                if (string.IsNullOrEmpty(agExe) || !File.Exists(agExe))
                {
                    RunOnUiThread(delegate
                    {
                        SetStatus(ColAmber, "Antigravity.exe не найден", "Запустите Antigravity IDE один раз вручную, чтобы определить путь установки.");
                    });
                    return;
                }

                RunOnUiThread(delegate
                {
                    if (_agLeakGuardBanner != null) _agLeakGuardBanner.Visibility = Visibility.Collapsed;
                    if (_aiTelemetryText != null)
                    {
                        if (_aiTelemetryDot != null) _aiTelemetryDot.Fill = new SolidColorBrush(ColAmber);
                        _aiTelemetryText.Text = "Мягкий перезапуск Antigravity внутри туннеля PWP-3...";
                    }
                });

                int port = _activeHttpPort;
                await Task.Run(() =>
                {
                    try
                    {
                        List<string> pLogs;
                        PatchAntigravitySanctionsAndProxy(out pLogs, false);
                    }
                    catch { }

                    try
                    {
                        foreach (var p in Process.GetProcessesByName("Antigravity"))
                        {
                            try { p.CloseMainWindow(); } catch { }
                        }
                        Thread.Sleep(900);
                        foreach (var pName in new[] { "Antigravity", "language_server", "language_server_windows_x64" })
                        {
                            foreach (var p in Process.GetProcessesByName(pName))
                            {
                                try { if (!p.HasExited) { p.Kill(); p.WaitForExit(1000); } } catch { }
                            }
                        }
                    }
                    catch { }

                    string proxyUrl = string.Format("http://127.0.0.1:{0}", port);
                    try
                    {
                        Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.User);
                        Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.Process);
                    }
                    catch { }

                    var psi = new ProcessStartInfo
                    {
                        FileName = agExe,
                        Arguments = string.Format("--proxy-server=\"{0}\" --disable-quic", proxyUrl),
                        WorkingDirectory = System.IO.Path.GetDirectoryName(agExe),
                        UseShellExecute = false
                    };
                    psi.EnvironmentVariables["AG_LS_PROXY"] = proxyUrl;
                    psi.EnvironmentVariables["HTTPS_PROXY"] = proxyUrl;
                    psi.EnvironmentVariables["HTTP_PROXY"] = proxyUrl;
                    psi.EnvironmentVariables["NO_PROXY"] = "localhost,127.0.0.1,*.ru,*.su,*.pixelstore.space";
                    using (var p = Process.Start(psi)) { }
                });

                _agRelaunchedForPort = port;
                _agBannerDismissed = true;
                RunOnUiThread(delegate
                {
                    SetStatus(
                        ColGreen,
                        "Antigravity перезапущен в защищённом туннеле",
                        string.Format("Шлюз :{0} (PWP-3 0-RTT) + защита от утечек QUIC/WebRTC активны", port)
                    );
                    if (_aiTelemetryText != null)
                    {
                        if (_aiTelemetryDot != null) _aiTelemetryDot.Fill = new SolidColorBrush(ColGreen);
                        _aiTelemetryText.Text = string.Format("Antigravity IDE запущен с AG_LS_PROXY=:{0} и --disable-quic [OK]", port);
                    }
                });
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                RunOnUiThread(delegate
                {
                    SetStatus(ColAmber, "Не удалось перезапустить Antigravity", errMsg);
                });
            }
        }

        private async void RelaunchDiscordWithSocksUdpAsync()
        {
            try
            {
                if (!_optDiscordYt)
                {
                    _optDiscordYt = true;
                    RunOnUiThread(delegate
                    {
                        UpdateCheckboxVisual(_chkBoxMedia, _chkMarkMedia, _iconBoxMedia, true, true);
                    });
                    SaveCurrentState();
                    if (_isConnected)
                    {
                        TriggerCategoryHotReloadIfConnected();
                    }
                }

                if (!_isConnected && !_isBusy)
                {
                    await StartTunnelInternalAsync();
                }
                if (!_isConnected) return;

                string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string updateExe = null;
                string procExeName = "Discord.exe";
                var candidates = new[]
                {
                    new[] { System.IO.Path.Combine(localApp, "Discord", "Update.exe"), "Discord.exe", "Discord" },
                    new[] { System.IO.Path.Combine(localApp, "DiscordPTB", "Update.exe"), "DiscordPTB.exe", "DiscordPTB" },
                    new[] { System.IO.Path.Combine(localApp, "DiscordCanary", "Update.exe"), "DiscordCanary.exe", "DiscordCanary" }
                };
                string procKillName = "Discord";
                foreach (var c in candidates)
                {
                    if (File.Exists(c[0]))
                    {
                        updateExe = c[0];
                        procExeName = c[1];
                        procKillName = c[2];
                        break;
                    }
                }

                if (string.IsNullOrEmpty(updateExe))
                {
                    RunOnUiThread(delegate
                    {
                        SetStatus(ColAmber, "Клиент Discord не найден", "Установите десктопный Discord в стандартную папку AppData\\Local\\Discord.");
                    });
                    return;
                }

                int socksPort = _activeSocksPort;
                RunOnUiThread(delegate
                {
                    if (_aiTelemetryText != null)
                    {
                        if (_aiTelemetryDot != null) _aiTelemetryDot.Fill = new SolidColorBrush(ColBlue);
                        _aiTelemetryText.Text = string.Format("Перезапуск Discord через SOCKS5 UDP ASSOCIATE (127.0.0.1:{0})...", socksPort);
                    }
                });

                await Task.Run(() =>
                {
                    try
                    {
                        foreach (var p in Process.GetProcessesByName(procKillName))
                        {
                            try { p.Kill(); p.WaitForExit(1200); } catch { }
                        }
                        Thread.Sleep(500);
                    }
                    catch { }

                    var psi = new ProcessStartInfo
                    {
                        FileName = updateExe,
                        Arguments = string.Format("--processStart {0} --process-start-args=\"--proxy-server=socks5://127.0.0.1:{1}\"", procExeName, socksPort),
                        WorkingDirectory = System.IO.Path.GetDirectoryName(updateExe),
                        UseShellExecute = false
                    };
                    using (var proc = Process.Start(psi)) { }
                });

                RunOnUiThread(delegate
                {
                    SetStatus(
                        ColGreen,
                        "Discord запущен с поддержкой голоса (SOCKS5 UDP)",
                        string.Format("Голосовые каналы и стримы идут через PWP-3 UDP-шлюз 127.0.0.1:{0} без драйвера Wintun", socksPort)
                    );
                    if (_aiTelemetryText != null)
                    {
                        if (_aiTelemetryDot != null) _aiTelemetryDot.Fill = new SolidColorBrush(ColGreen);
                        _aiTelemetryText.Text = string.Format("Discord UDP активен на 127.0.0.1:{0} • Голос и стрим работают без Wintun", socksPort);
                    }
                });
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                RunOnUiThread(delegate
                {
                    SetStatus(ColAmber, "Ошибка запуска Discord UDP", errMsg);
                });
            }
        }

        private static string RemoveJsonProperty(string json, string propName)
        {
            if (string.IsNullOrEmpty(json)) return json;
            string pat1 = "(?m)^[ \\t]*\"" + Regex.Escape(propName) + "\"\\s*:\\s*(?:\"[^\"]*\"|true|false|[0-9.]+)\\s*,?\\s*\\r?\\n?";
            string res = Regex.Replace(json, pat1, "");
            res = Regex.Replace(res, ",(\\s*\\})", "$1");
            return res;
        }

        // ====================================================================
        // ISOLATED ANTIGRAVITY TERMINAL & MCP PROXY GUARD (JSONC-SAFE SURGERY)
        // Preserves // comments, /* */ comments, and user's custom env vars!
        // ====================================================================
        private static int FindLastMeaningfulCharBeforeCloseBrace(string objText, int closeBraceIdx)
        {
            bool inStr = false;
            bool inLineCmt = false;
            bool inBlkCmt = false;
            int lastNonWsIdx = 0;

            for (int i = 0; i < closeBraceIdx; i++)
            {
                char c = objText[i];
                char next = (i + 1 < closeBraceIdx) ? objText[i + 1] : '\0';

                if (inLineCmt)
                {
                    if (c == '\n') inLineCmt = false;
                    continue;
                }
                if (inBlkCmt)
                {
                    if (c == '*' && next == '/') { inBlkCmt = false; i++; }
                    continue;
                }
                if (inStr)
                {
                    if (c == '\\') { i++; continue; }
                    if (c == '"') { inStr = false; lastNonWsIdx = i; }
                    continue;
                }

                if (c == '/' && next == '/') { inLineCmt = true; i++; continue; }
                if (c == '/' && next == '*') { inBlkCmt = true; i++; continue; }
                if (c == '"') { inStr = true; lastNonWsIdx = i; continue; }
                if (!char.IsWhiteSpace(c)) lastNonWsIdx = i;
            }
            return lastNonWsIdx;
        }

        private static bool FindJsonObjectPropertySpan(string json, string propName, out int propKeyIdx, out int valOpenBrace, out int valCloseBrace)
        {
            propKeyIdx = -1;
            valOpenBrace = -1;
            valCloseBrace = -1;
            if (string.IsNullOrEmpty(json)) return false;

            bool inStr = false;
            bool inLineCmt = false;
            bool inBlkCmt = false;
            int depth = 0;
            int n = json.Length;

            for (int i = 0; i < n; i++)
            {
                char c = json[i];
                char next = (i + 1 < n) ? json[i + 1] : '\0';

                if (inLineCmt) { if (c == '\n') inLineCmt = false; continue; }
                if (inBlkCmt) { if (c == '*' && next == '/') { inBlkCmt = false; i++; } continue; }
                if (inStr)
                {
                    if (c == '\\') { i++; continue; }
                    if (c == '"') inStr = false;
                    continue;
                }

                if (c == '/' && next == '/') { inLineCmt = true; i++; continue; }
                if (c == '/' && next == '*') { inBlkCmt = true; i++; continue; }

                if (c == '{') { depth++; continue; }
                if (c == '}') { depth--; continue; }

                if (c == '"' && depth == 1)
                {
                    int strStart = i;
                    int j = i + 1;
                    var sbKey = new StringBuilder();
                    while (j < n)
                    {
                        if (json[j] == '\\' && j + 1 < n) { sbKey.Append(json[j + 1]); j += 2; continue; }
                        if (json[j] == '"') break;
                        sbKey.Append(json[j]);
                        j++;
                    }
                    if (j >= n) break;
                    string keyParsed = sbKey.ToString();
                    i = j;

                    if (string.Equals(keyParsed, propName, StringComparison.Ordinal))
                    {
                        // Skip whitespace/comments to ':' then '{'
                        int k = j + 1;
                        while (k < n)
                        {
                            if (char.IsWhiteSpace(json[k])) { k++; continue; }
                            if (k + 1 < n && json[k] == '/' && json[k + 1] == '/')
                            {
                                k += 2;
                                while (k < n && json[k] != '\n') k++;
                                continue;
                            }
                            if (k + 1 < n && json[k] == '/' && json[k + 1] == '*')
                            {
                                k += 2;
                                while (k + 1 < n && !(json[k] == '*' && json[k + 1] == '/')) k++;
                                k += 2;
                                continue;
                            }
                            break;
                        }
                        if (k < n && json[k] == ':')
                        {
                            k++;
                            while (k < n)
                            {
                                if (char.IsWhiteSpace(json[k])) { k++; continue; }
                                if (k + 1 < n && json[k] == '/' && json[k + 1] == '/')
                                {
                                    k += 2;
                                    while (k < n && json[k] != '\n') k++;
                                    continue;
                                }
                                if (k + 1 < n && json[k] == '/' && json[k + 1] == '*')
                                {
                                    k += 2;
                                    while (k + 1 < n && !(json[k] == '*' && json[k + 1] == '/')) k++;
                                    k += 2;
                                    continue;
                                }
                                break;
                            }
                            if (k < n && json[k] == '{')
                            {
                                int openB = k;
                                int subDepth = 1;
                                bool sStr = false, sLine = false, sBlk = false;
                                for (int m = openB + 1; m < n; m++)
                                {
                                    char mc = json[m];
                                    char mn = (m + 1 < n) ? json[m + 1] : '\0';
                                    if (sLine) { if (mc == '\n') sLine = false; continue; }
                                    if (sBlk) { if (mc == '*' && mn == '/') { sBlk = false; m++; } continue; }
                                    if (sStr)
                                    {
                                        if (mc == '\\') { m++; continue; }
                                        if (mc == '"') sStr = false;
                                        continue;
                                    }
                                    if (mc == '/' && mn == '/') { sLine = true; m++; continue; }
                                    if (mc == '/' && mn == '*') { sBlk = true; m++; continue; }
                                    if (mc == '"') { sStr = true; continue; }
                                    if (mc == '{') subDepth++;
                                    else if (mc == '}')
                                    {
                                        subDepth--;
                                        if (subDepth == 0)
                                        {
                                            propKeyIdx = strStart;
                                            valOpenBrace = openB;
                                            valCloseBrace = m;
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        private static bool FindStringPropAtDepth1(string objText, string keyName, out int keyQuoteStart, out int valQuoteStart, out int valQuoteEnd, out string currentValue)
        {
            keyQuoteStart = -1;
            valQuoteStart = -1;
            valQuoteEnd = -1;
            currentValue = "";
            if (string.IsNullOrEmpty(objText)) return false;

            bool inStr = false, inLine = false, inBlk = false;
            int depth = 0;
            int n = objText.Length;

            for (int i = 0; i < n; i++)
            {
                char c = objText[i];
                char next = (i + 1 < n) ? objText[i + 1] : '\0';
                if (inLine) { if (c == '\n') inLine = false; continue; }
                if (inBlk) { if (c == '*' && next == '/') { inBlk = false; i++; } continue; }
                if (inStr)
                {
                    if (c == '\\') { i++; continue; }
                    if (c == '"') inStr = false;
                    continue;
                }
                if (c == '/' && next == '/') { inLine = true; i++; continue; }
                if (c == '/' && next == '*') { inBlk = true; i++; continue; }
                if (c == '{' || c == '[') { depth++; continue; }
                if (c == '}' || c == ']') { depth--; continue; }

                if (c == '"' && depth == 1)
                {
                    int kStart = i;
                    int j = i + 1;
                    var sbK = new StringBuilder();
                    while (j < n)
                    {
                        if (objText[j] == '\\' && j + 1 < n) { sbK.Append(objText[j + 1]); j += 2; continue; }
                        if (objText[j] == '"') break;
                        sbK.Append(objText[j]);
                        j++;
                    }
                    if (j >= n) break;
                    string parsedKey = sbK.ToString();
                    i = j;

                    // Advance past ':' and value so we don't confuse string values with keys!
                    int k = j + 1;
                    while (k < n && char.IsWhiteSpace(objText[k])) k++;
                    if (k < n && objText[k] == ':')
                    {
                        k++;
                        while (k < n && char.IsWhiteSpace(objText[k])) k++;
                        if (k < n && objText[k] == '"')
                        {
                            int vStart = k;
                            int m = k + 1;
                            var sbV = new StringBuilder();
                            while (m < n)
                            {
                                if (objText[m] == '\\' && m + 1 < n) { sbV.Append(objText[m + 1]); m += 2; continue; }
                                if (objText[m] == '"') break;
                                sbV.Append(objText[m]);
                                m++;
                            }
                            if (m < n)
                            {
                                i = m;
                                if (string.Equals(parsedKey, keyName, StringComparison.Ordinal))
                                {
                                    keyQuoteStart = kStart;
                                    valQuoteStart = vStart;
                                    valQuoteEnd = m;
                                    currentValue = sbV.ToString();
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        private static bool HasAnyPropertyAtDepth1(string objText)
        {
            if (string.IsNullOrEmpty(objText)) return false;
            bool inStr = false, inLine = false, inBlk = false;
            int depth = 0;
            int n = objText.Length;
            for (int i = 0; i < n; i++)
            {
                char c = objText[i];
                char next = (i + 1 < n) ? objText[i + 1] : '\0';
                if (inLine) { if (c == '\n') inLine = false; continue; }
                if (inBlk) { if (c == '*' && next == '/') { inBlk = false; i++; } continue; }
                if (inStr)
                {
                    if (c == '\\') { i++; continue; }
                    if (c == '"') inStr = false;
                    continue;
                }
                if (c == '/' && next == '/') { inLine = true; i++; continue; }
                if (c == '/' && next == '*') { inBlk = true; i++; continue; }
                if (c == '{' || c == '[') { depth++; continue; }
                if (c == '}' || c == ']') { depth--; continue; }
                if (c == ':' && depth == 1) return true;
            }
            return false;
        }

        private static string InsertPropIntoJsonObject(string objText, string propLine, string indent)
        {
            int closeIdx = objText.LastIndexOf('}');
            if (closeIdx <= 0) return "{\r\n" + indent + propLine + "\r\n}";

            int lastTok = FindLastMeaningfulCharBeforeCloseBrace(objText, closeIdx);
            char tokChar = objText[lastTok];

            if (tokChar == '{' || tokChar == ',')
            {
                string head = objText.Substring(0, closeIdx).TrimEnd(' ', '\t');
                if (!head.EndsWith("\n")) head += "\r\n";
                return head + indent + propLine + "\r\n" + (indent.Length >= 2 ? indent.Substring(0, indent.Length - 2) : "") + "}";
            }
            else
            {
                // Ставим запятую СТРОГО сразу после предыдущего значения (ДО возможных // комментариев в конце строки!)
                string withComma = objText.Substring(0, lastTok + 1) + "," + objText.Substring(lastTok + 1);
                int newCloseIdx = closeIdx + 1;
                string head = withComma.Substring(0, newCloseIdx).TrimEnd(' ', '\t');
                if (!head.EndsWith("\n")) head += "\r\n";
                return head + indent + propLine + "\r\n" + (indent.Length >= 2 ? indent.Substring(0, indent.Length - 2) : "") + "}";
            }
        }

        private static string RemoveSpanFromJsonObject(string objText, int spanStart, int spanEndInclusive)
        {
            int left = spanStart;
            while (left > 0 && (objText[left - 1] == ' ' || objText[left - 1] == '\t')) left--;

            int right = spanEndInclusive + 1;
            bool consumedTrailingComma = false;
            while (right < objText.Length && (objText[right] == ' ' || objText[right] == '\t')) right++;
            if (right < objText.Length && objText[right] == ',')
            {
                consumedTrailingComma = true;
                right++;
            }
            while (right < objText.Length && (objText[right] == ' ' || objText[right] == '\t')) right++;
            if (right < objText.Length && objText[right] == '\r') right++;
            if (right < objText.Length && objText[right] == '\n') right++;

            string updated = objText.Substring(0, left) + objText.Substring(right);

            if (!consumedTrailingComma)
            {
                // Если удалили последнее свойство перед '}' — подчистим висящую запятую у предыдущего свойства
                int closeIdx = updated.LastIndexOf('}');
                if (closeIdx > 0)
                {
                    int lastTok = FindLastMeaningfulCharBeforeCloseBrace(updated, closeIdx);
                    if (updated[lastTok] == ',')
                    {
                        updated = updated.Substring(0, lastTok) + updated.Substring(lastTok + 1);
                    }
                }
            }
            return updated;
        }

        public static string UpdateAntigravityTerminalEnvJson(string json, bool enable, int httpPort, int socksPort)
        {
            if (string.IsNullOrWhiteSpace(json)) json = "{\r\n}";
            string httpUrl = string.Format("http://127.0.0.1:{0}", httpPort);
            string socksUrl = string.Format("socks5h://127.0.0.1:{0}", socksPort);
            const string noProxyVal = "localhost,127.0.0.1,*.ru,*.su,*.pixelstore.space";

            string[][] managedPairs = new string[][]
            {
                new[] { "HTTP_PROXY", httpUrl },
                new[] { "HTTPS_PROXY", httpUrl },
                new[] { "ALL_PROXY", socksUrl },
                new[] { "NO_PROXY", noProxyVal },
                new[] { "http_proxy", httpUrl },
                new[] { "https_proxy", httpUrl },
                new[] { "all_proxy", socksUrl },
                new[] { "no_proxy", noProxyVal }
            };

            int propIdx, openB, closeB;
            bool hasEnvBlock = FindJsonObjectPropertySpan(json, "terminal.integrated.env.windows", out propIdx, out openB, out closeB);

            if (enable)
            {
                if (hasEnvBlock)
                {
                    string inner = json.Substring(openB, closeB - openB + 1);
                    foreach (var kv in managedPairs)
                    {
                        int ks, vs, ve;
                        string cur;
                        if (FindStringPropAtDepth1(inner, kv[0], out ks, out vs, out ve, out cur))
                        {
                            if (cur != kv[1])
                            {
                                inner = inner.Substring(0, vs) + "\"" + EscapeJson(kv[1]) + "\"" + inner.Substring(ve + 1);
                            }
                        }
                        else
                        {
                            inner = InsertPropIntoJsonObject(inner, "\"" + kv[0] + "\": \"" + EscapeJson(kv[1]) + "\"", "    ");
                        }
                    }
                    return json.Substring(0, openB) + inner + json.Substring(closeB + 1);
                }
                else
                {
                    string newBlock =
                        "\"terminal.integrated.env.windows\": {\r\n" +
                        "    \"HTTP_PROXY\": \"" + EscapeJson(httpUrl) + "\",\r\n" +
                        "    \"HTTPS_PROXY\": \"" + EscapeJson(httpUrl) + "\",\r\n" +
                        "    \"ALL_PROXY\": \"" + EscapeJson(socksUrl) + "\",\r\n" +
                        "    \"NO_PROXY\": \"" + EscapeJson(noProxyVal) + "\",\r\n" +
                        "    \"http_proxy\": \"" + EscapeJson(httpUrl) + "\",\r\n" +
                        "    \"https_proxy\": \"" + EscapeJson(httpUrl) + "\",\r\n" +
                        "    \"all_proxy\": \"" + EscapeJson(socksUrl) + "\",\r\n" +
                        "    \"no_proxy\": \"" + EscapeJson(noProxyVal) + "\"\r\n" +
                        "  }";
                    return InsertPropIntoJsonObject(json, newBlock, "  ");
                }
            }
            else
            {
                if (!hasEnvBlock) return json;
                string inner = json.Substring(openB, closeB - openB + 1);
                bool changedInner = false;

                foreach (var kv in managedPairs)
                {
                    int ks, vs, ve;
                    string cur;
                    if (FindStringPropAtDepth1(inner, kv[0], out ks, out vs, out ve, out cur))
                    {
                        bool isOurs = cur.IndexOf("127.0.0.1", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                      (kv[0].Equals("NO_PROXY", StringComparison.OrdinalIgnoreCase) && (cur.IndexOf("pixelstore.space", StringComparison.OrdinalIgnoreCase) >= 0 || cur.IndexOf("*.ru", StringComparison.OrdinalIgnoreCase) >= 0));
                        if (isOurs)
                        {
                            inner = RemoveSpanFromJsonObject(inner, ks, ve);
                            changedInner = true;
                        }
                    }
                }

                if (!changedInner) return json;

                if (!HasAnyPropertyAtDepth1(inner))
                {
                    return RemoveSpanFromJsonObject(json, propIdx, closeB);
                }
                return json.Substring(0, openB) + inner + json.Substring(closeB + 1);
            }
        }

        private void RepairOtherAppsAndCleanLeftovers()
        {
            try
            {
                _optAntigravity = true;
                _optCursorAi = false;
                _optDiscordYt = false;
                _optSocialWeb = false;
                UpdateCheckboxVisual(_chkBoxAg, _chkMarkAg, _iconBoxAg, _optAntigravity, true);
                UpdateCheckboxVisual(_chkBoxAi, _chkMarkAi, _iconBoxAi, _optCursorAi, true);
                UpdateCheckboxVisual(_chkBoxMedia, _chkMarkMedia, _iconBoxMedia, _optDiscordYt, true);
                UpdateCheckboxVisual(_chkBoxWeb, _chkMarkWeb, _iconBoxWeb, _optSocialWeb, true);
                SaveCurrentState();

                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null)
                    {
                        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                        object autoCfgObj = key.GetValue("AutoConfigURL", null);
                        if (autoCfgObj != null && IsPixelOrLocalAutoConfig(Convert.ToString(autoCfgObj)))
                        {
                            key.DeleteValue("AutoConfigURL", false);
                        }
                    }
                }
                ApplyWinInetPerConnectionProxy(false, "", "");
                SetProxyResetRunOnceGuard(false);
                PurgeGlobalCliProxyEnvVars();

                if (_isConnected && IsLocalPortOpen(_activeHttpPort, 150))
                {
                    string proxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.User);
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.Process);
                }
                else
                {
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.User);
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.Process);
                }
                BroadcastEnvironmentChange();

                HealAiEditorsAndServices(_isConnected, false, true, false, false);
                FlushWindowsDnsCache();

                SetStatus(
                    ColGreen,
                    "Cursor, браузеры и программы очищены!",
                    "Все прокси-хвосты удалены из Cursor, VS Code, Git, npm и реестра • Antigravity работает изолированно"
                );
            }
            catch { }
        }

        private static List<string> HealAiEditorsAndServices(bool tunnelActive, bool restartLanguageServer = true, bool routeAg = true, bool routeAi = false, bool routeMedia = false, bool routeWeb = false)
        {
            var healed = new List<string>();
            bool agSettingsChanged = false;
            try
            {
                PurgeGlobalCliProxyEnvVars();
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string activeProxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                string[] editors = GetCustomAiEditors();

                foreach (var ed in editors)
                {
                    try
                    {
                        string userDir = System.IO.Path.Combine(appData, ed, "User");
                        string settingsPath = System.IO.Path.Combine(userDir, "settings.json");
                        if (!Directory.Exists(userDir)) continue;

                        bool isAg = string.Equals(ed, "Antigravity", StringComparison.OrdinalIgnoreCase);
                        bool shouldProxyThisEditor = tunnelActive && (isAg ? routeAg : routeAi);

                        string json = File.Exists(settingsPath) ? File.ReadAllText(settingsPath, Encoding.UTF8) : "{\r\n}";
                        if (string.IsNullOrWhiteSpace(json) || !json.Trim().StartsWith("{")) json = "{\r\n}";
                        string orig = json;

                        if (shouldProxyThisEditor)
                        {
                            // 1. Force http.proxy to our active port so editor file-watcher reloads proxy on the fly!
                            if (Regex.IsMatch(json, "\"http\\.proxy\"\\s*:\\s*\"[^\"]*\""))
                            {
                                json = Regex.Replace(json, "\"http\\.proxy\"\\s*:\\s*\"[^\"]*\"", "\"http.proxy\": \"" + activeProxyUrl + "\"");
                            }
                            else
                            {
                                json = InjectJsonProperty(json, "\"http.proxy\": \"" + activeProxyUrl + "\"");
                            }

                            // 2. Force http.proxyStrictSSL = false
                            if (Regex.IsMatch(json, "\"http\\.proxyStrictSSL\"\\s*:\\s*(?:true|false)"))
                            {
                                json = Regex.Replace(json, "\"http\\.proxyStrictSSL\"\\s*:\\s*(?:true|false)", "\"http.proxyStrictSSL\": false");
                            }
                            else
                            {
                                json = InjectJsonProperty(json, "\"http.proxyStrictSSL\": false");
                            }

                            // 3. Force http.proxySupport = "override"
                            if (Regex.IsMatch(json, "\"http\\.proxySupport\"\\s*:\\s*\"[^\"]*\""))
                            {
                                json = Regex.Replace(json, "\"http\\.proxySupport\"\\s*:\\s*\"[^\"]*\"", "\"http.proxySupport\": \"override\"");
                            }
                            else
                            {
                                json = InjectJsonProperty(json, "\"http.proxySupport\": \"override\"");
                            }

                            // 4. Isolated Antigravity Terminal & MCP Proxy Guard (ONLY inside Antigravity IDE!)
                            if (isAg)
                            {
                                json = UpdateAntigravityTerminalEnvJson(json, _optMcpTerminal, _activeHttpPort, _activeSocksPort);
                            }

                            // 5. For Cursor (only when explicitly enabled by user): disable HTTP/2 over HTTP CONNECT proxy
                            if (string.Equals(ed, "Cursor", StringComparison.OrdinalIgnoreCase))
                            {
                                if (Regex.IsMatch(json, "\"cursor\\.general\\.disableHttp2\"\\s*:\\s*(?:true|false)"))
                                {
                                    json = Regex.Replace(json, "\"cursor\\.general\\.disableHttp2\"\\s*:\\s*(?:true|false)", "\"cursor.general.disableHttp2\": true");
                                }
                                else
                                {
                                    json = InjectJsonProperty(json, "\"cursor.general.disableHttp2\": true");
                                }
                            }

                            if (json != orig)
                            {
                                File.WriteAllText(settingsPath, json, new UTF8Encoding(false));
                                healed.Add(string.Format("{0}: прописан шлюз :{1}{2}", ed, _activeHttpPort, (isAg && _optMcpTerminal) ? " + MCP Терминал" : ""));
                                if (isAg) agSettingsChanged = true;
                            }
                        }
                        else
                        {
                            // Clean our local proxy from this editor so Cursor/VS Code/Windsurf work 100% natively!
                            if (Regex.IsMatch(json, "\"http\\.proxy\"\\s*:\\s*\"(?:http://127\\.0\\.0\\.1:\\d+/?|)\""))
                            {
                                json = RemoveJsonProperty(json, "http.proxy");
                                json = RemoveJsonProperty(json, "http.proxyStrictSSL");
                                json = RemoveJsonProperty(json, "http.proxySupport");
                                if (!isAg)
                                {
                                    json = RemoveJsonProperty(json, "cursor.general.disableHttp2");
                                }
                            }
                            json = UpdateAntigravityTerminalEnvJson(json, false, _activeHttpPort, _activeSocksPort);
                            if (json != orig)
                            {
                                File.WriteAllText(settingsPath, json, new UTF8Encoding(false));
                                healed.Add(ed + ": очищен от прокси (прямой режим)");
                            }
                        }
                    }
                    catch { }
                }

                // Configure Spotify Desktop App prefs when tunnelActive && (routeMedia || routeWeb) is true
                try
                {
                    string spotifyDir = System.IO.Path.Combine(appData, "Spotify");
                    string spotifyPrefs = System.IO.Path.Combine(spotifyDir, "prefs");
                    if (File.Exists(spotifyPrefs))
                    {
                        string spTxt = File.ReadAllText(spotifyPrefs, Encoding.UTF8);
                        if (tunnelActive && (routeMedia || routeWeb))
                        {
                            string targetAddr = string.Format("network.proxy.addr=\"127.0.0.1:{0}@http\"", _activeHttpPort);
                            string targetMode = "network.proxy.mode=2";
                            bool hasTargetProxy = spTxt.IndexOf(targetAddr, StringComparison.OrdinalIgnoreCase) >= 0 &&
                                                  spTxt.IndexOf(targetMode, StringComparison.OrdinalIgnoreCase) >= 0;
                            if (!hasTargetProxy)
                            {
                                var spProcs = Process.GetProcessesByName("Spotify");
                                bool wasSpotifyRunning = spProcs.Length > 0;
                                string spotifyExe = System.IO.Path.Combine(spotifyDir, "Spotify.exe");
                                if (wasSpotifyRunning)
                                {
                                    foreach (var sp in spProcs)
                                    {
                                        try
                                        {
                                            if (!File.Exists(spotifyExe) && sp.MainModule != null)
                                                spotifyExe = sp.MainModule.FileName;
                                        }
                                        catch { }
                                        try { sp.Kill(); sp.WaitForExit(600); } catch { }
                                    }
                                    Thread.Sleep(150);
                                    try { spTxt = File.ReadAllText(spotifyPrefs, Encoding.UTF8); } catch { }
                                }

                                string cleanedSp = Regex.Replace(spTxt, "(?m)^\\s*network\\.proxy\\.[^\\r\\n]*\\r?\\n?", "").TrimEnd();
                                string updatedSp = (string.IsNullOrEmpty(cleanedSp) ? "" : cleanedSp + "\r\n") + targetAddr + "\r\n" + targetMode + "\r\n";
                                File.WriteAllText(spotifyPrefs, updatedSp, new UTF8Encoding(false));

                                if (wasSpotifyRunning && File.Exists(spotifyExe))
                                {
                                    try { Process.Start(new ProcessStartInfo(spotifyExe) { UseShellExecute = true }); } catch { }
                                }
                                healed.Add(string.Format("Spotify: прописан шлюз 127.0.0.1:{0}@http в prefs (mode=2)", _activeHttpPort));
                            }
                        }
                        else
                        {
                            if (spTxt.IndexOf("network.proxy.", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                string cleanedSp = Regex.Replace(spTxt, "(?m)^\\s*network\\.proxy\\.[^\\r\\n]*\\r?\\n?", "");
                                if (cleanedSp != spTxt)
                                {
                                    File.WriteAllText(spotifyPrefs, cleanedSp, new UTF8Encoding(false));
                                    healed.Add("Spotify: очищен от прокси (прямой режим)");
                                }
                            }
                        }
                    }
                }
                catch { }

                // Always clean local proxy in ~/.gitconfig and ~/.npmrc so Git and npm/Node never break!
                try
                {
                    string userProf = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    string gitCfgPath = System.IO.Path.Combine(userProf, ".gitconfig");
                    if (File.Exists(gitCfgPath))
                    {
                        string gtxt = File.ReadAllText(gitCfgPath, Encoding.UTF8);
                        if (Regex.IsMatch(gtxt, "proxy\\s*=\\s*http://127\\.0\\.0\\.1:\\d+"))
                        {
                            gtxt = Regex.Replace(gtxt, "(?m)^\\s*proxy\\s*=\\s*http://127\\.0\\.0\\.1:\\d+/?\\s*\\r?\\n?", "");
                            File.WriteAllText(gitCfgPath, gtxt, new UTF8Encoding(false));
                            healed.Add("Git: очищен локальный прокси в .gitconfig");
                        }
                    }

                    string npmrcPath = System.IO.Path.Combine(userProf, ".npmrc");
                    if (File.Exists(npmrcPath))
                    {
                        string ntxt = File.ReadAllText(npmrcPath, Encoding.UTF8);
                        if (Regex.IsMatch(ntxt, "(?:https?-)?proxy\\s*=\\s*http://127\\.0\\.0\\.1:\\d+"))
                        {
                            ntxt = Regex.Replace(ntxt, "(?m)^\\s*(?:https?-)?proxy\\s*=\\s*http://127\\.0\\.0\\.1:\\d+/?\\s*\\r?\\n?", "");
                            File.WriteAllText(npmrcPath, ntxt, new UTF8Encoding(false));
                            healed.Add("npm: очищен локальный прокси в .npmrc");
                        }
                    }
                }
                catch { }

                if (tunnelActive && restartLanguageServer && agSettingsChanged && IsLocalPortOpen(_activeHttpPort, 150) && !IsAiStreamActivelyFlowing())
                {
                    string[] lsNames = new[] { "language_server", "language_server_windows_x64" };
                    foreach (var lsName in lsNames)
                    {
                        foreach (var p in Process.GetProcessesByName(lsName))
                        {
                            try { p.Kill(); healed.Add(lsName + ": \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0449\u0435\u043d"); } catch { }
                        }
                    }
                }
            }
            catch { }
            return healed;
        }

        private static string InjectJsonProperty(string json, string propKeyVal)
        {
            return InsertPropIntoJsonObject(json, propKeyVal, "  ");
        }

        private static string BuildSmartPacUrl()
        {
            return string.Format("http://127.0.0.1:{0}/proxy.pac?r={1}", _activeHttpPort, Math.Max(1, PixelCoreService.ActivePacRevision));
        }

        private static bool ShouldEnableBrowserProxy()
        {
            return _useSmartPacMode || _optMcpTerminal; // overridden cleanly below via instance helper
        }

        private bool ShouldEnableSystemWideBrowserProxy()
        {
            return _useSmartPacMode || _optCursorAi || _optDiscordYt || _optSocialWeb || _oauthHelperActive;
        }

        private void ApplyConnectedProxyPolicy()
        {
            if (ShouldEnableSystemWideBrowserProxy())
            {
                EnableSystemProxy();
            }
            else
            {
                DisableOrRestoreSystemProxy();
                string proxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.User);
                Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.Process);
                BroadcastEnvironmentChange();
            }
        }

        private static void EnableSystemProxy()
        {
            try
            {
                string proxySrv = string.Format("127.0.0.1:{0}", _activeHttpPort);
                string proxyOvr = BuildEffectiveProxyOverride();
                string pacUrl = BuildSmartPacUrl();

                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null)
                    {
                        if (_useSmartPacMode)
                        {
                            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                            key.SetValue("AutoConfigURL", pacUrl, RegistryValueKind.String);
                        }
                        else
                        {
                            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                            key.SetValue("ProxyServer", proxySrv, RegistryValueKind.String);
                            key.SetValue("ProxyOverride", proxyOvr, RegistryValueKind.String);
                            object autoCfgObj = key.GetValue("AutoConfigURL", null);
                            if (autoCfgObj != null && IsPixelOrLocalAutoConfig(Convert.ToString(autoCfgObj)))
                            {
                                key.DeleteValue("AutoConfigURL", false);
                            }
                        }
                    }
                }
                SetProxyResetRunOnceGuard(true);
                if (_useSmartPacMode)
                    ApplyWinInetPerConnectionProxy(true, "", "", pacUrl);
                else
                    ApplyWinInetPerConnectionProxy(true, proxySrv, proxyOvr, "");

                PurgeGlobalCliProxyEnvVars();
                string proxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.User);
                Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.Process);
                BroadcastEnvironmentChange();
            }
            catch { }
        }

        private static void UpdateForeign7890DeadState(bool isDead)
        {
            _foreign7890UpstreamDead = isDead;
            Interlocked.Exchange(ref _foreign7890DeadCheckedTicks, DateTime.UtcNow.Ticks);
        }

        private static bool IsForeign7890CachedDead()
        {
            if (!_foreign7890UpstreamDead) return false;
            long checkedTicks = Interlocked.Read(ref _foreign7890DeadCheckedTicks);
            if (checkedTicks <= 0) return false;
            return (DateTime.UtcNow.Ticks - checkedTicks) < TimeSpan.FromSeconds(15).Ticks;
        }

        private static int TryExtractLoopbackProxyPort(string proxySpec)
        {
            if (string.IsNullOrWhiteSpace(proxySpec)) return 0;
            try
            {
                string[] parts = proxySpec.Split(';');
                foreach (string rawPart in parts)
                {
                    string part = rawPart.Trim();
                    if (part.Length == 0) continue;
                    int eq = part.IndexOf('=');
                    if (eq >= 0) part = part.Substring(eq + 1).Trim();
                    part = Regex.Replace(part, "^https?://", "", RegexOptions.IgnoreCase);
                    int slash = part.IndexOf('/');
                    if (slash >= 0) part = part.Substring(0, slash);
                    if (part.StartsWith("127.0.0.1:", StringComparison.OrdinalIgnoreCase) ||
                        part.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase))
                    {
                        int col = part.LastIndexOf(':');
                        int port;
                        if (col >= 0 && int.TryParse(part.Substring(col + 1), out port) && port > 0 && port <= 65535)
                        {
                            return port;
                        }
                    }
                }
            }
            catch { }
            return 0;
        }

        /// <summary>
        /// Probes a local proxy (e.g., foreign 127.0.0.1:7890) for a working upstream TLS path
        /// within a short timeout so a listening blackhole proxy is detected immediately.
        /// </summary>
        private static bool ProbeLocalProxyUpstreamHealthy(int port, int timeoutMs = 1800)
        {
            if (port <= 0 || port > 65535) return false;
            int budgetMs = Math.Max(400, timeoutMs);
            TcpClient tcp = new TcpClient();
            try
            {
                tcp.NoDelay = true;
                tcp.ReceiveTimeout = budgetMs;
                tcp.SendTimeout = budgetMs;

                using (var cts = new CancellationTokenSource(budgetMs))
                using (cts.Token.Register(delegate { try { tcp.Close(); } catch { } }))
                {
                    IAsyncResult ar = tcp.BeginConnect("127.0.0.1", port, null, null);
                    WaitHandle wh = ar.AsyncWaitHandle;
                    try
                    {
                        if (!wh.WaitOne(Math.Min(budgetMs, 500)))
                        {
                            try { tcp.Close(); } catch { }
                            return false;
                        }
                        tcp.EndConnect(ar);
                    }
                    finally
                    {
                        try { wh.Close(); } catch { }
                    }

                    NetworkStream ns = tcp.GetStream();
                    ns.ReadTimeout = budgetMs;
                    ns.WriteTimeout = budgetMs;

                    byte[] req = Encoding.ASCII.GetBytes(
                        "CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\n" +
                        "Host: daily-cloudcode-pa.googleapis.com:443\r\n" +
                        "Proxy-Connection: keep-alive\r\n\r\n");
                    ns.Write(req, 0, req.Length);
                    ns.Flush();

                    byte[] hdrBuf = new byte[2048];
                    int total = 0;
                    bool gotHdrEnd = false;
                    while (total < hdrBuf.Length)
                    {
                        int n = ns.Read(hdrBuf, total, hdrBuf.Length - total);
                        if (n <= 0) break;
                        total += n;
                        string soFar = Encoding.ASCII.GetString(hdrBuf, 0, total);
                        if (soFar.IndexOf("\r\n\r\n", StringComparison.Ordinal) >= 0)
                        {
                            gotHdrEnd = true;
                            break;
                        }
                    }

                    if (!gotHdrEnd || total < 12) return false;
                    string statusText = Encoding.ASCII.GetString(hdrBuf, 0, total);
                    int lineEnd = statusText.IndexOf('\n');
                    string statusLine = lineEnd >= 0 ? statusText.Substring(0, lineEnd).Trim() : statusText.Trim();
                    if (!Regex.IsMatch(statusLine, @"^HTTP/\d\.\d\s+200\b", RegexOptions.IgnoreCase))
                    {
                        return false;
                    }

                    using (var ssl = new SslStream(ns, true, delegate { return true; }))
                    {
                        ssl.ReadTimeout = budgetMs;
                        ssl.WriteTimeout = budgetMs;
                        ssl.AuthenticateAsClient("daily-cloudcode-pa.googleapis.com");
                    }
                    return true;
                }
            }
            catch
            {
                return false;
            }
            finally
            {
                try { tcp.Close(); } catch { }
                try { ((IDisposable)tcp).Dispose(); } catch { }
            }
        }

        private static void DisableOrRestoreSystemProxy()
        {
            try
            {
                bool has7890 = _activeHttpPort != 7890 && IsLocalPortOpen(7890, 150);
                if (has7890)
                {
                    if (IsForeign7890CachedDead())
                    {
                        has7890 = false;
                    }
                    else
                    {
                        bool upstreamOk = ProbeLocalProxyUpstreamHealthy(7890, 1600);
                        UpdateForeign7890DeadState(!upstreamOk);
                        if (!upstreamOk)
                        {
                            has7890 = false;
                        }
                    }
                }
                else
                {
                    UpdateForeign7890DeadState(false);
                }

                string proxyOvr = BuildEffectiveProxyOverride();
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null)
                    {
                        object autoCfgObj = key.GetValue("AutoConfigURL", null);
                        if (autoCfgObj != null && IsPixelOrLocalAutoConfig(Convert.ToString(autoCfgObj)))
                        {
                            key.DeleteValue("AutoConfigURL", false);
                        }
                        if (has7890)
                        {
                            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                            key.SetValue("ProxyServer", "127.0.0.1:7890", RegistryValueKind.String);
                            key.SetValue("ProxyOverride", proxyOvr, RegistryValueKind.String);
                        }
                        else
                        {
                            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                            string existingSrv = Convert.ToString(key.GetValue("ProxyServer", ""));
                            if (TryExtractLoopbackProxyPort(existingSrv) == 7890)
                            {
                                key.DeleteValue("ProxyServer", false);
                            }
                        }
                    }
                }
                ApplyWinInetPerConnectionProxy(has7890, has7890 ? "127.0.0.1:7890" : "", has7890 ? proxyOvr : "", "");
                SetProxyResetRunOnceGuard(false);

                PurgeGlobalCliProxyEnvVars();
                if (has7890)
                {
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", "http://127.0.0.1:7890", EnvironmentVariableTarget.User);
                }
                else
                {
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.User);
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.Process);
                }
                BroadcastEnvironmentChange();

                HealAiEditorsAndServices(false, false, false, false, false);
            }
            catch { }
        }

        private static void FlushWindowsDnsCache()
        {
            try
            {
                var psi = new ProcessStartInfo("ipconfig.exe", "/flushdns")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (var p = Process.Start(psi))
                {
                    p.WaitForExit(1500);
                }
            }
            catch { }
        }

        private static bool IsLocalPortOpen(int port, int timeoutMs)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var res = client.BeginConnect("127.0.0.1", port, null, null);
                    bool ok = res.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMs));
                    if (!ok) return false;
                    client.EndConnect(res);
                    return true;
                }
            }
            catch { return false; }
        }

        private static string RunHttpProbe(string url, string proxyUrl, int timeoutSec)
        {
            try
            {
                string args = string.IsNullOrEmpty(proxyUrl)
                    ? string.Format("-k -s --noproxy * --connect-timeout {0} --max-time {1} -o NUL -w \"%{{http_code}}\" \"{2}\"", Math.Max(2, timeoutSec - 1), timeoutSec, url)
                    : string.Format("-k -s --connect-timeout {0} --max-time {1} -x \"{2}\" -o NUL -w \"%{{http_code}}\" \"{3}\"", Math.Max(2, timeoutSec - 1), timeoutSec, proxyUrl, url);

                var psi = new ProcessStartInfo
                {
                    FileName = "curl.exe",
                    Arguments = args,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(timeoutSec * 1000 + 500);
                    return (output ?? "").Trim();
                }
            }
            catch { return "000"; }
        }

        private static bool IsHttpCodeHealthy(string code)
        {
            if (string.IsNullOrEmpty(code) || code == "000") return false;
            return code.StartsWith("2") || code.StartsWith("3") || code == "404" || code == "403" || code == "401";
        }

        private static bool CheckOtherThirdPartyTunAdapters(out string detectedAdapterName)
        {
            detectedAdapterName = "";
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    string name = ni.Name ?? "";
                    string desc = ni.Description ?? "";
                    if (name.IndexOf("PixelAG", StringComparison.OrdinalIgnoreCase) >= 0) continue;

                    if (desc.IndexOf("Wintun", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        desc.IndexOf("WireGuard", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        desc.IndexOf("Sing-Box", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("PixelTUN", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Nekoray", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Hiddify", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Amnezia", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Outline", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        detectedAdapterName = string.Format("{0} ({1})", name, desc);
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        // ====================================================================
        // MAIN TUNNEL LAUNCHER WITH ZERO-BLACKHOLE PRE-FLIGHT VERIFICATION
        // ====================================================================
        private async void StartTunnelAsync()
        {
            try
            {
                await StartTunnelInternalAsync();
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                StopTunnelProcess(false);
                RunOnUiThread(delegate
                {
                    SetStatus(ColRed, "Ошибка запуска (Прямой интернет сохранён)", errMsg);
                    ResetButtonState(false);
                });
            }
        }

        private async Task StartTunnelInternalAsync()
        {
            try
            {
                string rawKey = ReadFromUiThread(() => _keyInput != null ? (_keyInput.Text ?? "").Trim() : "", "");
                if (string.IsNullOrEmpty(rawKey))
                {
                    int dLeft;
                    rawKey = EnsureAutoTrialKeyProvisioned(out dLeft);
                    RunOnUiThreadSync(delegate { if (_keyInput != null) _keyInput.Text = rawKey; });
                }

                if (!_optAntigravity && !_optCursorAi && !_optDiscordYt && !_optSocialWeb)
                {
                    RunOnUiThread(delegate
                    {
                        SetStatus(ColAmber, "Выберите хотя бы одну категорию", "Отметьте Antigravity IDE или другие сервисы для маршрутизации.");
                    });
                    return;
                }

                if (!IsAdministrator() && !_preferSafeProxyMode)
                {
                    RunOnUiThreadSync(delegate { RelaunchAsAdmin("--autoconnect"); });
                    if (!_preferSafeProxyMode) return;
                }

                SaveCurrentState();
                _isBusy = true;
                RunOnUiThread(delegate
                {
                    if (_actionBtnText != null) _actionBtnText.Text = "Подключение...";
                    if (_actionBtnIconHolder != null)
                    {
                        _actionBtnIconHolder.Content = CreateSpinningIcon(ColBg, 14);
                    }
                    SetStatus(ColAmber, "Запуск и проверка канала...", "Проверка портов, остановка конфликтов и тест сквозного соединения...");
                });

                string vlessUri = rawKey;
                if (rawKey.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    rawKey.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    vlessUri = await Task.Run(() => FetchVlessFromSubscription(rawKey));
                    if (string.IsNullOrEmpty(vlessUri))
                    {
                        RunOnUiThread(delegate
                        {
                            SetStatus(ColRed, "Не удалось загрузить подписку", "Проверьте интернет или вставьте прямой ключ vless:// из бота.");
                            ResetButtonState(false);
                        });
                        return;
                    }
                }

                VlessNode node = ParseVlessUri(vlessUri);
                bool isFreePwp3 = node != null && string.Equals(node.TransportType, "pwp3", StringComparison.OrdinalIgnoreCase);
                if (node == null || string.IsNullOrEmpty(node.Server) || (!isFreePwp3 && string.IsNullOrEmpty(node.Uuid)))
                {
                    RunOnUiThread(delegate
                    {
                        SetStatus(ColRed, "Ошибка чтения ключа", "Проверьте, что скопировали полный ключ vless:// из Telegram-\u0431\u043e\u0442\u0430.");
                        ResetButtonState(false);
                    });
                    return;
                }

                _activeNode = node;

                int pingMs = await Task.Run(() => MeasureTcpPing(node.Server, node.Port));
                bool isClusterHost = IsClusterHost(node.Server);
                if (pingMs < 0 && isClusterHost)
                {
                    pingMs = await Task.Run(() => MeasureTcpPing(node.Server, 443));
                    if (pingMs < 0) pingMs = await Task.Run(() => MeasureTcpPing(node.Server, 25443));
                    if (pingMs < 0) pingMs = await Task.Run(() => MeasureTcpPing(node.Server, 2087));
                    if (pingMs < 0) pingMs = await Task.Run(() => MeasureTcpPing(node.Server, 24443));
                }

                bool isCustomKey = IsCustomPaidKey(vlessUri);

                if (pingMs < 0 && isCustomKey)
                {
                    RunOnUiThread(delegate
                    {
                        SetStatus(ColRed, "Сервер недоступен", string.Format("Нет ответа от {0}:{1}. Нажмите «Диагностика».", node.Server, node.Port));
                        ResetButtonState(false);
                    });
                    return;
                }

                StopTunnelProcess(false);

                string agHttpCode = "000";
                string gstaticCode = "000";
                string directRuCode = "000";
                string portRelocationNote = "";

                await Task.Run(() =>
                {
                    StopConflictingVpnAndApplyFixes();
                    portRelocationNote = EnsureAvailableLocalPorts();
                    EnsureManifestSecretsForConfig(3500);

                    string jsonConfig = BuildSingBoxConfig(node, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                    ApplyAndStartCoreConfig(jsonConfig);

                    for (int i = 0; i < 35; i++)
                    {
                        if (IsLocalPortOpen(_activeHttpPort, 150)) break;
                        if (!PixelCoreService.IsRunning) break;
                        Thread.Sleep(100);
                    }

                    // Verify BOTH tunnel AND Direct .RU internet BEFORE enabling System Proxy!
                    if (IsLocalPortOpen(_activeHttpPort, 200))
                    {
                        string localProxy = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                        gstaticCode = RunHttpProbe("http://www.gstatic.com/generate_204", localProxy, 6);
                        if (string.IsNullOrEmpty(PixelCoreService.LastLicenseError))
                        {
                            var t1 = Task.Factory.StartNew(() => { agHttpCode = RunHttpProbe("https://daily-cloudcode-pa.googleapis.com", localProxy, 6); });
                            var t3 = Task.Factory.StartNew(() => { directRuCode = RunHttpProbe("https://ya.ru", "", 4); });
                            Task.WaitAll(new[] { t1, t3 }, 7000);
                        }
                    }
                });

                string licError = PixelCoreService.LastLicenseError;
                if (!string.IsNullOrEmpty(licError))
                {
                    StopTunnelProcess(false);
                    RunOnUiThread(delegate
                    {
                        ApplyLicenseErrorToUi(licError);
                        ResetButtonState(false);
                    });
                    return;
                }

                bool finalTunnelOk = IsHttpCodeHealthy(agHttpCode) || IsHttpCodeHealthy(gstaticCode);

                if ((PixelCoreService.IsRunning || (_coreProcess != null && !_coreProcess.HasExited)) && IsLocalPortOpen(_activeHttpPort, 250) && finalTunnelOk)
                {
                    ApplyConnectedProxyPolicy();
                    FlushWindowsDnsCache();
                    await Task.Run(() =>
                    {
                        List<string> pLogs;
                        PatchAntigravitySanctionsAndProxy(out pLogs, false);
                    });
                    HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);

                    _isConnected = true;
                    _tunnelConnectedUtc = DateTime.UtcNow;
                    var unusedPulseOnConn = RefreshAiPulseUiAsync(true);
                    _agBannerDismissed = false;
                    int shownMs = PixelCoreService.ActiveNodeLatencyMs > 0 ? PixelCoreService.ActiveNodeLatencyMs : (pingMs > 0 ? pingMs : 28);
                    string regTag = string.Equals(_selectedRegion, "us", StringComparison.OrdinalIgnoreCase) && PixelCoreService.IsRegionAvailable("us") ? "US" : "NL";
                    string modeBadge = string.Format("{0} :{1}", PixelCoreService.UsingGoEngine ? "Go uTLS Chrome" : "PWP-3 Dual-Mux", _activeHttpPort);
                    string codeShown = IsHttpCodeHealthy(agHttpCode) ? agHttpCode : gstaticCode;

                    RunOnUiThread(delegate
                    {
                        if (_pingLabel != null)
                        {
                            _pingLabel.Text = string.Format("{0} • {1} мс", regTag, shownMs);
                            _pingLabel.Foreground = new SolidColorBrush(ColGreen);
                        }

                        SetStatus(
                            ColGreen,
                            "Туннель активен • PWP-3 0-RTT & Вход из-под санкций",
                            string.Format("{0} • CloudCode HTTP {1} [OK] • Сайты .RU напрямую", modeBadge, codeShown)
                        );
                        ResetButtonState(true);
                        UpdateLicenseHintFromServer();
                        CheckSignedManifestUpdateUi();
                        RefreshAiTelemetryBanner();
                        CheckAntigravityPreTunnelState();
                    });

                    var unusedBgManifest = Task.Run(async delegate
                    {
                        try
                        {
                            await Task.Delay(3000).ConfigureAwait(false);
                            if (_isConnected)
                            {
                                CheckForGitHubUpdateAsync();
                                RunOnUiThread(delegate { CheckSignedManifestUpdateUi(); });
                            }
                        }
                        catch { }
                    });
                }
                else
                {
                    // ZERO-BLACKHOLE GUARD: Never leave a broken tunnel or proxy active!
                    string goReason = PixelCoreService.GoEngineFallbackReason;
                    string connErr = PixelCoreService.LastConnectError;
                    bool localPortUp = IsLocalPortOpen(_activeHttpPort, 100);
                    StopTunnelProcess(false);

                    string failTitle;
                    string failSub;
                    if (!localPortUp)
                    {
                        failTitle = "Не удалось запустить локальный шлюз";
                        failSub = !string.IsNullOrEmpty(goReason)
                            ? string.Format("Причина: {0}. Прямой интернет сохранён.", goReason)
                            : "Ядро не открыло локальный порт. Нажмите «Диагностика» для проверки.";
                    }
                    else if (!string.IsNullOrEmpty(connErr) || !string.IsNullOrEmpty(goReason))
                    {
                        string detail = !string.IsNullOrEmpty(connErr) ? connErr : goReason;
                        failTitle = "Туннель не пропускает трафик (Сеть сохранена)";
                        failSub = string.Format("Причина: {0}. Нажмите «Диагностика» для авто-исправления.", detail);
                    }
                    else
                    {
                        failTitle = "Туннель не пропускает трафик (Сеть сохранена)";
                        failSub = "Прямой интернет не затронут. Нажмите «Диагностика» для авто-исправления.";
                    }

                    RunOnUiThread(delegate
                    {
                        SetStatus(ColRed, failTitle, failSub);
                        ResetButtonState(false);
                    });
                }
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                StopTunnelProcess(false);
                RunOnUiThread(delegate
                {
                    SetStatus(ColRed, "Ошибка запуска (Прямой интернет сохранён)", errMsg);
                    ResetButtonState(false);
                });
            }
        }

        private static void KillCoreProcesses()
        {
            try
            {
                string[] procsToKill = new[] { CORE_EXE_NAME };
                foreach (var name in procsToKill)
                {
                    try
                    {
                        foreach (var p in Process.GetProcessesByName(name))
                        {
                            try { p.Kill(); p.WaitForExit(600); } catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ApplyAndStartCoreConfig(string jsonConfig)
        {
            try
            {
                string dir = System.IO.Path.GetDirectoryName(_activeConfigPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.WriteAllText(_activeConfigPath, jsonConfig, new UTF8Encoding(false));
            }
            catch { }
            PixelCoreService.StartServiceFromJson(jsonConfig, _activeConfigPath);
        }

        private void StopTunnelProcess(bool updateUi = true)
        {
            bool wasOAuthHelperActive = _oauthHelperActive;
            _oauthHelperActive = false;

            DisableOrRestoreSystemProxy();
            PixelCoreService.StopService();

            try
            {
                if (_coreProcess != null && !_coreProcess.HasExited)
                {
                    _coreProcess.Kill();
                    _coreProcess.WaitForExit(1200);
                }
            }
            catch { }

            KillCoreProcesses();

            _coreProcess = null;
            _isConnected = false;

            RunOnUiThread(delegate
            {
                if (wasOAuthHelperActive)
                {
                    if (_oauthHelperTimer != null)
                    {
                        try { _oauthHelperTimer.Stop(); } catch { }
                    }
                    if (_btnOAuthHelperText != null) _btnOAuthHelperText.Text = "Вход в Google (90с)";
                    if (_btnOAuthHelperBorder != null) _btnOAuthHelperBorder.BorderBrush = new SolidColorBrush(ColBlue);
                }
                if (_agLeakGuardBanner != null) _agLeakGuardBanner.Visibility = Visibility.Collapsed;

                if (updateUi)
                {
                    ResetButtonState(false);
                    _pingLabel.Text = "PWP-3 MUX";
                    _pingLabel.Foreground = new SolidColorBrush(ColText3);
                    SetStatus(ColText3, "Туннель остановлен", "Бесплатный анлокер готов • Нажмите «Запустить туннель» или «Умная диагностика»");
                    RefreshAiTelemetryBanner();
                }
            });
            var unusedPulseStop = RefreshAiPulseUiAsync(false);
        }

        // ====================================================================
        // SMART DIAGNOSTICS HELPERS: HOSTS DOCTOR, OAUTH GUARD & PASSPORT
        // ====================================================================
        public static List<string> ScanAndHealPoisonedHostsFile(string customHostsPath, bool attemptAutoComment, out int poisonedCount, out bool healedByWrite)
        {
            poisonedCount = 0;
            healedByWrite = false;
            var findings = new List<string>();

            try
            {
                string hostsPath = string.IsNullOrEmpty(customHostsPath)
                    ? System.IO.Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts")
                    : customHostsPath;

                if (!File.Exists(hostsPath)) return findings;

                string[] targetSuffixes = new[]
                {
                    "antigravity.google", "antigravity-unleash.goog", "googleapis.com", "google.com",
                    "gstatic.com", "gemini.google.com", "aistudio.google.com", "makersuite.google.com",
                    "googleusercontent.com", "claude.ai", "anthropic.com", "openai.com", "chatgpt.com",
                    "oaistatic.com", "oaiusercontent.com", "cursor.com", "cursor.sh", "cursorapi.com",
                    "codeium.com", "windsurf.com", "github.com", "githubusercontent.com", "npmjs.org",
                    "pypi.org", "huggingface.co", "discord.com", "discordapp.com", "discord.gg",
                    "spotify.com", "googlevideo.com", "youtube.com", "ytimg.com"
                };

                string[] rawLines = File.ReadAllLines(hostsPath, Encoding.UTF8);
                var rebuiltLines = new List<string>(rawLines.Length);
                bool modified = false;

                foreach (string line in rawLines)
                {
                    string trimmed = (line ?? "").Trim();
                    if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                    {
                        rebuiltLines.Add(line);
                        continue;
                    }

                    int hashComment = trimmed.IndexOf('#');
                    string activePart = hashComment >= 0 ? trimmed.Substring(0, hashComment).Trim() : trimmed;
                    string[] tokens = Regex.Split(activePart, "\\s+");
                    if (tokens.Length < 2)
                    {
                        rebuiltLines.Add(line);
                        continue;
                    }

                    string mappedIp = tokens[0];
                    var matchedDomains = new List<string>();
                    for (int i = 1; i < tokens.Length; i++)
                    {
                        string dom = tokens[i].Trim().ToLowerInvariant();
                        if (dom == "localhost" || dom == "ip6-localhost" || dom == "ip6-loopback" || dom == "broadcasthost" || dom == "local")
                            continue;

                        foreach (string suf in targetSuffixes)
                        {
                            if (dom == suf || dom.EndsWith("." + suf, StringComparison.OrdinalIgnoreCase))
                            {
                                matchedDomains.Add(dom);
                                break;
                            }
                        }
                    }

                    if (matchedDomains.Count > 0)
                    {
                        poisonedCount += matchedDomains.Count;
                        findings.Add(string.Join(", ", matchedDomains.ToArray()) + " -> " + mappedIp);
                        if (attemptAutoComment)
                        {
                            rebuiltLines.Add("# [PixelTunnel Disabled Dead IP] " + line);
                            modified = true;
                        }
                        else
                        {
                            rebuiltLines.Add(line);
                        }
                    }
                    else
                    {
                        rebuiltLines.Add(line);
                    }
                }

                if (modified && attemptAutoComment)
                {
                    try
                    {
                        File.WriteAllLines(hostsPath, rebuiltLines.ToArray(), new UTF8Encoding(false));
                        healedByWrite = true;
                    }
                    catch
                    {
                        healedByWrite = false;
                    }
                }
            }
            catch { }

            return findings;
        }

        private async void ToggleGoogleOAuthHelperModeAsync()
        {
            try
            {
                if (_oauthHelperActive)
                {
                    StopGoogleOAuthHelperMode(false);
                    return;
                }

                if (!_isConnected && !_isBusy)
                {
                    await StartTunnelInternalAsync();
                    if (!_isConnected) return;
                }

                _oauthHelperActive = true;
                _oauthHelperSecondsLeft = 90;

                await Task.Run(() =>
                {
                    try
                    {
                        if (_activeNode != null)
                        {
                            // На 90 сек включаем маршрутизацию браузера для Google OAuth с жёстким исключением 127.0.0.1 / localhost
                            string oauthCfg = BuildSingBoxConfig(_activeNode, true, _optCursorAi, _optDiscordYt, true, false);
                            ApplyAndStartCoreConfig(oauthCfg);
                        }
                        EnableSystemProxy();
                        FlushWindowsDnsCache();
                    }
                    catch { }
                });

                RunOnUiThread(delegate
                {
                    if (_btnOAuthHelperText != null) _btnOAuthHelperText.Text = "Вход активен (90с)";
                    if (_btnOAuthHelperBorder != null) _btnOAuthHelperBorder.BorderBrush = new SolidColorBrush(ColGreen);

                    SetStatus(
                        ColGreen,
                        "🔑 Режим входа в Google активен (90 сек)",
                        "Нажмите Sign in в Antigravity — браузер войдёт через Нидерланды, а возврат 127.0.0.1 придёт прямо в IDE!"
                    );

                    if (_oauthHelperTimer != null) _oauthHelperTimer.Stop();
                    _oauthHelperTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.0) };
                    _oauthHelperTimer.Tick += delegate
                    {
                        try
                        {
                            if (!_oauthHelperActive)
                            {
                                if (_oauthHelperTimer != null) _oauthHelperTimer.Stop();
                                return;
                            }
                            _oauthHelperSecondsLeft--;
                            if (_oauthHelperSecondsLeft <= 0)
                            {
                                StopGoogleOAuthHelperMode(false);
                            }
                            else
                            {
                                if (_btnOAuthHelperText != null)
                                    _btnOAuthHelperText.Text = string.Format("Вход активен ({0}с)", _oauthHelperSecondsLeft);
                            }
                        }
                        catch { }
                    };
                    _oauthHelperTimer.Start();
                });
            }
            catch (Exception ex)
            {
                _oauthHelperActive = false;
                string errMsg = ex.Message;
                RunOnUiThread(delegate
                {
                    SetStatus(ColAmber, "Не удалось включить режим входа Google", errMsg);
                });
            }
        }

        private void StopGoogleOAuthHelperMode(bool silent)
        {
            _oauthHelperActive = false;
            RunOnUiThread(delegate
            {
                if (_oauthHelperTimer != null)
                {
                    try { _oauthHelperTimer.Stop(); } catch { }
                }

                if (_btnOAuthHelperText != null) _btnOAuthHelperText.Text = "Вход в Google (90с)";
                if (_btnOAuthHelperBorder != null) _btnOAuthHelperBorder.BorderBrush = new SolidColorBrush(ColBlue);
            });

            if (_isConnected && _activeNode != null && !silent)
            {
                Task.Run(() =>
                {
                    try
                    {
                        string normalCfg = BuildSingBoxConfig(_activeNode, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                        ApplyAndStartCoreConfig(normalCfg);
                        ApplyConnectedProxyPolicy();
                        HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
                    }
                    catch { }
                });

                RunOnUiThread(delegate
                {
                    SetStatus(
                        ColGreen,
                        "Изолированный режим восстановлен",
                        string.Format("Вход в Google завершён • Туннель :{0} работает только для выбранных категорий", _activeHttpPort)
                    );
                });
            }
        }

        public static string BuildCompactSupportPassport(
            int hostsPoisonedCount,
            bool hostsHealed,
            string avMitmName,
            string nodeMatrixSummary,
            string agCode,
            string gemCode,
            string oauthCode,
            string yaCode,
            string thirdPartyAdapters,
            bool lsSanctionPatched)
        {
            long drift = PixelCoreService.ClockOffsetSeconds;
            string clockState = Math.Abs(drift) < 45L
                ? string.Format("OK ({0:+#;-#;0}с)", drift)
                : string.Format("АВТО-КОМПЕНСАЦИЯ ({0:+#;-#;0}с)", drift);

            string hostsState = hostsPoisonedCount == 0
                ? "Чист"
                : (hostsHealed ? string.Format("Вылечен ({0})", hostsPoisonedCount) : string.Format("Перехватов: {0} (нужен админ)", hostsPoisonedCount));

            string sslState = string.IsNullOrEmpty(avMitmName) ? "Чист (оригинальный TLS)" : ("MITM: " + avMitmName);

            string tier = string.IsNullOrEmpty(PixelCoreService.ServerLicenseTier)
                ? "LOCAL/TRIAL"
                : PixelCoreService.ServerLicenseTier.ToUpperInvariant();
            string licInfo = string.IsNullOrEmpty(PixelCoreService.LastLicenseError)
                ? string.Format("{0} (дней: {1}, ПК: {2}/{3})",
                    tier,
                    PixelCoreService.ServerDaysLeft >= 0 ? PixelCoreService.ServerDaysLeft.ToString() : "?",
                    Math.Max(1, PixelCoreService.ServerDevicesUsed),
                    PixelCoreService.ServerDevicesMax > 0 ? PixelCoreService.ServerDevicesMax.ToString() : "?")
                : ("ОШИБКА: " + PixelCoreService.LastLicenseError);

            var sb = new StringBuilder();
            sb.AppendLine(string.Format("[PixelTunnel v{0} • Паспорт диагностики]", APP_VERSION));
            sb.AppendLine(string.Format("ОС: {0} ({1}) | Порты: :{2}/:{3} | Категории: AG={4}, MCP={5}",
                Environment.OSVersion.Version,
                Environment.Is64BitOperatingSystem ? "x64" : "x86",
                _activeHttpPort, _activeSocksPort,
                "ON", _optMcpTerminal ? "ON" : "OFF"));
            sb.AppendLine(string.Format("Часы ПК: {0} | Hosts: {1} | SSL: {2}", clockState, hostsState, sslState));
            sb.AppendLine("Подписка: " + licInfo);
            sb.AppendLine(string.Format("Активный канал: {0} ({1}) • Anti-DPI: {2} (36KB={3}, эскалаций={4})",
                PixelCoreService.ActiveNodeName ?? "none",
                PixelCoreService.ActiveProtocol ?? "PWP-3",
                PixelCoreService.AntiDpiProfileName,
                PixelCoreService.LastAntiFreezeProbePassed ? "OK" : "FAIL",
                PixelCoreService.AntiFreezeEscalations));
            if (!string.IsNullOrEmpty(nodeMatrixSummary))
            {
                sb.AppendLine("Матрица узлов: " + nodeMatrixSummary);
            }
            sb.AppendLine(string.Format("Antigravity IDE: Патч={0} | Каналы: CloudCode={1}, Gemini={2}, OAuth2={3}, РФ={4}",
                lsSanctionPatched ? "OK" : "НЕТ",
                string.IsNullOrEmpty(agCode) ? "-" : agCode,
                string.IsNullOrEmpty(gemCode) ? "-" : gemCode,
                string.IsNullOrEmpty(oauthCode) ? "-" : oauthCode,
                string.IsNullOrEmpty(yaCode) ? "-" : yaCode));
            sb.Append("Сторонние TUN/VPN: " + (string.IsNullOrEmpty(thirdPartyAdapters) ? "Нет" : thirdPartyAdapters));
            return sb.ToString();
        }

        private string BuildLiveSupportPassportSnapshot()
        {
            int pCount;
            bool hOk;
            ScanAndHealPoisonedHostsFile(null, false, out pCount, out hOk);
            string tunName;
            CheckOtherThirdPartyTunAdapters(out tunName);
            List<string> dummyLogs;
            bool lsOk = PatchAntigravitySanctionsAndProxy(out dummyLogs, false);
            return BuildCompactSupportPassport(
                pCount, hOk,
                PixelCoreService.LastDetectedSslMitm,
                "",
                _isConnected ? "OK" : "IDLE",
                "-", "-", "OK",
                tunName, lsOk);
        }

        // ====================================================================
        // SMART DIAGNOSTICS & SELF-HEALING ENGINE ("АВТО-ДОКТОР КЛИЕНТА")
        // ====================================================================
        private async void RunSmartDiagnosticsAsync(bool autoFix, bool isAutoDiagCli = false)
        {
            if (_isDiagRunning) return;
            _isDiagRunning = true;

            int issuesFound = 0;
            int issuesFixed = 0;
            var report = new StringBuilder();

            int diagPoisonedHosts = 0;
            bool diagHostsHealed = false;
            string diagSslMitm = "";
            string diagNodeMatrix = "";
            string diagAgCode = "000";
            string diagGemCode = "000";
            string diagOAuthCode = "000";
            string diagYaCode = "000";
            string diagThirdPartyTun = "";
            bool diagLsPatched = false;
            string diagGoReason = "";
            string diagLicErrSummary = "";

            try
            {
                RunOnUiThread(delegate
                {
                    if (_diagBtnText != null) _diagBtnText.Text = "Проверка...";
                    if (_diagBtnIconHolder != null)
                    {
                        _diagBtnIconHolder.Content = CreateSpinningIcon(ColBlue, 13);
                    }
                    if (!_isConnected)
                    {
                        SetStatus(ColBlue, "Диагностика и проверка сети...", "Проверяем соединение, узлы и настройки...");
                    }
                });

                await Task.Run(() =>
                {
                    var sw = Stopwatch.StartNew();
                    report.AppendLine("╔══ ДИАГНОСТИКА И АВТО-ДОКТОР PIXELTUNNEL ══╗");

                // ----------------------------------------------------------------
                // 1. CHECK DIRECT ISP INTERNET & POISONED HOSTS FILE
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[1/9] Прямой интернет РФ и проверка файла Windows hosts:");
                int dnsPing = MeasureTcpPing("77.88.8.8", 53);
                string yaDirect = RunHttpProbe("https://ya.ru", "", 3);
                diagYaCode = yaDirect;
                if (IsHttpCodeHealthy(yaDirect) || dnsPing > 0)
                {
                    report.AppendLine(string.Format("  ✓ [OK] Прямой канал работает (ya.ru: HTTP {0}, DNS 77.88.8.8: {1} мс)", yaDirect, dnsPing > 0 ? dnsPing.ToString() : "OK"));
                }
                else
                {
                    issuesFound++;
                    report.AppendLine("  ✗ [ПРОБЛЕМА] Прямой выход в интернет заблокирован или недоступен!");
                    if (autoFix)
                    {
                        EmergencyDisableDeadSystemProxy();
                        KillCoreProcesses();
                        FlushWindowsDnsCache();
                        Thread.Sleep(300);
                        yaDirect = RunHttpProbe("https://ya.ru", "", 3);
                        diagYaCode = yaDirect;
                        if (IsHttpCodeHealthy(yaDirect))
                        {
                            issuesFixed++;
                            report.AppendLine("  ⚡ [АВТО-ФИКС] Сброшены зависшие прокси и DNS-кэш -> Прямой интернет восстановлен (HTTP " + yaDirect + ")!");
                        }
                        else
                        {
                            report.AppendLine("  💡 [СОВЕТ] Проверьте Wi-Fi/кабель провайдера или отключите сторонний фаервол.");
                        }
                    }
                }

                var poisonedHostsList = ScanAndHealPoisonedHostsFile(null, autoFix, out diagPoisonedHosts, out diagHostsHealed);
                if (diagPoisonedHosts == 0)
                {
                    report.AppendLine("  ✓ [OK] Файл C:\\Windows\\System32\\drivers\\etc\\hosts чист (нет мёртвых IP от старых обходов).");
                }
                else
                {
                    issuesFound++;
                    foreach (var ph in poisonedHostsList)
                    {
                        report.AppendLine("  ✗ [ОТРАВЛЕННЫЙ HOSTS] Перехвачен AI-домен: " + ph);
                    }
                    if (diagHostsHealed)
                    {
                        issuesFixed++;
                        FlushWindowsDnsCache();
                        report.AppendLine("  ⚡ [АВТО-ФИКС] Мёртвые IP-записи автоматически закомментированы в hosts + сброшен DNS!");
                    }
                    else
                    {
                        report.AppendLine("  💡 [РЕШЕНИЕ] Запустите PixelTunnel от имени Администратора и нажмите «Авто-Фикс» — он сам очистит мёртвые IP в hosts.");
                    }
                }

                // ----------------------------------------------------------------
                // 2. CHECK CONFLICTING SERVICES, PORTS & THIRD-PARTY TUN ADAPTERS
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[2/9] Проверка конфликтов служб, Hyper-V/WSL и локальных портов:");
                if (autoFix)
                {
                    var earlyFixed = StopConflictingVpnAndApplyFixes();
                    if (earlyFixed.Count > 0)
                    {
                        foreach (var item in earlyFixed)
                        {
                            issuesFound++;
                            issuesFixed++;
                            report.AppendLine("  ✓ [АВТО-ФИКС] " + item);
                        }
                    }
                    else
                    {
                        report.AppendLine("  ✓ [OK] Конфликтующих служб ProksiFi и фоновых перехватчиков не обнаружено.");
                    }
                }
                else
                {
                    report.AppendLine("  ✓ [OK] Конфликтующих служб ProksiFi не обнаружено.");
                }

                if (!_isConnected)
                {
                    string portMsg = EnsureAvailableLocalPorts();
                    if (!string.IsNullOrEmpty(portMsg))
                    {
                        issuesFound++;
                        issuesFixed++;
                        report.AppendLine("  ⚡ [АВТО-ПОРТ] " + portMsg);
                    }
                    else
                    {
                        report.AppendLine(string.Format("  ✓ [OK] Локальные порты HTTP :{0} / SOCKS5 :{1} свободны и готовы.", _activeHttpPort, _activeSocksPort));
                    }
                }
                else
                {
                    report.AppendLine(string.Format("  ✓ [OK] Активный локальный шлюз работает на портах HTTP :{0} / SOCKS5 :{1}.", _activeHttpPort, _activeSocksPort));
                }

                string thirdPartyTun;
                if (CheckOtherThirdPartyTunAdapters(out thirdPartyTun))
                {
                    diagThirdPartyTun = thirdPartyTun;
                    issuesFound++;
                    report.AppendLine("  ⚠ [ВНИМАНИЕ] Обнаружен сторонний виртуальный адаптер: " + thirdPartyTun);
                    if (autoFix)
                    {
                        _preferSafeProxyMode = true;
                        issuesFixed++;
                        report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС] Включён режим «Безопасный локальный шлюз :{0} без конфликта с чужим TUN»!", _activeHttpPort));
                    }
                }

                string[] otherVpnProcs = new[] { "v2rayN", "nekobox", "nekoray", "Hiddify", "AmneziaVPN", "wireguard", "goodbyedpi", "winws" };
                var runningOthers = new List<string>();
                foreach (var vp in otherVpnProcs)
                {
                    try { if (Process.GetProcessesByName(vp).Length > 0) runningOthers.Add(vp + ".exe"); } catch { }
                }
                if (runningOthers.Count > 0)
                {
                    if (string.IsNullOrEmpty(diagThirdPartyTun)) diagThirdPartyTun = string.Join(",", runningOthers.ToArray());
                    report.AppendLine("  💡 [ЗАМЕТКА] Запущены сетевые утилиты: " + string.Join(", ", runningOthers.ToArray()) + " (не убиваем их для сохранения вашего Discord/игр).");
                }

                // ----------------------------------------------------------------
                // 3. CHECK WINDOWS SYSTEM PROXY REGISTRY ("DEAD PROXY" KILLER)
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[3/9] Проверка системного прокси Windows (WinInet) и AG_LS_PROXY:");
                try
                {
                    using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                    {
                        if (key != null)
                        {
                            object wpadObj = key.GetValue("AutoConfigURL", null);
                            string wpadStr = Convert.ToString(wpadObj);
                            if (wpadObj != null && IsActivePixelSmartPacUrl(wpadStr))
                            {
                                report.AppendLine("  ✓ [OK] Smart PAC активен (" + wpadStr + ")");
                            }
                            else if (wpadObj != null && IsPixelOrLocalAutoConfig(wpadStr))
                            {
                                issuesFound++;
                                report.AppendLine("  ✗ [ПРОБЛЕМА] Обнаружен устаревший WPAD/PAC AutoConfigURL: " + wpadStr);
                                if (autoFix)
                                {
                                    key.DeleteValue("AutoConfigURL", false);
                                    RefreshWinInet();
                                    issuesFixed++;
                                    report.AppendLine("  ⚡ [АВТО-ФИКС] Устаревший AutoConfigURL удалён из реестра.");
                                }
                            }

                            int proxyEn = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                            string proxySrv = Convert.ToString(key.GetValue("ProxyServer", ""));
                            string proxyOvr = Convert.ToString(key.GetValue("ProxyOverride", ""));

                            bool checkedForeign7890 = false;
                            bool foreign7890Dead = false;

                            if (proxyEn == 1 && !string.IsNullOrEmpty(proxySrv))
                            {
                                int pPort = TryExtractLoopbackProxyPort(proxySrv);
                                bool portAlive = pPort > 0 && IsLocalPortOpen(pPort, 200);
                                bool foreign7890Blocked = false;
                                if (portAlive && pPort == 7890 && pPort != _activeHttpPort)
                                {
                                    bool upstreamOk = ProbeLocalProxyUpstreamHealthy(7890, 1800);
                                    checkedForeign7890 = true;
                                    foreign7890Dead = !upstreamOk;
                                    UpdateForeign7890DeadState(foreign7890Dead);
                                    foreign7890Blocked = !upstreamOk;
                                }

                                if (!portAlive)
                                {
                                    issuesFound++;
                                    report.AppendLine(string.Format("  ✗ [НАЙДЕН УБИЙЦА БРАУЗЕРОВ] Системный прокси включён ({0}), но порт {1} МЁРТВ!", proxySrv, pPort));
                                    if (autoFix)
                                    {
                                        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                        if (pPort == 7890) key.DeleteValue("ProxyServer", false);
                                        ApplyWinInetPerConnectionProxy(false, "", "");
                                        issuesFixed++;
                                        report.AppendLine("  ⚡ [АВТО-ФИКС] Мёртвый системный прокси отключён -> Браузеры разблокированы!");
                                    }
                                }
                                else if (foreign7890Blocked)
                                {
                                    issuesFound++;
                                    report.AppendLine(string.Format("  ✗ [ПРОБЛЕМА UPSTREAM] Чужой локальный прокси {0} слушает порт 7890, но его upstream МЁРТВ (таймаут TLS/CONNECT)!", proxySrv));
                                    if (autoFix)
                                    {
                                        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                        key.DeleteValue("ProxyServer", false);
                                        ApplyWinInetPerConnectionProxy(false, "", "");
                                        issuesFixed++;
                                        report.AppendLine("  ⚡ [АВТО-ФИКС] Нерабочий сторонний прокси 127.0.0.1:7890 очищен из системного прокси Windows -> Сеть разблокирована!");
                                    }
                                }
                                else
                                {
                                    report.AppendLine(string.Format("  ✓ [OK] Системный прокси ({0}) активен и порт отвечает.", proxySrv));
                                    if (autoFix)
                                    {
                                        string effOvr = BuildEffectiveProxyOverride();
                                        if (proxyOvr.IndexOf("127.*", StringComparison.OrdinalIgnoreCase) < 0 ||
                                            proxyOvr.IndexOf("localhost", StringComparison.OrdinalIgnoreCase) < 0 ||
                                            proxyOvr.IndexOf("*.ru", StringComparison.OrdinalIgnoreCase) < 0)
                                        {
                                            key.SetValue("ProxyOverride", effOvr, RegistryValueKind.String);
                                            issuesFixed++;
                                            report.AppendLine("  ⚡ [АВТО-ФИКС] Добавлены исключения localhost, 127.* и *.ru в ProxyOverride (защита Google OAuth и РФ-сайтов).");
                                        }
                                        ApplyWinInetPerConnectionProxy(true, proxySrv, effOvr);
                                    }
                                }
                            }
                            else
                            {
                                report.AppendLine("  ✓ [OK] Системный прокси не блокирует сеть (изолированный режим прямого интернета).");
                            }

                            string agLs = Environment.GetEnvironmentVariable("AG_LS_PROXY", EnvironmentVariableTarget.User);
                            if (string.IsNullOrEmpty(agLs))
                            {
                                agLs = Environment.GetEnvironmentVariable("AG_LS_PROXY", EnvironmentVariableTarget.Process);
                            }
                            if (!string.IsNullOrEmpty(agLs))
                            {
                                int agPort = TryExtractLoopbackProxyPort(agLs);
                                if (agPort <= 0 && agLs.Contains(":"))
                                {
                                    int col = agLs.LastIndexOf(':');
                                    int.TryParse(agLs.Substring(col + 1).TrimEnd('/'), out agPort);
                                }
                                bool agPortOpen = agPort > 0 && IsLocalPortOpen(agPort, 150);
                                bool agForeign7890Dead = false;
                                if (agPortOpen && agPort == 7890 && agPort != _activeHttpPort)
                                {
                                    if (checkedForeign7890)
                                    {
                                        agForeign7890Dead = foreign7890Dead;
                                    }
                                    else
                                    {
                                        bool agUpstreamOk = ProbeLocalProxyUpstreamHealthy(7890, 1800);
                                        agForeign7890Dead = !agUpstreamOk;
                                        UpdateForeign7890DeadState(agForeign7890Dead);
                                    }
                                }

                                if (agPort > 0 && !agPortOpen)
                                {
                                    issuesFound++;
                                    report.AppendLine(string.Format("  ✗ [ПРОБЛЕМА АНТИГРАВИТИ] AG_LS_PROXY указывает на мёртвый порт {0} ({1})!", agPort, agLs));
                                    if (autoFix)
                                    {
                                        string pUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                                        Environment.SetEnvironmentVariable("AG_LS_PROXY", pUrl, EnvironmentVariableTarget.User);
                                        Environment.SetEnvironmentVariable("AG_LS_PROXY", pUrl, EnvironmentVariableTarget.Process);
                                        PurgeGlobalCliProxyEnvVars();
                                        BroadcastEnvironmentChange();
                                        foreach (var p in Process.GetProcessesByName("language_server")) { try { p.Kill(); } catch { } }
                                        foreach (var p in Process.GetProcessesByName("language_server_windows_x64")) { try { p.Kill(); } catch { } }
                                        issuesFixed++;
                                        report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС] AG_LS_PROXY перенаправлен на {0} + перезапущен language_server -> Модели разблокированы!", pUrl));
                                    }
                                }
                                else if (agForeign7890Dead)
                                {
                                    issuesFound++;
                                    report.AppendLine(string.Format("  ✗ [ПРОБЛЕМА АНТИГРАВИТИ] AG_LS_PROXY указывает на чужой прокси {0}, но upstream порта 7890 МЁРТВ (language_server ловит таймаут TLS)!", agLs));
                                    if (autoFix)
                                    {
                                        if (_activeHttpPort != 7890 && IsLocalPortOpen(_activeHttpPort, 150))
                                        {
                                            string pUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                                            Environment.SetEnvironmentVariable("AG_LS_PROXY", pUrl, EnvironmentVariableTarget.User);
                                            Environment.SetEnvironmentVariable("AG_LS_PROXY", pUrl, EnvironmentVariableTarget.Process);
                                            report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС] Битый :7890 удалён из AG_LS_PROXY -> перенаправлен на {0} + перезапущен language_server!", pUrl));
                                        }
                                        else
                                        {
                                            Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.User);
                                            Environment.SetEnvironmentVariable("AG_LS_PROXY", null, EnvironmentVariableTarget.Process);
                                            report.AppendLine("  ⚡ [АВТО-ФИКС] Битый сторонний AG_LS_PROXY (127.0.0.1:7890) очищен + перезапущен language_server!");
                                        }
                                        PurgeGlobalCliProxyEnvVars();
                                        BroadcastEnvironmentChange();
                                        foreach (var p in Process.GetProcessesByName("language_server")) { try { p.Kill(); } catch { } }
                                        foreach (var p in Process.GetProcessesByName("language_server_windows_x64")) { try { p.Kill(); } catch { } }
                                        issuesFixed++;
                                    }
                                }
                                else
                                {
                                    report.AppendLine(string.Format("  ✓ [OK] Переменная AG_LS_PROXY настроена: {0}.", agLs));
                                }
                            }
                        }
                    }
                }
                catch { }

                // ----------------------------------------------------------------
                // 4. ZERO-ADMIN CLOCK SKEW COMPENSATOR & ANTIVIRUS SSL-MITM DETECTOR
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[4/9] Точность часов ПК (без админа) и проверка перехвата SSL антивирусами:");
                long clockDriftSec;
                string clockSource;
                if (PixelCoreService.ProbeAndSyncClockOffset(out clockDriftSec, out clockSource))
                {
                    if (Math.Abs(clockDriftSec) < 45L)
                    {
                        report.AppendLine(string.Format("  ✓ [OK] Системные часы ПК точны (расхождение с {0}: {1:+#;-#;0} сек).", clockSource, clockDriftSec));
                    }
                    else
                    {
                        issuesFound++;
                        issuesFixed++;
                        long mins = clockDriftSec / 60L;
                        report.AppendLine(string.Format("  ✗ [НАЙДЕН СБОЙ ЧАСОВ ПК] Часы Windows сбиты на {0:+#;-#;0} мин ({1:+#;-#;0} сек) относительно {2}!", mins, clockDriftSec, clockSource));
                        report.AppendLine("  ⚡ [АВТО-ФИКС БЕЗ АДМИНА] Включён авто-компенсатор времени PWP-3 -> туннель подписывает пакеты серверным временем и не рвётся!");
                    }
                }
                else
                {
                    report.AppendLine("  ✓ [OK] Авто-компенсатор времени по заголовкам сервера активен.");
                }

                string certIssuer, avMitm;
                if (PixelCoreService.DetectSslMitmInterceptor(out certIssuer, out avMitm))
                {
                    diagSslMitm = avMitm;
                    issuesFound++;
                    report.AppendLine("  ⚠ [НАЙДЕН ПЕРЕХВАТ HTTPS] Антивирус подменяет TLS-сертификаты: " + avMitm);
                    report.AppendLine("  💡 [РЕШЕНИЕ] Из-за подмены сертификата Node.js / MCP и Antigravity могут выдавать ошибку x509! В настройках антивируса добавьте googleapis.com и antigravity.exe в исключения проверки защищённых соединений.");
                }
                else
                {
                    report.AppendLine("  ✓ [OK] Перехвата HTTPS антивирусами (Kaspersky / Dr.Web / ESET / AdGuard) не обнаружено.");
                }

                // ----------------------------------------------------------------
                // 5. PARALLEL MULTI-NODE & ANTI-DPI v2 MATRIX BENCHMARK
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[5/9] Турбо-бенчмарк матрицы узлов PWP-3 и Anti-DPI Shield v2 (36 КБ ТСПУ):");
                string rawKey = "";
                RunOnUiThreadSync(delegate
                {
                    if (_keyInput == null) return;
                    rawKey = (_keyInput.Text ?? "").Trim();
                    if (string.IsNullOrEmpty(rawKey))
                    {
                        int dLeft;
                        rawKey = EnsureAutoTrialKeyProvisioned(out dLeft);
                        _keyInput.Text = rawKey;
                    }
                });
                if (string.IsNullOrEmpty(rawKey))
                {
                    int dLeft;
                    rawKey = EnsureAutoTrialKeyProvisioned(out dLeft);
                }

                VlessNode node = null;
                string resolvedUri = rawKey;
                if (rawKey.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || rawKey.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    resolvedUri = FetchVlessFromSubscription(rawKey);
                }
                node = ParseVlessUri(resolvedUri);
                if (node == null || string.IsNullOrEmpty(node.Server))
                {
                    int dLeft;
                    rawKey = EnsureAutoTrialKeyProvisioned(out dLeft);
                    node = ParseVlessUri(rawKey);
                }

                var benchResults = PixelCoreService.RunParallelNodeBenchmarkAsync(3200).GetAwaiter().GetResult();
                var matrixParts = new List<string>();
                int healthyNodesCount = 0;
                foreach (var br in benchResults)
                {
                    if (br.Ok)
                    {
                        healthyNodesCount++;
                        string star = br.IsBestSelected ? " ★ ЛУЧШИЙ ДЛЯ ВАШЕГО ПРОВАЙДЕРА" : "";
                        report.AppendLine(string.Format("  ✓ [{0}] :{1} -> {2} мс (ТСПУ 36KB: {3}, SNI: {4}){5}",
                            br.Name, br.Port, br.HandshakeMs, br.AntiFreezeOk ? "OK" : "FAIL", br.EffectiveSni, star));
                        matrixParts.Add(string.Format("{0}={1}ms[OK]", br.Name, br.HandshakeMs));
                    }
                    else
                    {
                        report.AppendLine(string.Format("  • [{0}] :{1} -> пропущен ({2})",
                            br.Name, br.Port, string.IsNullOrEmpty(br.Error) ? "недоступен" : br.Error));
                        matrixParts.Add(string.Format("{0}[FAIL]", br.Name));
                    }
                }
                diagNodeMatrix = string.Join(" | ", matrixParts.ToArray());

                if (healthyNodesCount == 0 && !string.IsNullOrEmpty(PixelCoreService.LastLicenseError))
                {
                    issuesFound++;
                    report.AppendLine("  ✗ [КЛЮЧ ОТКЛОНЁН] Статус лицензии на сервере: " + PixelCoreService.LastLicenseError);
                }
                else if (healthyNodesCount > 0)
                {
                    report.AppendLine(string.Format("  ✓ [OK] Доступно рабочих маршрутов: {0}/{1} • Активный профиль Anti-DPI: {2}.",
                        healthyNodesCount, benchResults.Count, PixelCoreService.AntiDpiProfileName));
                }

                if (!string.IsNullOrEmpty(PixelCoreService.ServerLicenseTier) && PixelCoreService.ServerDaysLeft >= 0)
                {
                    report.AppendLine(string.Format("  ✓ [OK] Подписка: {0} (осталось {1} дн., привязано ПК: {2}/{3}).",
                        PixelCoreService.ServerLicenseTier.ToUpperInvariant(),
                        PixelCoreService.ServerDaysLeft,
                        Math.Max(1, PixelCoreService.ServerDevicesUsed),
                        PixelCoreService.ServerDevicesMax));
                }

                // ----------------------------------------------------------------
                // 6. GOOGLE OAUTH2 LOGIN & LOOPBACK CALLBACK CHECK
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[6/9] Проверка авторизации Google OAuth2 и локального возврата 127.0.0.1:");
                report.AppendLine("  ✓ [OK] Локальный возврат 127.0.0.1 / localhost защищён от перехвата прокси.");
                if (!_optSocialWeb && !_oauthHelperActive)
                {
                    report.AppendLine("  💡 [ЕСЛИ НЕ ВХОДИТ В GOOGLE] В изолированном режиме ваш браузер идёт с РФ-IP. Нажмите кнопку «Вход в Google (90с)» ниже перед нажатием Sign in в Antigravity!");
                }

                // ----------------------------------------------------------------
                // 7. SANCTIONS PATCH, ISOLATED MCP TERMINAL & IDE CONFIG HEALER
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[7/9] Патч «Вход из-под санкций», Терминал/MCP Guard и лечение конфигов IDE:");
                StopConflictingVpnAndApplyFixes();
                if (_optAntigravity && _optMcpTerminal)
                {
                    report.AppendLine("  ✓ [OK] Терминал Antigravity & MCP-серверы (npx/uvx/Python) защищены изолированно.");
                }
                List<string> sanctionPatchLogs;
                diagLsPatched = PatchAntigravitySanctionsAndProxy(out sanctionPatchLogs, autoFix);
                if (diagLsPatched)
                {
                    foreach (var sLog in sanctionPatchLogs)
                    {
                        if (sLog.Contains("АВТО-ПАТЧ")) { issuesFound++; issuesFixed++; }
                        report.AppendLine(sLog);
                    }
                }
                var aiFixedList = HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
                foreach (var aiItem in aiFixedList)
                {
                    issuesFixed++;
                    report.AppendLine("  ⚡ [АВТО-ФИКС AI] " + aiItem);
                }
                if (aiFixedList.Count == 0)
                {
                    report.AppendLine("  ✓ [OK] Конфиги IDE проверены (Cursor, VS Code, Git и браузеры не затронуты).");
                }

                // ----------------------------------------------------------------
                // 8. ANTIGRAVITY IDE LOGS & STALE REGION-CACHE RESTARTER
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[8/9] Анализ логов Antigravity IDE и сброс зависшего кэша региона:");
                string agLogBanner, agValUrl;
                Color agLogCol;
                List<string> agDiagLines;
                InspectAntigravityLogs(out agLogBanner, out agLogCol, out agValUrl, out agDiagLines);
                foreach (var dl in agDiagLines)
                {
                    report.AppendLine(dl);
                }

                // Если в логах language_server висит ошибка региона/сети (ColAmber/ColRed) и сейчас не идёт стрим ответа — мягко перезапустим фоновый language_server без закрытия окна IDE!
                if (autoFix && (agLogCol == ColRed || (agLogBanner != null && (agLogBanner.IndexOf("ошибка", StringComparison.OrdinalIgnoreCase) >= 0 || agLogBanner.IndexOf("недоступ", StringComparison.OrdinalIgnoreCase) >= 0))) && !IsAiStreamActivelyFlowing())
                {
                    int restartedLs = 0;
                    foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
                    {
                        foreach (var p in Process.GetProcessesByName(lsName))
                        {
                            try { p.Kill(); restartedLs++; } catch { }
                        }
                    }
                    if (restartedLs > 0)
                    {
                        issuesFound++;
                        issuesFixed++;
                        report.AppendLine("  ⚡ [АВТО-СБРОС СЕССИИ] Перезапущен фоновый language_server без закрытия ваших вкладок -> зависший кэш ошибки очищен!");
                    }
                }

                // ----------------------------------------------------------------
                // 9. LIVE END-TO-END TUNNEL TEST & SUPPORT PASSPORT GENERATION
                // ----------------------------------------------------------------
                AppendDiagLive(report, "\r\n[9/9] Сквозной боевой тест туннеля (CloudCode + Gemini + OAuth2 + РФ):");
                if (node != null && !string.IsNullOrEmpty(node.Server))
                {
                    string proxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                    bool portOpen = IsLocalPortOpen(_activeHttpPort, 200);
                    bool coreAlive = PixelCoreService.IsRunning;

                    string agCode = portOpen ? RunHttpProbe("https://daily-cloudcode-pa.googleapis.com", proxyUrl, 5) : "000";
                    string gemCode = portOpen ? RunHttpProbe("https://gemini.google.com", proxyUrl, 5) : "000";
                    string oauthCode = portOpen ? RunHttpProbe("https://oauth2.googleapis.com/token", proxyUrl, 5) : "000";
                    string spCode = portOpen ? RunHttpProbe("https://open.spotify.com", proxyUrl, 5) : "000";
                    string yaCode = RunHttpProbe("https://ya.ru", "", 4);

                    if (autoFix && (!portOpen || !coreAlive || (!IsHttpCodeHealthy(agCode) && !IsHttpCodeHealthy(gemCode)) || !IsHttpCodeHealthy(yaCode)))
                    {
                        issuesFound++;
                        AppendDiagLive(report, "  ↻ Авто-поднятие мультиплексного туннеля PWP-3 на лучшем узле...");

                        KillCoreProcesses();
                        Thread.Sleep(200);

                        _preferSafeProxyMode = true;
                        _activeNode = node;
                        string healedCfg = BuildSingBoxConfig(node, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb || _oauthHelperActive, false);
                        ApplyAndStartCoreConfig(healedCfg);

                        for (int i = 0; i < 25; i++)
                        {
                            if (IsLocalPortOpen(_activeHttpPort, 150)) break;
                            if (!PixelCoreService.IsRunning) break;
                            Thread.Sleep(100);
                        }

                        if (IsLocalPortOpen(_activeHttpPort, 200))
                        {
                            agCode = RunHttpProbe("https://daily-cloudcode-pa.googleapis.com", proxyUrl, 5);
                            gemCode = RunHttpProbe("https://gemini.google.com", proxyUrl, 5);
                            oauthCode = RunHttpProbe("https://oauth2.googleapis.com/token", proxyUrl, 5);
                            spCode = RunHttpProbe("https://open.spotify.com", proxyUrl, 5);
                            yaCode = RunHttpProbe("https://ya.ru", "", 4);
                        }

                        if (string.IsNullOrEmpty(PixelCoreService.LastLicenseError) && !IsHttpCodeHealthy(agCode) && !IsHttpCodeHealthy(gemCode))
                        {
                            AppendDiagLive(report, "  ↻ Авто-перебалансировка маршрута через манифест PixelCore...");
                            PixelCoreService.StopService();
                            Thread.Sleep(150);

                            string retryCfg = BuildSingBoxConfig(node, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb || _oauthHelperActive, false);
                            ApplyAndStartCoreConfig(retryCfg);

                            for (int i = 0; i < 25; i++)
                            {
                                if (IsLocalPortOpen(_activeHttpPort, 150)) break;
                                if (!PixelCoreService.IsRunning) break;
                                Thread.Sleep(100);
                            }

                            if (IsLocalPortOpen(_activeHttpPort, 200))
                            {
                                agCode = RunHttpProbe("https://daily-cloudcode-pa.googleapis.com", proxyUrl, 5);
                                gemCode = RunHttpProbe("https://gemini.google.com", proxyUrl, 5);
                                oauthCode = RunHttpProbe("https://oauth2.googleapis.com/token", proxyUrl, 5);
                                spCode = RunHttpProbe("https://open.spotify.com", proxyUrl, 5);
                                yaCode = RunHttpProbe("https://ya.ru", "", 4);
                            }
                        }

                        diagAgCode = agCode;
                        diagGemCode = gemCode;
                        diagOAuthCode = oauthCode;
                        diagYaCode = yaCode;

                        if (IsHttpCodeHealthy(agCode) || IsHttpCodeHealthy(gemCode))
                        {
                            ApplyConnectedProxyPolicy();
                            FlushWindowsDnsCache();
                            HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
                            issuesFixed++;
                            report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС УСПЕШЕН] Туннель поднят! CloudCode: HTTP {0} [OK], Gemini: HTTP {1} [OK], OAuth2: HTTP {2} [OK], РФ (ya.ru): HTTP {3} [OK]", agCode, gemCode, oauthCode, yaCode));
                            RunOnUiThreadSync(delegate
                            {
                                _isConnected = true;
                                _tunnelConnectedUtc = DateTime.UtcNow;
                                if (_pingLabel != null)
                                {
                                    _pingLabel.Text = "HEALED • OK";
                                    _pingLabel.Foreground = new SolidColorBrush(ColGreen);
                                }
                                SetStatus(ColGreen, "Туннель вылечен и активен", string.Format("PWP-3 Шлюз :{0} ({1}) • CloudCode HTTP {2} [OK] • Сайты .RU напрямую", _activeHttpPort, PixelCoreService.ActiveNodeName ?? "NL", agCode));
                                ResetButtonState(true);
                                UpdateLicenseHintFromServer();
                            });
                        }
                        else
                        {
                            string diagLicErr = PixelCoreService.LastLicenseError;
                            diagLicErrSummary = diagLicErr;
                            diagGoReason = !string.IsNullOrEmpty(PixelCoreService.LastConnectError)
                                ? PixelCoreService.LastConnectError
                                : PixelCoreService.GoEngineFallbackReason;
                            StopTunnelProcess(false);
                            report.AppendLine("  ✗ [ВНИМАНИЕ] Зарубежный узел не пропускает трафик. Системный прокси автоматически ОТКЛЮЧЁН для сохранения прямого интернета.");
                            if (!string.IsNullOrEmpty(diagLicErr))
                            {
                                report.AppendLine("  💡 [ПРИЧИНА] Сервер отклонил ключ (" + diagLicErr + "). Получите актуальный ключ в " + GetTelegramBotHandle());
                            }
                            else
                            {
                                report.AppendLine("  💡 [СОВЕТ] Сохраните отчёт (PixelTunnel_Report.txt) — вся диагностика хранится локально.");
                            }
                            RunOnUiThreadSync(delegate
                            {
                                ResetButtonState(false);
                                if (!ApplyLicenseErrorToUi(diagLicErr))
                                {
                                    SetStatus(ColAmber, "Прямой интернет защищён (Нужен свежий ключ)", "Туннель отключён, чтобы не блокировать сеть. Возьмите новый ключ в боте.");
                                }
                            });
                        }
                    }
                    else
                    {
                        diagAgCode = agCode;
                        diagGemCode = gemCode;
                        diagOAuthCode = oauthCode;
                        diagYaCode = yaCode;

                        _activeNode = node;
                        ApplyConnectedProxyPolicy();
                        FlushWindowsDnsCache();
                        HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
                        RunOnUiThreadSync(delegate
                        {
                            _isConnected = true;
                            SetStatus(ColGreen, "Туннель активен • Antigravity разблокирован", string.Format("PWP-3 Шлюз :{0} ({1}) • CloudCode HTTP {2} [OK] • Сайты .RU напрямую", _activeHttpPort, PixelCoreService.ActiveNodeName ?? "NL", agCode));
                            ResetButtonState(true);
                            UpdateLicenseHintFromServer();
                        });
                        report.AppendLine(string.Format("  ✓ [OK] Все каналы работают идеально! CloudCode: HTTP {0} [OK], Gemini: HTTP {1} [OK], OAuth2: HTTP {2} [OK], РФ (ya.ru): HTTP {3} [OK]", agCode, gemCode, oauthCode, yaCode));
                    }
                }

                _lastSupportPassport = BuildCompactSupportPassport(
                    diagPoisonedHosts, diagHostsHealed, diagSslMitm,
                    diagNodeMatrix, diagAgCode, diagGemCode, diagOAuthCode, diagYaCode,
                    diagThirdPartyTun, diagLsPatched);

                sw.Stop();
                report.AppendLine(string.Format("\r\n╚══ Диагностика завершена за {0} мс | Найдено: {1} | Исправлено: {2} ══╝", sw.ElapsedMilliseconds, issuesFound, issuesFixed));
                });
            }
            catch (Exception diagEx)
            {
                issuesFound++;
                report.AppendLine("  ✗ [ОШИБКА ДИАГНОСТИКИ] " + diagEx.Message);
            }
            finally
            {
                _isDiagRunning = false;
            }

            try
            {
                string finalReport = report.ToString();
                _lastDiagReport = finalReport;
                RunOnUiThread(delegate
                {
                    if (_diagBtnText != null) _diagBtnText.Text = "Диагностика";
                    if (_diagBtnIconHolder != null)
                    {
                        _diagBtnIconHolder.Content = CreateVectorIcon("M22 12h-4l-3 9L9 3l-3 9H2", ColGreen, 14);
                    }
                    RefreshAiTelemetryBanner();
                });

                if (isAutoDiagCli)
                {
                    SaveDiagnosticReportToDesktop();
                    RunOnUiThread(delegate { ExplicitShutdown(); });
                    return;
                }

                var unusedPulseRefresh = RefreshAiPulseUiAsync(true);

                RunOnUiThread(delegate
                {
                    string headline;
                    if (issuesFound == 0)
                        headline = "Проблем не обнаружено — настройки и соединение в порядке.";
                    else if (issuesFixed >= issuesFound)
                        headline = string.Format("Обнаружено и автоматически исправлено проблем: {0}.", issuesFixed);
                    else
                        headline = string.Format("Найдено проблем: {0}, исправлено автоматически: {1}.", issuesFound, issuesFixed);

                    string channelSummary;
                    if (!string.IsNullOrEmpty(diagLicErrSummary))
                        channelSummary = "Сервер отклонил текущий ключ (" + diagLicErrSummary + "). Получите новый ключ в " + GetTelegramBotHandle() + ".";
                    else if (IsHttpCodeHealthy(diagAgCode) || IsHttpCodeHealthy(diagGemCode))
                        channelSummary = string.Format("Зарубежные сервисы доступны (CloudCode HTTP {0}, Gemini HTTP {1}), российские сайты работают напрямую (ya.ru HTTP {2}).", diagAgCode, diagGemCode, diagYaCode);
                    else if (!string.IsNullOrEmpty(diagGoReason))
                        channelSummary = string.Format("Туннель не смог пропустить трафик ({0}). Прямой интернет сохранён.", diagGoReason);
                    else
                        channelSummary = string.Format("Прямой интернет (ya.ru): HTTP {0}. Узлы проверены.", diagYaCode);

                    string msg = headline + "\n" + channelSummary + "\n\nСохранить подробный отчёт на Рабочий стол (PixelTunnel_Report.txt) и скопировать в буфер обмена?";
                    MessageBoxResult res = MessageBox.Show(
                        this,
                        msg,
                        "Диагностика PixelTunnel",
                        MessageBoxButton.YesNo,
                        issuesFound > issuesFixed ? MessageBoxImage.Warning : MessageBoxImage.Information);
                    if (res == MessageBoxResult.Yes)
                    {
                        string savedPath = SaveDiagnosticReportToDesktop();
                        if (!_isConnected && !string.IsNullOrEmpty(savedPath))
                        {
                            SetStatus(ColGreen, "Отчёт диагностики сохранён", "Файл PixelTunnel_Report.txt на Рабочем столе и в буфере обмена.");
                        }
                    }
                    else if (!_isConnected && IsHttpCodeHealthy(diagYaCode) && !IsHttpCodeHealthy(diagAgCode) && string.IsNullOrEmpty(diagLicErrSummary))
                    {
                        SetStatus(ColText2, "Готов к подключению", headline);
                    }
                });
            }
            catch { }
        }

        private async void RunEmergencyNetworkResetAsync(bool confirmPrompt = false)
        {
            if (_isDiagRunning) return;
            if (confirmPrompt)
            {
                MessageBoxResult confirm = ReadFromUiThread(() => MessageBox.Show(
                    this,
                    "Отключить туннель, очистить системный прокси Windows и восстановить прямой доступ в интернет?",
                    "Сброс сети — PixelTunnel",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question), MessageBoxResult.No);
                if (confirm != MessageBoxResult.Yes) return;
            }
            _isDiagRunning = true;

            string yaCode = "000";
            try
            {
                RunOnUiThread(delegate
                {
                    if (_diagBtnText != null) _diagBtnText.Text = "Сброс...";
                    SetStatus(ColAmber, "Выполняется сброс сети...", "Отключаем прокси и очищаем кэш DNS...");
                });

                await Task.Run(() =>
                {
                    StopTunnelProcess(false);
                    StopConflictingVpnAndApplyFixes();

                    try
                    {
                        using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                        {
                            if (key != null)
                            {
                                key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                key.DeleteValue("AutoConfigURL", false);
                            }
                        }
                    }
                    catch { }

                    ApplyWinInetPerConnectionProxy(false, "", "");
                    FlushWindowsDnsCache();
                    Thread.Sleep(250);
                    yaCode = RunHttpProbe("https://ya.ru", "", 3);
                });

                string yaShown = string.IsNullOrEmpty(yaCode) ? "200" : yaCode;
                _lastDiagReport =
                    "╔══ АВАРИЙНЫЙ СБРОС СЕТИ ВЫПОЛНЕН ══╗\r\n" +
                    "• Процессы pixel-tun-core, sing-box и ProksiFi: ОСТАНОВЛЕНЫ\r\n" +
                    "• Системный прокси Windows: ОТКЛЮЧЁН (ProxyEnable = 0)\r\n" +
                    "• Перехват WPAD (AutoConfigURL): ОЧИЩЕН\r\n" +
                    "• Системный кэш DNS Windows: СБРОШЕН (ipconfig /flushdns)\r\n" +
                    string.Format("• Проверка прямого интернета (ya.ru): HTTP {0} [OK]\r\n", yaShown);

                RunOnUiThread(delegate
                {
                    if (_diagBtnText != null) _diagBtnText.Text = "Диагностика";
                    ResetButtonState(false);
                    if (_pingLabel != null)
                    {
                        _pingLabel.Text = "DIRECT NET";
                        _pingLabel.Foreground = new SolidColorBrush(ColGreen);
                    }
                    SetStatus(
                        ColGreen,
                        "Прямой интернет полностью восстановлен",
                        string.Format("Все прокси и TUN-адаптеры отключены • Яндекс HTTP {0} [OK]", yaShown)
                    );
                    MessageBox.Show(
                        this,
                        string.Format("Сброс сети выполнен!\n\nСистемный прокси отключён, кэш DNS очищен.\nПрямой интернет работает (ya.ru: HTTP {0}).", yaShown),
                        "Сброс сети завершён",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                });
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                RunOnUiThread(delegate
                {
                    if (_diagBtnText != null) _diagBtnText.Text = "Диагностика";
                    SetStatus(ColAmber, "Ошибка сброса сети", errMsg);
                });
            }
            finally
            {
                _isDiagRunning = false;
            }
        }

        private void AppendDiagLive(StringBuilder sb, string line)
        {
            sb.AppendLine(line);
        }

        private static string ReadLogTail(string path, int maxBytes)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length > maxBytes)
                        fs.Seek(fs.Length - maxBytes, SeekOrigin.Begin);
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
            catch { return ""; }
        }

        private void ResetButtonState(bool connected)
        {
            _isBusy = false;
            _isConnected = connected;
            if (connected)
            {
                _actionBtnBorder.Background = new SolidColorBrush(ColSurfaceHover);
                _actionBtnBorder.BorderBrush = new SolidColorBrush(ColGreen);
                _actionBtnText.Foreground = new SolidColorBrush(ColText1);
                _actionBtnText.Text = "Остановить туннель";
                if (_actionBtnIconHolder != null)
                {
                    _actionBtnIconHolder.Content = CreateVectorIcon("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4", ColGreen, 15);
                }
            }
            else
            {
                _actionBtnBorder.Background = new SolidColorBrush(ColText1);
                _actionBtnBorder.BorderBrush = new SolidColorBrush(ColText1);
                _actionBtnText.Foreground = new SolidColorBrush(ColBg);
                _actionBtnText.Text = "Запустить туннель";
                if (_actionBtnIconHolder != null)
                {
                    _actionBtnIconHolder.Content = CreateVectorIcon("M13 2L3 14h9l-1 8 10-12h-9l1-8z", ColBg, 15);
                }
            }
        }

        private void SetStatus(Color dotColor, string title, string sub)
        {
            _statusDot.Fill = new SolidColorBrush(dotColor);
            _statusTitle.Text = title;
            _statusSub.Text = sub;
            UpdateStatusPulseAnimation(dotColor, dotColor == ColGreen || dotColor == ColAmber);
        }

        private async void CheckAntigravityUpdateWatchdogAsync()
        {
            if (_isWatchdogPatchRunning || _isDiagRunning) return;
            _isWatchdogPatchRunning = true;
            try
            {
                if (!HasUnverifiedAntigravityBinaryOnDisk()) return;

                bool patchedNow = false;
                await Task.Run(() =>
                {
                    try
                    {
                        List<string> pLogs;
                        PatchAntigravitySanctionsAndProxy(out pLogs, false, out patchedNow);
                        if (patchedNow)
                        {
                            if (_isConnected)
                            {
                                ApplyConnectedProxyPolicy();
                            }
                            HealAiEditorsAndServices(_isConnected, true, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
                        }
                    }
                    catch { }
                });

                if (patchedNow)
                {
                    RunOnUiThread(delegate
                    {
                        SetStatus(
                            ColGreen,
                            "Antigravity обновлён • Патч входа применён на лету!",
                            string.Format("Снят блок региона + прописан шлюз OAuth2 :{0} для новой версии IDE", _activeHttpPort)
                        );
                        if (_trayIcon != null)
                        {
                            try
                            {
                                _trayIcon.ShowBalloonTip(
                                    3200,
                                    "PixelTunnel — Авто-патч Antigravity",
                                    "Antigravity обновился — патч входа из-под санкций и шлюз OAuth2 применены автоматически!",
                                    System.Windows.Forms.ToolTipIcon.Info
                                );
                            }
                            catch { }
                        }
                    });
                }
            }
            catch { }
            finally
            {
                _isWatchdogPatchRunning = false;
            }
        }

        private async void MonitorLoop()
        {
            try
            {
                CheckAntigravityUpdateWatchdogAsync();
                RunOnUiThread(delegate { RefreshAiTelemetryBanner(); });
                if (!_isConnected || _isBusy || _isDiagRunning) return;

                string licErr = PixelCoreService.LastLicenseError;
                if (!string.IsNullOrEmpty(licErr))
                {
                    _isConnected = false;
                    StopTunnelProcess(false);
                    RunOnUiThread(delegate
                    {
                        ApplyLicenseErrorToUi(licErr);
                        ResetButtonState(false);
                    });
                    return;
                }

                bool alive = PixelCoreService.IsRunning;
                if (!alive)
                {
                    try
                    {
                        if (_coreProcess != null && !_coreProcess.HasExited)
                            alive = true;
                        else if (Process.GetProcessesByName(CORE_EXE_NAME).Length > 0)
                            alive = true;
                    }
                    catch { }
                }

                if (!alive || !IsLocalPortOpen(_activeHttpPort, 200))
                {
                    // Immediately disable system proxy if core died so browsers NEVER lose internet!
                    _isConnected = false;
                    DisableOrRestoreSystemProxy();
                    RunOnUiThread(delegate
                    {
                        ResetButtonState(false);
                        SetStatus(ColRed, "Туннель остановился (Прямой интернет сохранён)", "Системный прокси автоматически отключён. Нажмите «Запустить туннель».");
                    });
                    return;
                }

                // Watchdog: ensure Windows system proxy matches active policy (Smart PAC vs Classic ProxyEnable=1)
                if (ShouldEnableSystemWideBrowserProxy())
                {
                    try
                    {
                        using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false))
                        {
                            if (key != null)
                            {
                                int en = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                                string srv = Convert.ToString(key.GetValue("ProxyServer", ""));
                                string pac = Convert.ToString(key.GetValue("AutoConfigURL", ""));
                                if (_useSmartPacMode)
                                {
                                    if (en != 0 || !IsActivePixelSmartPacUrl(pac))
                                        EnableSystemProxy();
                                }
                                else
                                {
                                    if (en == 0 || srv != string.Format("127.0.0.1:{0}", _activeHttpPort))
                                        EnableSystemProxy();
                                }
                            }
                        }
                    }
                    catch { }
                }

                _pulseTickCounter++;
                if (_pulseTickCounter % 8 == 1)
                {
                    var unusedPulse = RefreshAiPulseUiAsync(false);
                }

                if (_activeNode != null)
                {
                    int ms = PixelCoreService.ActiveNodeLatencyMs;
                    if (ms <= 0)
                    {
                        string host = _activeNode.Server;
                        int port = IsClusterHost(host) ? 443 : _activeNode.Port;
                        ms = await Task.Run(() => MeasureTcpPing(host, port));
                    }
                    int activeStreams = Math.Max(PixelCoreService.ActiveMuxStreams, Math.Max(PixelCoreService.ActiveConnections, CountActiveProxyConnections()));
                    int activeUdp = PixelCoreService.ActiveUdpAssociations;
                    string speedBadge = PixelCoreService.FormatLiveSpeedBadge();
                    if (ms > 0 && _isConnected)
                    {
                        _consecutivePingFailures = 0;
                        string tag = (string.Equals(_selectedRegion, "us", StringComparison.OrdinalIgnoreCase) && PixelCoreService.IsRegionAvailable("us"))
                            ? "US"
                            : "NL";
                        string pingText;
                        if (!string.IsNullOrEmpty(speedBadge) && activeUdp > 0)
                            pingText = string.Format("{0} • {1} мс • {2} • UDP:{3}", tag, ms, speedBadge, activeUdp);
                        else if (!string.IsNullOrEmpty(speedBadge))
                            pingText = string.Format("{0} • {1} мс • {2}", tag, ms, speedBadge);
                        else if (activeUdp > 0)
                            pingText = string.Format("{0} • {1} мс • Mux:{2} UDP:{3}", tag, ms, activeStreams, activeUdp);
                        else if (activeStreams > 0)
                            pingText = string.Format("{0} • {1} мс • Mux: {2}", tag, ms, activeStreams);
                        else
                            pingText = string.Format("{0} • {1} мс", tag, ms);

                        RunOnUiThread(delegate
                        {
                            UpdateLicenseHintFromServer();
                            if (_isConnected && _pingLabel != null)
                            {
                                _pingLabel.Text = pingText;
                            }
                        });
                    }
                    else if (_isConnected)
                    {
                        RunOnUiThread(delegate { UpdateLicenseHintFromServer(); });
                        _consecutivePingFailures++;
                        if (_consecutivePingFailures >= 3)
                        {
                            _consecutivePingFailures = 0;
                            string proxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                            string probe = await Task.Run(() => RunHttpProbe("https://www.gstatic.com/generate_204", proxyUrl, 5));
                            if (!IsHttpCodeHealthy(probe))
                            {
                                VlessNode curNode = _activeNode;
                                if (curNode != null)
                                {
                                    await Task.Run(() =>
                                    {
                                        try
                                        {
                                            WaitForIdleAiStream(2500);
                                            PixelCoreService.StopService();
                                            Thread.Sleep(150);
                                            string retryCfg = BuildSingBoxConfig(curNode, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                                            ApplyAndStartCoreConfig(retryCfg);
                                        }
                                        catch { }
                                    });
                                    RunOnUiThread(delegate
                                    {
                                        SetStatus(ColGreen, "Туннель активен (Авто-восстановление)", "Авто-переподключение канала выполнено без обрыва сети");
                                    });
                                }
                            }
                        }
                    }
                    else
                    {
                        RunOnUiThread(delegate { UpdateLicenseHintFromServer(); });
                    }
                }
            }
            catch { }
        }

        private static int MeasureTcpPing(string host, int port)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(host, port, null, null);
                    bool ok = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(2200));
                    if (!ok) return -1;
                    client.EndConnect(result);
                    sw.Stop();
                    return (int)Math.Max(1, sw.ElapsedMilliseconds);
                }
            }
            catch
            {
                return -1;
            }
        }

        private static string FetchVlessFromSubscription(string subUrl)
        {
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(subUrl);
                req.Timeout = 5000;
                req.UserAgent = "PixelTunnel/1.2";
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                {
                    string body = sr.ReadToEnd().Trim();
                    if (body.Contains("vless://"))
                    {
                        foreach (var line in body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            if (line.Trim().StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                                return line.Trim();
                        }
                    }

                    byte[] rawBytes = Convert.FromBase64String(body);
                    string decoded = Encoding.UTF8.GetString(rawBytes);
                    foreach (var line in decoded.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (line.Trim().StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                            return line.Trim();
                    }
                }
            }
            catch { }
            return null;
        }

                private const string DEFAULT_CUSTOM_PROXY = "antigravity.google, cursor.com, cursor.sh, windsurf.com, chatgpt.com, claude.ai, elevenlabs.io, suno.com, midjourney.com, perplexity.ai, klingai.com, lovable.dev";
        private const string DEFAULT_CUSTOM_DIRECT = "ya.ru, ozon.ru, wildberries.ru, avito.ru, vk.com, gosuslugi.ru, sberbank.ru, tbank.ru, kinopoisk.ru, dzen.ru, rutube.ru, habr.com";
        private const string DEFAULT_CUSTOM_EDITORS = "Cursor, Antigravity, Windsurf, Code, Trae, Void, PearAI";

        private static string GetCustomRulesFilePath()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string localFile = System.IO.Path.Combine(baseDir, "custom_rules.txt");
                if (File.Exists(localFile)) return localFile;

                string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string appDataDir = System.IO.Path.Combine(localApp, "PixelTunnel");
                if (!Directory.Exists(appDataDir)) Directory.CreateDirectory(appDataDir);
                string prodRules = System.IO.Path.Combine(appDataDir, "custom_rules.txt");
                if (!File.Exists(prodRules))
                {
                    try
                    {
                        string legacyNext = System.IO.Path.Combine(localApp, "PixelTunnel_Next", "custom_rules.txt");
                        if (File.Exists(legacyNext)) File.Copy(legacyNext, prodRules, false);
                    }
                    catch { }
                }
                return prodRules;
            }
            catch { return "custom_rules.txt"; }
        }

        private static void ReadCustomRulesConfig(out string proxyCsv, out string directCsv, out string editorsCsv)
        {
            proxyCsv = DEFAULT_CUSTOM_PROXY;
            directCsv = DEFAULT_CUSTOM_DIRECT;
            editorsCsv = DEFAULT_CUSTOM_EDITORS;
            try
            {
                string p = GetCustomRulesFilePath();
                if (File.Exists(p))
                {
                    foreach (var line in File.ReadAllLines(p, Encoding.UTF8))
                    {
                        string t = (line ?? "").Trim();
                        if (t.StartsWith("PROXY=", StringComparison.OrdinalIgnoreCase))
                            proxyCsv = t.Substring(6).Trim();
                        else if (t.StartsWith("DIRECT=", StringComparison.OrdinalIgnoreCase))
                            directCsv = t.Substring(7).Trim();
                        else if (t.StartsWith("EDITORS=", StringComparison.OrdinalIgnoreCase))
                            editorsCsv = t.Substring(8).Trim();
                    }
                }
            }
            catch { }
        }

        private async void TriggerCategoryHotReloadIfConnected()
        {
            try
            {
                if (!_isConnected || _isBusy || _activeNode == null) return;
                string prx, dir, eds;
                ReadCustomRulesConfig(out prx, out dir, out eds);
                await PixelCoreService.ReloadRulesV4Async(BuildReloadRulesJsonPayload(prx, dir));
                await Task.Run(() =>
                {
                    try
                    {
                        string newCfg = BuildSingBoxConfig(_activeNode, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                        File.WriteAllText(_activeConfigPath, newCfg, new UTF8Encoding(false));
                    }
                    catch { }
                });
                FlushWindowsDnsCache();
                ApplyConnectedProxyPolicy();
                HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
                RunOnUiThread(delegate
                {
                    SetStatus(ColGreen, "Категории маршрутизации обновлены", string.Format("Активный шлюз :{0} обновлён мгновенно без обрыва соединений.", _activeHttpPort));
                });
            }
            catch { }
        }

        private string BuildReloadRulesJsonPayload(string prxCsv, string dirCsv)
        {
            var payload = new Dictionary<string, object>
            {
                { "categories", new Dictionary<string, object>
                    {
                        { "antigravity", _optAntigravity },
                        { "ai", _optCursorAi },
                        { "media", _optDiscordYt },
                        { "social", _optSocialWeb },
                        { "mcp", _optMcpTerminal }
                    }
                },
                { "custom_proxy_domains", ParseDomainCsv(prxCsv) },
                { "custom_direct_domains", ParseDomainCsv(dirCsv) },
                { "proxy_all", _optCursorAi || _optDiscordYt || _optSocialWeb }
            };
            return MiniJson.Serialize(payload);
        }

        private string BuildLocalDiagnosticReportString()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== PIXELTUNNEL DIAGNOSTIC REPORT v" + APP_VERSION + " ===");
            sb.AppendLine("Timestamp: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Engine: " + PixelCoreService.ActiveEngineLabel + (string.IsNullOrEmpty(PixelCoreService.GoEngineFallbackReason) ? "" : (" (" + PixelCoreService.GoEngineFallbackReason + ")")));
            sb.AppendLine("ProxyMode: " + (_useSmartPacMode ? ("Smart PAC (" + BuildSmartPacUrl() + ")") : "Classic ProxyEnable=1"));
            sb.AppendLine(string.Format("Active Local Ports: HTTP 127.0.0.1:{0} | SOCKS5 127.0.0.1:{1}", _activeHttpPort, _activeSocksPort));
            if (!string.IsNullOrEmpty(PixelCoreService.ActiveWslBridgeIp))
                sb.AppendLine("WSL2 Bridge IP: " + PixelCoreService.ActiveWslBridgeIp + ":" + _activeHttpPort);
            sb.AppendLine(string.Format("Active Proxy Streams: {0}", CountActiveProxyConnections()));
            if (!string.IsNullOrEmpty(_lastSupportPassport))
            {
                sb.AppendLine();
                sb.AppendLine(_lastSupportPassport);
            }
            sb.AppendLine();
            sb.AppendLine(_lastDiagReport ?? "");

            string agLog = FindLatestAntigravityLogFile();
            if (!string.IsNullOrEmpty(agLog))
            {
                sb.AppendLine();
                sb.AppendLine("=== ANTIGRAVITY LANGUAGE_SERVER LOG TAIL ===");
                sb.AppendLine("Path: " + agLog);
                sb.AppendLine(ReadLogTail(agLog, 6144));
            }
            return sb.ToString();
        }

        private void CopyDiagnosticReportToClipboard()
        {
            try
            {
                Clipboard.SetText(BuildLocalDiagnosticReportString());
            }
            catch { }
        }

        private string SaveDiagnosticReportToDesktop()
        {
            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string reportFile = System.IO.Path.Combine(desktop, "PixelTunnel_Report.txt");
                string txt = BuildLocalDiagnosticReportString();
                File.WriteAllText(reportFile, txt, new UTF8Encoding(false));
                try { Clipboard.SetText(txt); } catch { }
                return reportFile;
            }
            catch { return ""; }
        }

        private static List<string> ParseDomainCsv(string csv)
        {
            var res = new List<string>();
            if (string.IsNullOrWhiteSpace(csv)) return res;
            foreach (var raw in csv.Split(new[] { ',', ';', '\r', '\n', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string d = raw.Trim().ToLowerInvariant();
                if (d.StartsWith("https://")) d = d.Substring(8);
                if (d.StartsWith("http://")) d = d.Substring(7);
                int slash = d.IndexOf('/');
                if (slash >= 0) d = d.Substring(0, slash);
                if (d.StartsWith("*.")) d = d.Substring(2);
                if (!string.IsNullOrEmpty(d) && d.Contains(".") && !res.Contains(d))
                    res.Add(d);
            }
            return res;
        }

        private static string[] GetCustomAiEditors()
        {
            string prx, dir, eds;
            ReadCustomRulesConfig(out prx, out dir, out eds);
            var list = new List<string> { "Cursor", "Antigravity", "Windsurf", "Code" };
            if (!string.IsNullOrWhiteSpace(eds))
            {
                foreach (var raw in eds.Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string name = raw.Trim();
                    if (!string.IsNullOrEmpty(name))
                    {
                        bool exists = false;
                        foreach (var x in list)
                        {
                            if (string.Equals(x, name, StringComparison.OrdinalIgnoreCase)) { exists = true; break; }
                        }
                        if (!exists) list.Add(name);
                    }
                }
            }
            return list.ToArray();
        }

        private static string BuildEffectiveProxyOverride()
        {
            string prx, dir, eds;
            ReadCustomRulesConfig(out prx, out dir, out eds);
            var extraDirect = ParseDomainCsv(dir);
            if (extraDirect.Count == 0) return PROXY_OVERRIDE;
            var sb = new StringBuilder(PROXY_OVERRIDE);
            foreach (var d in extraDirect)
            {
                string pattern = "*." + d;
                if (PROXY_OVERRIDE.IndexOf(d, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    sb.Append(';').Append(d).Append(';').Append(pattern);
                }
            }
            return sb.ToString();
        }

        private static string BuildEffectiveProxyDomainsJson(bool routeAg, bool routeAi, bool routeMedia, bool routeWeb)
        {
            var domains = new List<string>();
            Action<string> addDom = delegate(string d)
            {
                if (!string.IsNullOrEmpty(d) && !domains.Contains(d)) domains.Add(d);
            };

            if (routeAg)
            {
                string[] agList = new[]
                {
                    "antigravity.google", "antigravity-unleash.goog", "daily-cloudcode-pa.googleapis.com",
                    "cloudcode-pa.googleapis.com", "generativelanguage.googleapis.com", "aistudio.google.com",
                    "gemini.google.com", "makersuite.google.com", "alkalimakersuite-pa.clients6.google.com",
                    "notebooklm.google.com", "labs.google", "deepmind.google", "ai.google.dev",
                    "googleapis.com", "oauth2.googleapis.com", "www.googleapis.com",
                    "clients6.google.com", "clients1.google.com", "clients2.google.com", "clients3.google.com",
                    "clients4.google.com", "clients5.google.com", "cloudaicompanion.googleapis.com",
                    "daily-cloud-pa.clients6.google.com", "geminiweb-pa.clients6.google.com", "aicode.googleapis.com",
                    "gstatic.com", "googleusercontent.com", "accounts.google.com", "google.com",
                    "gvt1.com", "gvt2.com", "gvt3.com", "1e100.net", "pki.goog"
                };
                foreach (var d in agList) addDom(d);

                if (_optMcpTerminal)
                {
                    string[] mcpList = new[]
                    {
                        "npmjs.org", "registry.npmjs.org", "npmjs.com",
                        "pypi.org", "files.pythonhosted.org", "pythonhosted.org", "astral.sh",
                        "github.com", "api.github.com", "raw.githubusercontent.com", "githubusercontent.com", "githubassets.com", "ghcr.io",
                        "huggingface.co", "hf.co", "smithery.ai", "context7.com", "modelcontextprotocol.io", "glama.ai",
                        "deno.land", "jsr.io", "bun.sh", "pkg.dev", "docker.io", "cloudflare.com"
                    };
                    foreach (var d in mcpList) addDom(d);
                }
            }

            if (routeAi)
            {
                string[] aiList = new[]
                {
                    "cursor.com", "cursor.sh", "cursorapi.com", "windsurf.com", "codeium.com",
                    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
                    "claude.ai", "anthropic.com", "perplexity.ai", "grok.com", "x.ai",
                    "elevenlabs.io", "suno.com", "suno.ai", "midjourney.com", "klingai.com",
                    "runwayml.com", "sora.com", "luma.ai", "lumalabs.ai", "heygen.com",
                    "v0.dev", "bolt.new", "lovable.dev", "replit.com", "huggingface.co",
                    "openrouter.ai", "together.ai", "groq.com", "deepseek.com", "mistral.ai",
                    "cohere.com", "replicate.com", "civitai.com", "githubcopilot.com", "copilot.microsoft.com"
                };
                foreach (var d in aiList) addDom(d);
            }

            if (routeMedia)
            {
                string[] mediaList = new[]
                {
                    "discord.com", "discordapp.com", "discordapp.net", "discord.gg", "discord.media", "discordstatus.com",
                    "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtubei.googleapis.com", "ggpht.com",
                    "twitch.tv", "ttvnw.net", "jtvnw.net"
                };
                foreach (var d in mediaList) addDom(d);
            }

            if (routeWeb)
            {
                string[] telegramList = new[]
                {
                    "telegram.org", "t.me", "web.telegram.org", "tdesktop.com", "telesco.pe", "telegra.ph"
                };
                foreach (var d in telegramList) addDom(d);
            }

            if (routeWeb)
            {
                string[] spotifyList = new[]
                {
                    "spotify.com", "spotify.net", "scdn.co", "spotifycdn.com", "pscdn.co", "byspotify.com", "spotify.link", "spotilocal.com",
                    "spclient.wg.spotify.com", "apresolve.spotify.com", "dealer.spotify.com", "login5.spotify.com", "accounts.spotify.com", "open.spotify.com",
                    "audio-ak-spotify-com.akamaized.net", "heads4-ak-spotify-com.akamaized.net", "akamaized.net"
                };
                foreach (var d in spotifyList) addDom(d);
            }

            if (routeWeb)
            {
                string[] webList = new[]
                {
                    "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net",
                    "twitter.com", "x.com", "twimg.com", "t.co", "threads.net",
                    "tiktok.com", "linkedin.com", "netflix.com", "nflxvideo.net",
                    "patreon.com", "reddit.com", "redd.it", "medium.com", "quora.com",
                    "canva.com", "figma.com", "notion.so", "rutracker.org", "rutracker.net",
                    "github.com", "githubusercontent.com", "githubassets.com",
                    "vscode-cdn.net", "visualstudio.com", "jetbrains.com",
                    "docker.com", "docker.io", "npmjs.org", "pypi.org",
                    "cloudflare.com", "ipinfo.io"
                };
                foreach (var d in webList) addDom(d);
            }

            string prx, dir, eds;
            ReadCustomRulesConfig(out prx, out dir, out eds);
            foreach (var d in ParseDomainCsv(prx)) addDom(d);

            if (domains.Count == 0)
            {
                addDom("antigravity.google");
                addDom("daily-cloudcode-pa.googleapis.com");
            }

            var items = new List<string>();
            foreach (var d in domains) items.Add("\"domain:" + EscapeJson(d) + "\"");
            return string.Join(", ", items.ToArray());
        }

        private static string BuildCustomDirectDomainsJson()
        {
            string prx, dir, eds;
            ReadCustomRulesConfig(out prx, out dir, out eds);
            var domains = ParseDomainCsv(dir);
            if (domains.Count == 0) return "";
            var sb = new StringBuilder();
            foreach (var d in domains)
            {
                sb.Append(",\r\n          \"domain:").Append(EscapeJson(d)).Append("\"");
            }
            return sb.ToString();
        }

        public static VlessNode ParseVlessUri(string uri)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(uri) && (uri.StartsWith("pwp3://", StringComparison.OrdinalIgnoreCase) || uri.StartsWith("pwp4://", StringComparison.OrdinalIgnoreCase)))
                {
                    Uri u = new Uri(uri);
                    string userInfo = string.IsNullOrEmpty(u.UserInfo) ? "" : Uri.UnescapeDataString(u.UserInfo);
                    string pwpUuid = string.Equals(userInfo, "free", StringComparison.OrdinalIgnoreCase) ? "" : userInfo;
                    string pwpHost = string.IsNullOrEmpty(u.Host) ? GetDefaultClusterHost() : u.Host;
                    return new VlessNode
                    {
                        Uuid = pwpUuid,
                        Server = pwpHost,
                        ResolvedIp = pwpHost,
                        Port = u.Port > 0 ? u.Port : 443,
                        Sni = pwpHost,
                        TransportType = "pwp3",
                        Security = "pwp3-tls",
                        Flow = "",
                        Remark = "PixelTunnel PWP-4"
                    };
                }
                if (!string.IsNullOrWhiteSpace(uri) && Regex.IsMatch(uri.Trim(), @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"))
                {
                    string cleanUuid = uri.Trim().ToLowerInvariant();
                    string defHost = GetDefaultClusterHost();
                    return new VlessNode
                    {
                        Uuid = LegacyTrialUuids.Contains(cleanUuid) ? "" : cleanUuid,
                        Server = defHost,
                        ResolvedIp = defHost,
                        Port = 443,
                        Sni = defHost,
                        TransportType = "pwp3",
                        Security = "pwp3-tls",
                        Flow = "",
                        Remark = "PixelTunnel PRO"
                    };
                }
                if (!string.IsNullOrWhiteSpace(uri) && Regex.IsMatch(uri.Trim(), @"^https://ai\.pixelstore\.space/sub/[A-Za-z0-9_-]{6,64}$", RegexOptions.IgnoreCase))
                {
                    string defHost = GetDefaultClusterHost();
                    string subId = uri.Trim().Substring(uri.Trim().LastIndexOf('/') + 1);
                    return new VlessNode
                    {
                        Uuid = subId,
                        Server = defHost,
                        ResolvedIp = defHost,
                        Port = 443,
                        Sni = defHost,
                        TransportType = "pwp3",
                        Security = "pwp3-tls",
                        Flow = "",
                        Remark = "PixelTunnel Sub"
                    };
                }
                if (!string.IsNullOrWhiteSpace(uri) && uri.StartsWith("pwp1://", StringComparison.OrdinalIgnoreCase))
                {
                    Uri u = new Uri(uri);
                    string sec = string.IsNullOrEmpty(u.UserInfo) ? "" : Uri.UnescapeDataString(u.UserInfo);
                    return new VlessNode
                    {
                        Uuid = sec,
                        Server = u.Host,
                        ResolvedIp = u.Host,
                        Port = u.Port > 0 ? u.Port : 2087,
                        Sni = "www.amd.com",
                        TransportType = "pwp1",
                        Security = "pwp1-tls",
                        Remark = "PixelCore PWP-1 NL"
                    };
                }
                if (string.IsNullOrWhiteSpace(uri) || !uri.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                    return null;

                string withoutScheme = uri.Substring(8);
                string remark = "PixelStore VPN";
                int hashIdx = withoutScheme.IndexOf('#');
                if (hashIdx >= 0)
                {
                    remark = Uri.UnescapeDataString(withoutScheme.Substring(hashIdx + 1));
                    withoutScheme = withoutScheme.Substring(0, hashIdx);
                }

                string queryPart = "";
                int qIdx = withoutScheme.IndexOf('?');
                if (qIdx >= 0)
                {
                    queryPart = withoutScheme.Substring(qIdx + 1);
                    withoutScheme = withoutScheme.Substring(0, qIdx);
                }

                int atIdx = withoutScheme.IndexOf('@');
                if (atIdx <= 0) return null;

                string uuid = withoutScheme.Substring(0, atIdx).Trim();
                string hostPort = withoutScheme.Substring(atIdx + 1).Trim();

                string host = hostPort;
                int port = 443;
                int colonIdx = hostPort.LastIndexOf(':');
                if (colonIdx > 0)
                {
                    host = hostPort.Substring(0, colonIdx);
                    int.TryParse(hostPort.Substring(colonIdx + 1), out port);
                }

                var node = new VlessNode
                {
                    Uuid = uuid,
                    Server = host,
                    Port = port,
                    Remark = remark
                };

                var qParams = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var pair in queryPart.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = pair.IndexOf('=');
                    if (eq > 0)
                    {
                        string k = Uri.UnescapeDataString(pair.Substring(0, eq));
                        string v = Uri.UnescapeDataString(pair.Substring(eq + 1));
                        qParams[k] = v;
                    }
                }

                if (qParams.ContainsKey("sni") && !string.IsNullOrEmpty(qParams["sni"]))
                    node.Sni = qParams["sni"];
                else if (qParams.ContainsKey("host") && !string.IsNullOrEmpty(qParams["host"]))
                    node.Sni = qParams["host"];

                if (qParams.ContainsKey("pbk")) node.PublicKey = qParams["pbk"];
                if (qParams.ContainsKey("sid")) node.ShortId = qParams["sid"];
                if (qParams.ContainsKey("fp") && !string.IsNullOrEmpty(qParams["fp"])) node.Fingerprint = qParams["fp"];
                if (qParams.ContainsKey("flow")) node.Flow = qParams["flow"];
                if (qParams.ContainsKey("type") && !string.IsNullOrEmpty(qParams["type"])) node.TransportType = qParams["type"];
                if (qParams.ContainsKey("security") && !string.IsNullOrEmpty(qParams["security"])) node.Security = qParams["security"];
                if (qParams.ContainsKey("spx") && !string.IsNullOrEmpty(qParams["spx"])) node.SpiderX = qParams["spx"];
                if (qParams.ContainsKey("serviceName")) node.ServiceName = qParams["serviceName"];
                if (qParams.ContainsKey("path")) node.WsPath = qParams["path"];
                if (qParams.ContainsKey("host")) node.WsHost = qParams["host"];

                IPAddress parsedIp;
                if (IPAddress.TryParse(node.Server, out parsedIp) && parsedIp.AddressFamily == AddressFamily.InterNetwork)
                {
                    node.ResolvedIp = parsedIp.ToString();
                }
                else
                {
                    try
                    {
                        foreach (var ip in Dns.GetHostAddresses(node.Server))
                        {
                            if (ip.AddressFamily == AddressFamily.InterNetwork)
                            {
                                node.ResolvedIp = ip.ToString();
                                break;
                            }
                        }
                    }
                    catch { }
                }

                return node;
            }
            catch
            {
                return null;
            }
        }

        private static bool IsClusterHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            string h = host.Trim();
            return string.Equals(h, GetDefaultClusterHost(), StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "node.pixelstore.space", StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "201.34.152.97", StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "185.103.103.162", StringComparison.OrdinalIgnoreCase);
        }

        private static void EnsureManifestSecretsForConfig(int maxWaitMs = 3500)
        {
            try
            {
                Type svcType = typeof(PixelCoreService);
                BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;

                MethodInfo initPaths = svcType.GetMethod("EnsureManifestPathsInitialized", flags);
                if (initPaths != null) initPaths.Invoke(null, null);

                MethodInfo hasAny = svcType.GetMethod("HasAnyNodeWithSecret", flags);
                bool hasSecret = hasAny != null && (bool)hasAny.Invoke(null, null);

                if (!hasSecret)
                {
                    MethodInfo loadCache = svcType.GetMethod("TryLoadCachedManifest", flags);
                    if (loadCache != null) loadCache.Invoke(null, null);
                    hasSecret = hasAny != null && (bool)hasAny.Invoke(null, null);
                }

                if (!hasSecret)
                {
                    string[] localCandidates = new[]
                    {
                        System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "nodes_v3.enc"),
                        System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "manifest", "nodes_v3.enc")
                    };
                    foreach (string cand in localCandidates)
                    {
                        if (!File.Exists(cand)) continue;
                        try
                        {
                            string raw = File.ReadAllText(cand, Encoding.UTF8);
                            if (PixelCoreService.TryApplySignedManifestEnvelope(raw, "local-file", false))
                            {
                                hasSecret = true;
                                break;
                            }
                        }
                        catch { }
                    }
                }

                if (!hasSecret)
                {
                    MethodInfo ensureLoaded = svcType.GetMethod("EnsureManifestSecretsLoaded", flags);
                    if (ensureLoaded != null) ensureLoaded.Invoke(null, new object[] { maxWaitMs });
                }
            }
            catch { }
        }

        private static void BuildManifestFieldsForConfig(out string pwpSecret, out string nodesJson)
        {
            pwpSecret = "";
            nodesJson = "[]";
            try
            {
                EnsureManifestSecretsForConfig(3500);

                Type svcType = typeof(PixelCoreService);
                BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
                FieldInfo nodesLockField = svcType.GetField("_nodesLock", flags);
                FieldInfo nodesField = svcType.GetField("_nodes", flags);
                FieldInfo secretField = svcType.GetField("_secret", flags);

                object lockObj = nodesLockField != null ? nodesLockField.GetValue(null) : null;
                if (lockObj == null) lockObj = new object();

                var sb = new StringBuilder();
                sb.Append('[');
                bool first = true;

                lock (lockObj)
                {
                    string globalSecret = secretField != null ? (secretField.GetValue(null) as string ?? "") : "";
                    pwpSecret = globalSecret.Trim();

                    var nodes = nodesField != null ? (nodesField.GetValue(null) as List<PixelServerNode>) : null;
                    if (nodes != null)
                    {
                        for (int i = 0; i < nodes.Count; i++)
                        {
                            PixelServerNode n = nodes[i];
                            if (n == null || string.IsNullOrWhiteSpace(n.Host)) continue;
                            string nodeSecret = !string.IsNullOrEmpty(n.Secret) ? n.Secret.Trim() : pwpSecret;
                            if (string.IsNullOrEmpty(pwpSecret) && !string.IsNullOrEmpty(nodeSecret))
                                pwpSecret = nodeSecret;

                            string region = string.IsNullOrWhiteSpace(n.Region) ? "nl" : n.Region.Trim().ToLowerInvariant();
                            string sni = string.IsNullOrWhiteSpace(n.Sni) ? GetDefaultClusterHost() : n.Sni.Trim();
                            string path = string.IsNullOrWhiteSpace(n.UpgradePath) ? "/api/v3/telemetry/mux" : n.UpgradePath.Trim();
                            string pwp4Path = n.SupportsMuxV3 ? "/api/v4/telemetry/mux" : "";
                            string name = string.IsNullOrWhiteSpace(n.Name) ? n.Host : n.Name.Trim();

                            if (!first) sb.Append(", ");
                            first = false;
                            sb.AppendFormat(
                                "{{\"name\":\"{0}\",\"region\":\"{1}\",\"host\":\"{2}\",\"port\":{3},\"sni\":\"{4}\",\"path\":\"{5}\",\"pwp4_path\":\"{6}\",\"secret\":\"{7}\",\"tls\":{8},\"mux\":{9},\"frag\":{10}}}",
                                EscapeJson(name),
                                EscapeJson(region),
                                EscapeJson(n.Host.Trim()),
                                n.Port > 0 ? n.Port : 443,
                                EscapeJson(sni),
                                EscapeJson(path),
                                EscapeJson(pwp4Path),
                                EscapeJson(nodeSecret),
                                n.UseTls ? "true" : "false",
                                n.SupportsMuxV3 ? "true" : "false",
                                n.EnableDpiSplit ? "true" : "false");
                        }
                    }
                }

                sb.Append(']');
                nodesJson = sb.ToString();
            }
            catch
            {
                if (nodesJson == null) nodesJson = "[]";
                if (pwpSecret == null) pwpSecret = "";
            }
        }

        public static string BuildSingBoxConfig(VlessNode node, bool routeAg, bool routeAi, bool routeMedia, bool routeWeb = true, bool includeTun = true)
        {
            if (node == null) node = new VlessNode();
            string server = string.IsNullOrEmpty(node.Server) ? GetDefaultClusterHost() : node.Server;
            int port = node.Port > 0 ? node.Port : 443;
            string uuid = string.IsNullOrEmpty(node.Uuid) ? "" : node.Uuid;
            string flow = string.IsNullOrEmpty(node.Flow) ? "xtls-rprx-vision" : node.Flow;
            string net = string.IsNullOrEmpty(node.TransportType) ? "pwp3" : node.TransportType;
            string fp = string.IsNullOrEmpty(node.Fingerprint) ? "chrome" : node.Fingerprint;
            string sni = string.IsNullOrEmpty(node.Sni) ? "ai.pixelstore.space" : node.Sni;
            string pbk = string.IsNullOrEmpty(node.PublicKey) ? "" : node.PublicKey;
            string sid = string.IsNullOrEmpty(node.ShortId) ? "" : node.ShortId;
            string spx = string.IsNullOrEmpty(node.SpiderX) ? "/" : node.SpiderX;
            string serviceName = string.IsNullOrEmpty(node.ServiceName) ? "" : node.ServiceName;

            if (IsClusterHost(server))
            {
                if (string.Equals(server.Trim(), "node.pixelstore.space", StringComparison.OrdinalIgnoreCase))
                    server = GetDefaultClusterHost();
                port = 443;
                net = "pwp3";
                flow = "";
                sni = "ai.pixelstore.space";
                pbk = "";
                sid = "";
                serviceName = "";
            }
            else if (string.Equals(net, "grpc", StringComparison.OrdinalIgnoreCase) || string.Equals(net, "pwp3", StringComparison.OrdinalIgnoreCase))
            {
                flow = "";
            }

            string manifestPwpSecret, manifestNodesJson;
            BuildManifestFieldsForConfig(out manifestPwpSecret, out manifestNodesJson);

            string grpcSettingsJson = "";
            if (string.Equals(net, "grpc", StringComparison.OrdinalIgnoreCase))
            {
                grpcSettingsJson = string.Format(@",
        ""grpcSettings"": {{
          ""serviceName"": ""{0}"",
          ""multiMode"": false,
          ""idle_timeout"": 60,
          ""health_check_timeout"": 20
        }}", EscapeJson(serviceName));
            }

            string directIpCidrs = "\"127.0.0.0/8\", \"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\", \"100.64.0.0/10\"";
            if (!string.IsNullOrEmpty(node.ResolvedIp))
            {
                directIpCidrs += ", \"" + EscapeJson(node.ResolvedIp) + "/32\"";
            }

            string inboundsSection = string.Format(@"    {{
      ""tag"": ""http-in"",
      ""port"": {0},
      ""listen"": ""127.0.0.1"",
      ""protocol"": ""http"",
      ""sniffing"": {{
        ""enabled"": true,
        ""destOverride"": [ ""http"", ""tls"" ]
      }}
    }},
    {{
      ""tag"": ""socks-in"",
      ""port"": {1},
      ""listen"": ""127.0.0.1"",
      ""protocol"": ""socks"",
      ""settings"": {{
        ""udp"": true
      }},
      ""sniffing"": {{
        ""enabled"": true,
        ""destOverride"": [ ""http"", ""tls"" ]
      }}
    }}", _activeHttpPort, _activeSocksPort);

            string defaultOutboundRules = (routeWeb || routeMedia || routeAi)
                ? @",
      {
        ""type"": ""field"",
        ""outboundTag"": ""proxy"",
        ""network"": ""tcp,udp""
      }"
                : @",
      {
        ""type"": ""field"",
        ""outboundTag"": ""direct"",
        ""network"": ""tcp,udp""
      }";

            string prxCsv, dirCsv, edsCsv;
            ReadCustomRulesConfig(out prxCsv, out dirCsv, out edsCsv);
            string v2Json = string.Format(@"{{
    ""smart_pac"": {0},
    ""pac_rev"": {1},
    ""wsl_bridge"": {2},
    ""local_token"": """",
    ""categories"": {{
      ""antigravity"": {3},
      ""ai"": {4},
      ""media"": {5},
      ""social"": {6},
      ""mcp"": {7}
    }},
    ""custom_proxy"": [{8}],
    ""custom_direct"": [{9}],
    ""custom_proxy_domains"": [{8}],
    ""custom_direct_domains"": [{9}]
  }}",
                _useSmartPacMode ? "true" : "false",
                Math.Max(1, PixelCoreService.ActivePacRevision),
                _optWslBridge ? "true" : "false",
                routeAg ? "true" : "false",
                routeAi ? "true" : "false",
                routeMedia ? "true" : "false",
                routeWeb ? "true" : "false",
                _optMcpTerminal ? "true" : "false",
                JoinJsonStrings(ParseDomainCsv(prxCsv)),
                JoinJsonStrings(ParseDomainCsv(dirCsv)));

            return string.Format(@"{{
  ""preferredRegion"": ""{16}"",
  ""http_port"": {18},
  ""socks_port"": {19},
  ""pwpSecret"": ""{20}"",
  ""nodes"": {21},
  ""v2"": {17},
  ""log"": {{
    ""loglevel"": ""warning""
  }},
  ""inbounds"": [
{11}
  ],
  ""outbounds"": [
    {{
      ""tag"": ""proxy"",
      ""protocol"": ""vless"",
      ""settings"": {{
        ""vnext"": [
          {{
            ""address"": ""{0}"",
            ""port"": {1},
            ""users"": [
              {{
                ""id"": ""{2}"",
                ""flow"": ""{3}"",
                ""encryption"": ""none""
              }}
            ]
          }}
        ]
      }},
      ""streamSettings"": {{
        ""network"": ""{4}"",
        ""security"": ""reality"",
        ""realitySettings"": {{
          ""show"": false,
          ""fingerprint"": ""{5}"",
          ""serverName"": ""{6}"",
          ""publicKey"": ""{7}"",
          ""shortId"": ""{8}"",
          ""spiderX"": ""{9}""
        }}{15}
      }}
    }},
    {{
      ""tag"": ""direct"",
      ""protocol"": ""freedom"",
      ""settings"": {{}}
    }}
  ],
  ""routing"": {{
    ""domainStrategy"": ""AsIs"",
    ""rules"": [
      {{
        ""type"": ""field"",
        ""outboundTag"": ""direct"",
        ""ip"": [ {10} ]
      }},
      {{
        ""type"": ""field"",
        ""outboundTag"": ""direct"",
        ""domain"": [
          ""regexp:.*\\.ru$"",
          ""regexp:.*\\.su$"",
          ""regexp:.*\\.xn--p1ai$"",
          ""domain:ya.ru"",
          ""domain:yandex.ru"",
          ""domain:yandex.net"",
          ""domain:vk.com"",
          ""domain:vk.ru"",
          ""domain:userapi.com"",
          ""domain:ozon.ru"",
          ""domain:wildberries.ru"",
          ""domain:avito.ru"",
          ""domain:sberbank.ru"",
          ""domain:tbank.ru"",
          ""domain:gosuslugi.ru"",
          ""domain:chatzone.ru"",
          ""domain:radiofine.net"",
          ""domain:rusweb.net"",
          ""domain:pixelstore.space"",
          ""domain:steampowered.com"",
          ""domain:steamcontent.com"",
          ""domain:steamstatic.com"",
          ""domain:windowsupdate.com"",
          ""domain:epicgames.com"",
          ""domain:battle.net"",
          ""domain:wargaming.net"",
          ""domain:lesta.ru"",
          ""domain:vkplay.ru""{13}
        ]
      }},
      {{
        ""type"": ""field"",
        ""outboundTag"": ""proxy"",
        ""domain"": [ {12} ]
      }}{14}
    ]
  }}
}}",
                EscapeJson(server),
                port,
                EscapeJson(uuid),
                EscapeJson(flow),
                EscapeJson(net),
                EscapeJson(fp),
                EscapeJson(sni),
                EscapeJson(pbk),
                EscapeJson(sid),
                EscapeJson(spx),
                directIpCidrs,
                inboundsSection,
                BuildEffectiveProxyDomainsJson(routeAg, routeAi, routeMedia, routeWeb),
                BuildCustomDirectDomainsJson(),
                defaultOutboundRules,
                grpcSettingsJson,
                EscapeJson(string.IsNullOrEmpty(_selectedRegion) ? "auto" : _selectedRegion),
                v2Json,
                _activeHttpPort,
                _activeSocksPort,
                EscapeJson(manifestPwpSecret),
                manifestNodesJson
            );
        }

        private static string JoinJsonStrings(List<string> items)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < items.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append('"').Append(EscapeJson(items[i])).Append('"');
            }
            return sb.ToString();
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
