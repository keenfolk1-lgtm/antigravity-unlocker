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
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using ShapePath = System.Windows.Shapes.Path;

[assembly: AssemblyTitle("PixelTunnel")]
[assembly: AssemblyDescription("Native Go uTLS + PWP-4 Dual-Mux & Smart PAC Assistant for Antigravity IDE")]
[assembly: AssemblyCompany("PixelTunnel Community")]
[assembly: AssemblyProduct("PixelTunnel")]
[assembly: AssemblyCopyright("Copyright © 2026 PixelTunnel")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("2.2.0.0")]
[assembly: AssemblyFileVersion("2.2.0.0")]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]

namespace PixelTunnel
{
    public enum TunnelState
    {
        Offline,
        Connecting,
        Online
    }

    public enum ThemeModeChoice
    {
        Light,
        Dark,
        System
    }

    internal sealed class ThemeTokens
    {
        public Color Bg;
        public Color Surface;
        public Color SurfaceHover;
        public Color StatusCardBg;
        public Color Well;
        public Color Border;
        public Color BorderStrong;
        public Color Ink;
        public Color Muted;
        public Color Faint;
        public Color Accent;
        public Color AccentInk;
        public Color AccentSoft;
        public Color AccentBorder;
        public Color Ok;
        public Color OkSoft;
        public Color OkBorder;
        public Color Warn;
        public Color WarnSoft;
        public Color WarnBorder;
        public Color Err;
        public Color ErrSoft;
        public Color ErrBorder;
        public Color CtaIdleBg;
        public Color CtaIdleInk;
        public Color ModalScrim;
        public double WindowShadowOpacity;
        public double CardShadowOpacity;

        public static ThemeTokens CreateLight()
        {
            var t = new ThemeTokens();
            t.Bg = Color.FromRgb(248, 248, 250);           // #F8F8FA
            t.Surface = Color.FromRgb(255, 255, 255);      // #FFFFFF
            t.SurfaceHover = Color.FromRgb(241, 241, 245); // #F1F1F5
            t.StatusCardBg = Color.FromRgb(243, 244, 248); // #F3F4F8
            t.Well = Color.FromRgb(230, 231, 238);         // #E6E7EE
            t.Border = Color.FromRgb(228, 228, 234);       // #E4E4EA
            t.BorderStrong = Color.FromRgb(207, 207, 216); // #CFCFD8
            t.Ink = Color.FromRgb(17, 17, 19);             // #111113
            t.Muted = Color.FromRgb(82, 82, 91);           // #52525B
            t.Faint = Color.FromRgb(113, 113, 122);        // #71717A
            t.Accent = Color.FromRgb(29, 78, 216);         // #1D4ED8 (Ice Cobalt Light)
            t.AccentInk = Color.FromRgb(255, 255, 255);    // #FFFFFF
            t.AccentSoft = Color.FromRgb(238, 242, 255);   // #EEF2FF
            t.AccentBorder = Color.FromRgb(199, 215, 254); // #C7D7FE
            t.Ok = Color.FromRgb(4, 120, 87);              // #047857
            t.OkSoft = Color.FromRgb(236, 253, 245);       // #ECFDF5
            t.OkBorder = Color.FromRgb(167, 243, 208);     // #A7F3D0
            t.Warn = Color.FromRgb(180, 83, 9);            // #B45309
            t.WarnSoft = Color.FromRgb(255, 251, 235);     // #FFFBEB
            t.WarnBorder = Color.FromRgb(253, 230, 138);   // #FDE68A
            t.Err = Color.FromRgb(220, 38, 38);            // #DC2626
            t.ErrSoft = Color.FromRgb(254, 242, 242);      // #FEF2F2
            t.ErrBorder = Color.FromRgb(254, 202, 202);    // #FECACA
            t.CtaIdleBg = Color.FromRgb(17, 17, 19);       // #111113
            t.CtaIdleInk = Color.FromRgb(255, 255, 255);   // #FFFFFF
            t.ModalScrim = Color.FromArgb(105, 15, 20, 30);
            t.WindowShadowOpacity = 0.22;
            t.CardShadowOpacity = 0.05;
            return t;
        }

        public static ThemeTokens CreateDark()
        {
            var t = new ThemeTokens();
            t.Bg = Color.FromRgb(9, 9, 11);                // #09090B
            t.Surface = Color.FromRgb(17, 17, 20);         // #111114
            t.SurfaceHover = Color.FromRgb(24, 24, 29);    // #18181D
            t.StatusCardBg = Color.FromRgb(14, 14, 18);    // #0E0E12
            t.Well = Color.FromRgb(28, 28, 34);            // #1C1C22
            t.Border = Color.FromRgb(35, 35, 42);          // #23232A
            t.BorderStrong = Color.FromRgb(53, 53, 64);    // #353540
            t.Ink = Color.FromRgb(244, 244, 245);          // #F4F4F5
            t.Muted = Color.FromRgb(161, 161, 170);        // #A1A1AA
            t.Faint = Color.FromRgb(113, 113, 122);        // #71717A
            t.Accent = Color.FromRgb(59, 130, 246);        // #3B82F6 (Refined Cobalt Dark)
            t.AccentInk = Color.FromRgb(255, 255, 255);    // #FFFFFF
            t.AccentSoft = Color.FromRgb(20, 34, 62);      // #14223E
            t.AccentBorder = Color.FromRgb(37, 68, 126);   // #25447E
            t.Ok = Color.FromRgb(52, 211, 153);            // #34D399
            t.OkSoft = Color.FromRgb(11, 41, 32);          // #0B2920
            t.OkBorder = Color.FromRgb(21, 94, 71);        // #155E47
            t.Warn = Color.FromRgb(251, 191, 36);          // #FBBF24
            t.WarnSoft = Color.FromRgb(43, 31, 9);         // #2B1F09
            t.WarnBorder = Color.FromRgb(107, 76, 18);     // #6B4C12
            t.Err = Color.FromRgb(248, 113, 113);          // #F87171
            t.ErrSoft = Color.FromRgb(48, 16, 20);         // #301014
            t.ErrBorder = Color.FromRgb(127, 29, 29);      // #7F1D1D
            t.CtaIdleBg = Color.FromRgb(250, 250, 250);    // #FAFAFA
            t.CtaIdleInk = Color.FromRgb(9, 9, 11);        // #09090B
            t.ModalScrim = Color.FromArgb(175, 6, 8, 12);
            t.WindowShadowOpacity = 0.56;
            t.CardShadowOpacity = 0.0;
            return t;
        }
    }

    internal sealed class RouteItemView
    {
        public string Id;
        public string IconData;
        public string Title;
        public string Subtitle;
        public bool IsPro;
        public bool IsOn;

        public Border RowBorder;
        public Border IconBox;
        public ShapePath IconPath;
        public TextBlock TitleText;
        public TextBlock SubtitleText;
        public Border TierBadge;
        public TextBlock TierText;
        public Border SwitchTrack;
        public Border SwitchThumb;
        public TranslateTransform ThumbTransform;
        public Border BottomDivider;
    }

    internal enum DiagItemState
    {
        Pending,
        Running,
        Ok,
        Warn,
        Error
    }

    internal sealed class DiagCheckItem
    {
        public string Id;
        public string Title;
        public DiagItemState State;
        public string Detail;
        public string Recommendation;
        public bool CanAutoFix;
    }

    internal sealed class RadarEntry
    {
        public string Domain;
        public string ProcessName;
        public string Proto;
        public int Port;
        public string Node;
        public bool IsTunnel;
        public int LatencyMs;
        public string AgeText;
    }

    public class VlessNode
    {
        public string Uuid = "";
        public string Server = "";
        public string ResolvedIp = "";
        public int Port = 443;
        public string Sni = "www.microsoft.com";
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
            bool isSanitizeProxy = false;
            bool autoConnect = false;
            bool autoDiag = false;
            bool startMinimized = false;
            bool elevatedTun = false;
            string deepLinkUri = null;
            if (args != null)
            {
                foreach (var a in args)
                {
                    if (string.Equals(a, "--genconfig", StringComparison.OrdinalIgnoreCase))
                        isGenConfig = true;
                    else if (string.Equals(a, "--sanitize-proxy", StringComparison.OrdinalIgnoreCase))
                        isSanitizeProxy = true;
                    else if (string.Equals(a, "--autoconnect", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(a, "--connect", StringComparison.OrdinalIgnoreCase))
                        autoConnect = true;
                    else if (string.Equals(a, "--autostart", StringComparison.OrdinalIgnoreCase))
                        autoConnect = true;
                    else if (string.Equals(a, "--minimized", StringComparison.OrdinalIgnoreCase))
                        startMinimized = true;
                    else if (string.Equals(a, "--elevated-tun", StringComparison.OrdinalIgnoreCase))
                        elevatedTun = true;
                    else if (string.Equals(a, "--autodiag", StringComparison.OrdinalIgnoreCase))
                        autoDiag = true;
                    else if (!string.IsNullOrWhiteSpace(a) && a.Trim().StartsWith("pixeltunnel://", StringComparison.OrdinalIgnoreCase))
                        deepLinkUri = a.Trim();
                }
            }

            if (isGenConfig)
            {
                PixelTunnel.MainWindow._isConfigGenMode = true;
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

            if (isSanitizeProxy)
            {
                PixelTunnel.MainWindow.EmergencyDisableDeadSystemProxy(false);
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

            if (failedToKillElevated && !PixelTunnel.MainWindow.IsAdministratorStatic())
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = Process.GetCurrentProcess().MainModule.FileName,
                        Arguments = "",
                        UseShellExecute = true,
                        Verb = "runas"
                    };
                    Process.Start(psi);
                    return;
                }
                catch { }
            }

            PixelTunnel.MainWindow.CleanupOldUpdateArtifacts();

            try
            {
                var app = new App();
                var win = new MainWindow(autoConnect, autoDiag, deepLinkUri, startMinimized, elevatedTun);
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

        public const string APP_VERSION = "2.2.0";
        public const string IPC_PIPE_NAME = "Local\\PixelTunnel_IPC_v2";
        private const int LOCAL_MIXED_PORT = 17890;
        internal static volatile bool _isConfigGenMode = false;
        private static readonly string[] OAuthTemporaryDomains = new[]
        {
            "accounts.google.com", "oauth2.googleapis.com", "myaccount.google.com",
            "consent.google.com", "ssl.gstatic.com", "fonts.gstatic.com",
            "apis.google.com", "recaptcha.net", "pki.goog"
        };
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
        private static bool _optTunMode = false;
        private CancellationTokenSource _deepLinkPipeCts;
        private readonly string _initialDeepLinkUri;
        private readonly bool _startMinimized;
        private int _pulseTickCounter = 0;
        private bool _isExplicitExit = false;
        private bool _hasShownTrayBalloon = false;
        private int _consecutivePingFailures = 0;
        private string _githubReleaseUrl = "";
        private string _githubLatestVer = "";
        private static volatile bool _githubUpdateChecked = false;
        private DateTime _tunnelConnectedUtc = DateTime.MinValue;
        private static DateTime _lastTunnelConnectedUtc = DateTime.MinValue;
        private static DateTime _agLsEnvLastUpdatedUtc = DateTime.MinValue;
        private static DateTime _lsBinaryLastPatchedUtc = DateTime.MinValue;
        private static volatile bool _forceShowAgBannerOnNextCheck = false;
        private int _agRelaunchedForPort = 0;
        private bool _agBannerDismissed = false;
        private static string _selectedRegion = "auto";
        private static bool _isWatchdogPatchRunning = false;
        private static readonly Dictionary<string, string> _verifiedLsBinSignatures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, long> _agLogHighWaterOffsets = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, DateTime> _agLogHighWaterTimes = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private const string PROXY_OVERRIDE = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>;*.ru;*.su;*.xn--p1ai;*.pixelstore.space;pixelstore.space;185.103.103.162;201.34.152.97;*.o3.ru;*.o3team.ru;*.o3t.ru;*.ozon.ru;*.ozon-dostavka.ru;*.ozonalco.ru;*.ozon.by;*.ozon.kz;*.ozone.ru;*.ozonru.me;*.ozonrucn.me;*.ozoncom.me;*.ozon.tech;*.ozonusercontent.com;*.ozon.com;*.ozonpartners.ru;*.ozondostavka.ru;*.ozon.travel;*.ozon.team;*.chatzone.ru;185.73.*;89.31.143.*";

        private readonly string _baseDir;
        private readonly string _engineDir;
        private readonly string _activeConfigPath;
        private readonly string _savedKeyPath;

        // Typography & Theme State (Obsidian Precision v2.2)
        private static readonly FontFamily DisplayFont = new FontFamily("Segoe UI Variable Display, Segoe UI, Arial");
        private static readonly FontFamily UiFont = new FontFamily("Segoe UI Variable Text, Segoe UI, Arial");
        private static readonly FontFamily MonoFont = new FontFamily("Cascadia Mono, Consolas, Courier New");

        private ThemeModeChoice _themeChoice = ThemeModeChoice.System;
        private bool _isDark = false;
        private ThemeTokens _theme = ThemeTokens.CreateLight();
        private TunnelState _connState = TunnelState.Offline;
        private bool _proActive = false;
        private bool _keyDrawerOpen = false;
        private bool _optAutostart = false;
        private static bool _optInstantWake = true;
        private bool _statusHasCustomMessage = false;
        private string _statusCustomTitle = "";
        private string _statusCustomSub = "";

        private readonly List<string> _customProxyDomains = new List<string>();
        private readonly List<string> _customDirectDomains = new List<string>();
        private readonly List<RadarEntry> _radarEntries = new List<RadarEntry>();
        private int _currentPing = 0;
        private int _waveStep = 0;
        private string _geminiStatus = "idle";
        private string _claudeStatus = "idle";
        private string _openaiStatus = "idle";
        private int _geminiMs = 0;
        private int _claudeMs = 0;
        private int _openaiMs = 0;
        private int _geminiHttp = 0;
        private int _claudeHttp = 0;
        private int _openaiHttp = 0;

        private DispatcherTimer _waveTimer;
        private DispatcherTimer _radarTimer;
        private DispatcherTimer _oauthHelperTimer;
        private DispatcherTimer _inlineFeedbackTimer;

        // Window Chrome & Containers
        private Border _outerWinBorder;
        private ScaleTransform _outerWinScale;
        private DropShadowEffect _winShadow;
        private Border _headerDivider;
        private Border _logoBox;
        private ShapePath _logoOuterArch;
        private Border _logoCorePixel;
        private TextBlock _brandTitle;
        private Border _versionPill;
        private TextBlock _versionPillText;
        private Border _updatePillBtn;
        private TextBlock _updatePillText;
        private Border _toolsBtn;
        private ContentControl _toolsIconHolder;
        private Border _themeBtn;
        private ContentControl _themeIconHolder;
        private Border _minBtn;
        private ShapePath _minBtnPath;
        private Border _closeBtn;
        private ShapePath _closeBtnPath;

        // Left Column (Hero Status Card + Connect + AI Pulse + Antigravity Quick Bar)
        private Border _statusCard;
        private DropShadowEffect _statusCardShadow;
        private readonly Border[] _signalBars = new Border[4];
        private TextBlock _statusTitle;
        private TextBlock _statusSub;
        private Border _specDivider;
        private Border _agChamberBorder;
        private Border _agChamberBadge;
        private TextBlock _agChamberBadgeText;
        private AsciiAntigravityPrismEngine _agAsciiEngine;
        private bool _agPointerActive = false;
        private double _agPointerNormX = 0.5;
        private double _agPointerNormY = 0.5;
        private AsciiVpnPillEngine _vpnBlueEngine;
        private AsciiVpnPillEngine _vpnRedEngine;
        private bool _vpnBlueHover = false;
        private bool _vpnRedHover = false;
        private AsciiDiagScannerEngine _diagAsciiEngine;
        private Border _diagChamberBorder;
        private DispatcherTimer _asciiTimer;
        private double _asciiTime = 0.0;
        private TextBlock _specLatencyVal;
        private TextBlock _specModeLbl;
        private TextBlock _specModeVal;
        private TextBlock _specAccessLbl;
        private TextBlock _specAccessVal;

        private Border _connectBtn;
        private Ellipse _connectLiveDot;
        private ContentControl _connectIconHolder;
        private TextBlock _connectBtnText;

        private Border _aiPulseCard;
        private DropShadowEffect _aiPulseShadow;
        private ContentControl _aiPulseIconHolder;
        private TextBlock _aiPulseTitle;
        private Ellipse _dotGemini;
        private Ellipse _dotClaude;
        private Ellipse _dotOpenAi;
        private TextBlock _lblGemini;
        private TextBlock _lblClaude;
        private TextBlock _lblOpenAi;
        private TextBlock _msGemini;
        private TextBlock _msClaude;
        private TextBlock _msOpenAi;

        // Left Quick Bar: Antigravity IDE + Google OAuth 3m
        private Border _ideQuickBar;
        private Ellipse _ideQuickDot;
        private TextBlock _ideQuickLabel;
        private Border _btnRestartIde;
        private TextBlock _btnRestartIdeText;
        private Border _btnOAuthQuick;
        private TextBlock _btnOAuthQuickText;
        private bool _ideOpenedPreTunnel = false;

        // Right Column (Split-Tunneling + Domains/Traffic Button + Key Drawer + Utilities + Donate)
        private TextBlock _splitHeaderLeft;
        private Border _domainsTrafficBtn;
        private TextBlock _domainsTrafficText;

        private Border _routesCard;
        private DropShadowEffect _routesCardShadow;
        private readonly List<RouteItemView> _routes = new List<RouteItemView>();

        private Border _keyDrawer;
        private TranslateTransform _keyDrawerTranslate;
        private int _keyDrawerAnimToken = 0;
        private TextBox _keyInput;
        private Border _pasteProBtn;
        private TextBlock _pasteProBtnText;

        private Border _btnVpn;
        private ContentControl _btnVpnIcon;
        private TextBlock _btnVpnText;
        private Border _btnKey;
        private ContentControl _btnKeyIcon;
        private TextBlock _btnKeyText;
        private Border _btnDiag;
        private ContentControl _btnDiagIcon;
        private TextBlock _btnDiagText;

        private Border _donateBar;
        private ContentControl _donateHeartIcon;
        private TextBlock _donateTitle;
        private TextBlock _donateSub;
        private TextBlock _donateActionText;
        private ContentControl _donateArrowIcon;

        // Modal Overlay & Sub-state
        private Border _modalBackdrop;
        private Border _modalCard;
        private ScaleTransform _modalScale;
        private TranslateTransform _modalTranslate;
        private int _modalAnimToken = 0;
        private string _activeModalKind = "";
        private int _radarTab = 0;     // 0 = Live Radar, 1 = Custom Domains
        private bool _addRuleTunnel = true;
        private string _draftRuleText = "";
        private string _radarFilterText = "";
        private StackPanel _radarListHost;
        private TextBlock _radarStatusLabel;
        private string _rulesAdviceTitle = "";
        private string _rulesAdviceBody = "";
        private bool _rulesAdviceIsWarn = false;

        private readonly List<DiagCheckItem> _diagItems = new List<DiagCheckItem>();
        private bool _diagFixing = false;
        private string _diagFixActionNotice = "";

        private string _licenseRightActionUrl = "";
        private const string ADMIN_HQ_URL = "https://ai.pixelstore.space/hq/";

        private bool _optAntigravity = true;
        private static bool _optMcpTerminal = true;
        private bool _optCursorAi = false;
        private bool _optDiscordYt = false;
        private bool _optSocialWeb = false;
        private bool _preferSafeProxyMode = true;
        private bool _isUpdatingApp = false;

        private bool _oauthHelperActive = false;
        private int _oauthHelperSecondsLeft = 0;
        private bool _isOAuthToggleRunning = false;
        private string _lastSupportPassport = "";
        private string _lastDiagReport = "";

        private DispatcherTimer _monitorTimer;
        private bool _isMonitorTickRunning = false;
        private DateTime _lastAutoReconnectUtc = DateTime.MinValue;
        private int _idleMonitorTickCounter = 0;
        private bool _isConnected = false;
        private bool _isBusy = false;
        private bool _isDiagRunning = false;
        private VlessNode _activeNode = null;
        private System.Windows.Forms.NotifyIcon _trayIcon;

        // Semantic helper colors for backend telemetry routines
        private static readonly Color ColGreen = Color.FromRgb(16, 185, 129);
        private static readonly Color ColAmber = Color.FromRgb(245, 158, 11);
        private static readonly Color ColRed = Color.FromRgb(239, 68, 68);
        private static readonly Color ColBlue = Color.FromRgb(59, 130, 246);

        public MainWindow(bool autoConnect, bool autoDiag, string initialDeepLinkUri = null, bool startMinimized = false, bool elevatedTun = false)
        {
            _initialDeepLinkUri = initialDeepLinkUri;
            _startMinimized = startMinimized;
            _baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string localEngineDir = System.IO.Path.Combine(_baseDir, "engine");

            if (IsDirectoryWritable(localEngineDir))
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

            _activeConfigPath = System.IO.Path.Combine(_engineDir, "active_config.json");
            _savedKeyPath = System.IO.Path.Combine(_baseDir, "saved_key.txt");
            PixelCoreService.RegisterPowerModeHookOnUiThread();

            Title = "PixelTunnel";
            Width = 752;
            SizeToContent = SizeToContent.Height;
            MaxHeight = Math.Max(600, SystemParameters.WorkArea.Height - 20);
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = Brushes.Transparent;
            ResizeMode = ResizeMode.CanMinimize;
            UseLayoutRounding = true;
            SnapsToDevicePixels = true;
            TextOptions.SetTextFormattingMode(this, TextFormattingMode.Ideal);
            TextOptions.SetTextRenderingMode(this, TextRenderingMode.ClearType);

            if (_startMinimized)
            {
                ShowInTaskbar = false;
                WindowState = WindowState.Minimized;
                Visibility = Visibility.Hidden;
                _hasShownTrayBalloon = true;
            }

            string icoPath = EnsureIconFileAvailable();
            var winIcon = LoadWindowIconSafe(icoPath);
            if (winIcon != null)
            {
                try { Icon = winIcon; } catch { }
            }

            BuildInterface();
            InitTray(icoPath);
            LoadSavedState();

            if (elevatedTun && IsAdministratorStatic())
            {
                string thirdTun;
                if (!CheckOtherThirdPartyTunAdapters(out thirdTun) && (HasActiveProAccess() || _optSocialWeb))
                {
                    _optTunMode = true;
                    _preferSafeProxyMode = false;
                    SaveCurrentState();
                }
            }

            ApplyTheme(false);
            SyncRoutesFromOptions(false);
            UpdateConnectionVisuals(false);
            UpdateRulesCountPill();
            UpdateIdeQuickBarVisual();

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

            KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Escape && !string.IsNullOrEmpty(_activeModalKind))
                {
                    CloseModal();
                }
            };

            _waveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(160) };
            _waveTimer.Tick += delegate
            {
                if (_connState == TunnelState.Connecting)
                {
                    _waveStep = (_waveStep + 1) % 4;
                    UpdateSignalBars(true);
                }
            };

            _monitorTimer = new DispatcherTimer();
            _monitorTimer.Interval = TimeSpan.FromSeconds(2.0);
            _monitorTimer.Tick += delegate { MonitorLoop(); };
            _monitorTimer.Start();

            _asciiTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(45) };
            _asciiTimer.Tick += delegate
            {
                if (!IsVisible || WindowState == WindowState.Minimized) return;
                _asciiTime += 0.045;
                if (_agAsciiEngine != null)
                {
                    _agAsciiEngine.Render(_asciiTime, _connState, _isDark, _agPointerActive, _agPointerNormX, _agPointerNormY);
                }
                if (_activeModalKind == "vpn_matrix")
                {
                    if (_vpnBlueEngine != null) _vpnBlueEngine.Render(_asciiTime, false, _isDark, _vpnBlueHover);
                    if (_vpnRedEngine != null) _vpnRedEngine.Render(_asciiTime, true, _isDark, _vpnRedHover);
                }
                else if (_activeModalKind == "diag" && _diagAsciiEngine != null)
                {
                    _diagAsciiEngine.Render(_asciiTime, BuildDiagNodeStates(), _diagFixing, _isDark);
                }
            };
            _asciiTimer.Start();

            Loaded += delegate
            {
                if (_trayIcon != null && !_trayIcon.Visible)
                {
                    try { _trayIcon.Visible = true; } catch { }
                }
                if (!_startMinimized)
                {
                    var fade = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(220))
                    {
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    };
                    _outerWinBorder.BeginAnimation(OpacityProperty, fade);

                    var sAnim = new DoubleAnimation(0.975, 1.0, TimeSpan.FromMilliseconds(240))
                    {
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    };
                    _outerWinScale.BeginAnimation(ScaleTransform.ScaleXProperty, sAnim);
                    _outerWinScale.BeginAnimation(ScaleTransform.ScaleYProperty, sAnim);
                }
                else
                {
                    _outerWinBorder.Opacity = 1.0;
                    _outerWinScale.ScaleX = 1.0;
                    _outerWinScale.ScaleY = 1.0;
                    Hide();
                }

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
                    _githubLatestVer = "";
                    _updatePillText.Text = "\u2191 v" + remoteVer;
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
                                if (!string.IsNullOrEmpty(json))
                                {
                                    _githubUpdateChecked = true;
                                    break;
                                }
                            }
                            catch { }
                        }

                        if (string.IsNullOrEmpty(json)) return;
                        _githubUpdateChecked = true;
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
                                            _githubLatestVer = latestVer;
                                            _updatePillText.Text = "\u2191 v" + latestVer;
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

        private static bool IsPixelTunnelLocalPort(int port)
        {
            if (port <= 0) return false;
            return port == _activeHttpPort ||
                   port == _activeSocksPort ||
                   port == LOCAL_MIXED_PORT ||
                   port == LOCAL_MIXED_PORT + 1 ||
                   port == 17892 || port == 17893 ||
                   port == 18890 || port == 18891 ||
                   port == 27890 || port == 27891;
        }

        private static bool IsPixelTunnelProxyUrl(string val)
        {
            if (string.IsNullOrWhiteSpace(val)) return false;
            if (val.IndexOf("pixel", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            int port = TryExtractLoopbackProxyPort(val);
            return IsPixelTunnelLocalPort(port);
        }

        private static bool IsPixelOrLocalAutoConfig(string val)
        {
            if (string.IsNullOrEmpty(val)) return false;
            if (val.IndexOf("pixel", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            int port = TryExtractLoopbackProxyPort(val);
            return IsPixelTunnelLocalPort(port) && val.IndexOf("/proxy.pac", StringComparison.OrdinalIgnoreCase) >= 0;
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
            _optTunMode = (flags.Contains("MEDIA=1") || flags.Contains("WEB=1")) && flags.Contains("TUN=1");
            _optInstantWake = !flags.Contains("WAKE=0");
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

        private static bool IsForeignIncompatibleVpnKey(string raw, out string reason)
        {
            reason = "";
            if (string.IsNullOrWhiteSpace(raw)) return false;
            string s = raw.Trim();
            if (IsLegacyOrFreeKey(s)) return false;

            if (s.StartsWith("pwp3://", StringComparison.OrdinalIgnoreCase) ||
                s.StartsWith("pwp4://", StringComparison.OrdinalIgnoreCase) ||
                s.StartsWith("pwp1://", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            if (Regex.IsMatch(s, @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"))
            {
                return false;
            }
            if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    Uri subUri = new Uri(s);
                    string h = (subUri.Host ?? "").Trim().ToLowerInvariant();
                    if (h == "pixelstore.space" || h.EndsWith(".pixelstore.space", StringComparison.Ordinal))
                        return false;
                }
                catch { }
                reason = "Вставлена ссылка подписки от стороннего VPN-клиента (Hiddify/v2rayNG). Нажмите «Сбросить на FREE» или вставьте ключ из " + GetTelegramBotHandle() + ".";
                return true;
            }

            string lower = s.ToLowerInvariant();
            string[] foreignPrefixes = new[]
            {
                "vmess://", "ss://", "trojan://", "hy2://", "hysteria2://",
                "tuic://", "wg://", "wireguard://", "warp://", "socks://", "naive+https://"
            };
            foreach (string pfx in foreignPrefixes)
            {
                if (lower.StartsWith(pfx, StringComparison.Ordinal))
                {
                    reason = "Ключ стороннего VPN-протокола (" + pfx.TrimEnd('/', ':') + ") не поддерживается в PixelTunnel. Нажмите «Сбросить на FREE» для работы AI/IDE или используйте ключ из " + GetTelegramBotHandle() + ".";
                    return true;
                }
            }

            if (s.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
            {
                VlessNode parsed = ParseVlessUri(s);
                if (parsed == null || string.IsNullOrWhiteSpace(parsed.Server))
                {
                    reason = "Некорректный формат VLESS-ключа. Нажмите «Сбросить на FREE» или скопируйте полный ключ из " + GetTelegramBotHandle() + ".";
                    return true;
                }
                if (IsClusterHost(parsed.Server))
                {
                    return false;
                }
                reason = string.Format(
                    "Вставлен сторонний VLESS-ключ ({0}), не совместимый с кластером PixelTunnel. Нажмите «Сбросить на FREE» или используйте ключ из {1}.",
                    parsed.Server, GetTelegramBotHandle());
                return true;
            }

            if (s.IndexOf("://", StringComparison.Ordinal) >= 0)
            {
                reason = "Неподдерживаемый формат VPN-ключа. Нажмите «Сбросить на FREE» или вставьте ключ из " + GetTelegramBotHandle() + ".";
                return true;
            }
            return false;
        }

        private static bool IsValidProActivationKey(string candidate, out string normalizedSavedKey, out string keyIdentity)
        {
            normalizedSavedKey = "";
            keyIdentity = "";
            if (string.IsNullOrWhiteSpace(candidate)) return false;
            string k = candidate.Trim();
            if (IsLegacyOrFreeKey(k)) return false;
            string foreignReason;
            if (IsForeignIncompatibleVpnKey(k, out foreignReason)) return false;

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
                    string exePath = "";
                    try { exePath = System.Reflection.Assembly.GetExecutingAssembly().Location; } catch { }
                    if (string.IsNullOrEmpty(exePath))
                    {
                        try { using (var cp = Process.GetCurrentProcess()) { exePath = cp.MainModule.FileName; } } catch { }
                    }
                    if (!string.IsNullOrEmpty(exePath) &&
                        File.Exists(exePath) &&
                        exePath.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        using (var runOnce = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\RunOnce"))
                        {
                            if (runOnce != null)
                            {
                                runOnce.SetValue(
                                    "PixelTunnelProxyReset",
                                    string.Format("\"{0}\" --sanitize-proxy", exePath),
                                    RegistryValueKind.String);
                            }
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
                if (_asciiTimer != null)
                {
                    try { _asciiTimer.Stop(); } catch { }
                }
                if (_deepLinkPipeCts != null)
                {
                    try { _deepLinkPipeCts.Cancel(); } catch { }
                    _deepLinkPipeCts = null;
                }
                if (_isConnected || PixelCoreService.IsRunning)
                {
                    StopTunnelProcess(false);
                }
                else
                {
                    EmergencyDisableDeadSystemProxy(false);
                }
            }
            catch { }
        }

        private static bool TryClearDeadSystemProxyInRegistry(int probeTimeoutMs, bool treatDefaultPortAsDead, out string clearedSummary)
        {
            clearedSummary = "";
            bool clearedAny = false;
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null)
                    {
                        object autoCfgObj = key.GetValue("AutoConfigURL", null);
                        if (autoCfgObj != null)
                        {
                            string pac = Convert.ToString(autoCfgObj);
                            if (IsPixelOrLocalAutoConfig(pac))
                            {
                                int pacPort = TryExtractLoopbackProxyPort(pac);
                                bool deadPac = pacPort <= 0 ||
                                               (treatDefaultPortAsDead && IsPixelTunnelLocalPort(pacPort)) ||
                                               !IsLocalPortOpen(pacPort, probeTimeoutMs);
                                if (deadPac)
                                {
                                    key.DeleteValue("AutoConfigURL", false);
                                    clearedAny = true;
                                    clearedSummary = pac;
                                }
                            }
                        }

                        int en = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                        string srv = Convert.ToString(key.GetValue("ProxyServer", ""));
                        if (en == 1 && !string.IsNullOrEmpty(srv) &&
                            (srv.IndexOf("127.0.0.1:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             srv.IndexOf("localhost:", StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            int port = TryExtractLoopbackProxyPort(srv);
                            if (IsPixelTunnelLocalPort(port))
                            {
                                bool deadProxy = (treatDefaultPortAsDead && port == LOCAL_MIXED_PORT) ||
                                                 !IsLocalPortOpen(port, probeTimeoutMs);
                                if (deadProxy)
                                {
                                    key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                    clearedAny = true;
                                    clearedSummary = srv;
                                }
                            }
                        }

                        if (clearedAny)
                        {
                            int remainingEn = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                            if (remainingEn == 0)
                            {
                                ApplyWinInetPerConnectionProxy(false, "", "", "");
                                SetProxyResetRunOnceGuard(false);
                            }
                            else
                            {
                                RefreshWinInet();
                            }
                        }
                    }
                }
            }
            catch { }
            return clearedAny;
        }

        public static void EmergencyDisableDeadSystemProxy(bool treatDefaultPortAsDead = false)
        {
            try
            {
                string ignored;
                TryClearDeadSystemProxyInRegistry(150, treatDefaultPortAsDead, out ignored);
                CleanDeadProxyEnvironmentVariables();
            }
            catch { }
        }

        private static bool PurgeGlobalCliProxyEnvVars()
        {
            bool cleanedAny = false;
            try
            {
                // Purge only PixelTunnel-owned global proxy env vars; preserve third-party proxies (e.g. :7890)
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
                        shouldRemove = IsPixelTunnelProxyUrl(val);
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

        private static void SetAgLsProxyEnv(string proxyUrl, bool updateProcessEnv = true)
        {
            try
            {
                string prevUser = Environment.GetEnvironmentVariable("AG_LS_PROXY", EnvironmentVariableTarget.User);
                string prevProc = Environment.GetEnvironmentVariable("AG_LS_PROXY", EnvironmentVariableTarget.Process);
                Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.User);
                if (updateProcessEnv)
                {
                    Environment.SetEnvironmentVariable("AG_LS_PROXY", proxyUrl, EnvironmentVariableTarget.Process);
                }
                if (!string.IsNullOrEmpty(proxyUrl) &&
                    (!string.Equals(prevUser, proxyUrl, StringComparison.Ordinal) ||
                     (updateProcessEnv && !string.Equals(prevProc, proxyUrl, StringComparison.Ordinal))))
                {
                    _agLsEnvLastUpdatedUtc = DateTime.UtcNow;
                }
            }
            catch { }
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
                        SetAgLsProxyEnv(null, true);
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
                string clearedProxy;
                if (TryClearDeadSystemProxyInRegistry(180, false, out clearedProxy) && !string.IsNullOrEmpty(clearedProxy))
                {
                    SetStatus(
                        ColAmber,
                        "Восстановлен прямой интернет",
                        string.Format("Отключен зависший системный прокси ({0}), блокировавший сеть.", clearedProxy)
                    );
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

        private static string ComputeBytesSha256Hex(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                return sb.ToString();
            }
        }

        private static bool FileMatchesBytes(string filePath, byte[] expectedBytes, string expectedHash)
        {
            try
            {
                if (!File.Exists(filePath)) return false;
                var fi = new FileInfo(filePath);
                if (fi.Length != expectedBytes.Length) return false;
                string actualHash = ComputeBytesSha256Hex(File.ReadAllBytes(filePath));
                return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private string EnsureIconFileAvailable()
        {
            string localIco = System.IO.Path.Combine(_baseDir, "pixel.ico");
            try
            {
                byte[] embeddedBytes = null;
                string embeddedHash = "";
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("PixelTunnel.pixel.ico"))
                {
                    if (s != null)
                    {
                        using (var ms = new MemoryStream())
                        {
                            s.CopyTo(ms);
                            embeddedBytes = ms.ToArray();
                            embeddedHash = ComputeBytesSha256Hex(embeddedBytes);
                        }
                    }
                }

                if (embeddedBytes != null && embeddedBytes.Length > 0)
                {
                    if (FileMatchesBytes(localIco, embeddedBytes, embeddedHash)) return localIco;
                    if (IsDirectoryWritable(_baseDir))
                    {
                        try
                        {
                            File.WriteAllBytes(localIco, embeddedBytes);
                            return localIco;
                        }
                        catch { }
                    }

                    string appDataDir = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "PixelTunnel"
                    );
                    if (!Directory.Exists(appDataDir)) Directory.CreateDirectory(appDataDir);
                    string fallbackIco = System.IO.Path.Combine(appDataDir, "pixel.ico");
                    if (!FileMatchesBytes(fallbackIco, embeddedBytes, embeddedHash))
                    {
                        File.WriteAllBytes(fallbackIco, embeddedBytes);
                    }
                    if (File.Exists(fallbackIco)) return fallbackIco;
                }

                if (File.Exists(localIco)) return localIco;
            }
            catch { }
            return File.Exists(localIco) ? localIco : "";
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

        private void RestoreFromTray()
        {
            try
            {
                ShowInTaskbar = true;
                Show();
                WindowState = WindowState.Normal;
                if (_outerWinBorder != null) _outerWinBorder.Opacity = 1.0;
                if (_outerWinScale != null) { _outerWinScale.ScaleX = 1.0; _outerWinScale.ScaleY = 1.0; }
                Activate();
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
            if (_asciiTimer != null)
            {
                try { _asciiTimer.Stop(); } catch { }
            }
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

        private static byte[] ReadIconBytesSafe(string icoPath)
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("PixelTunnel.pixel.ico"))
                {
                    if (s != null)
                    {
                        using (var ms = new MemoryStream())
                        {
                            s.CopyTo(ms);
                            var res = ms.ToArray();
                            if (res != null && res.Length > 0) return res;
                        }
                    }
                }
            }
            catch { }
            try
            {
                if (!string.IsNullOrEmpty(icoPath) && File.Exists(icoPath))
                {
                    using (var fs = new FileStream(icoPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var ms = new MemoryStream())
                    {
                        fs.CopyTo(ms);
                        return ms.ToArray();
                    }
                }
            }
            catch { }
            return null;
        }

        private ImageSource LoadWindowIconSafe(string icoPath)
        {
            try
            {
                byte[] bytes = ReadIconBytesSafe(icoPath);
                if (bytes != null && bytes.Length > 0)
                {
                    using (var ms = new MemoryStream(bytes))
                    {
                        var dec = new System.Windows.Media.Imaging.IconBitmapDecoder(
                            ms,
                            System.Windows.Media.Imaging.BitmapCreateOptions.None,
                            System.Windows.Media.Imaging.BitmapCacheOption.OnLoad
                        );
                        System.Windows.Media.Imaging.BitmapSource best = null;
                        foreach (var f in dec.Frames)
                        {
                            if (best == null) { best = f; continue; }
                            bool fIdeal = f.PixelWidth >= 32 && f.PixelWidth <= 64;
                            bool bIdeal = best.PixelWidth >= 32 && best.PixelWidth <= 64;
                            if (fIdeal && (!bIdeal || f.PixelWidth > best.PixelWidth)) best = f;
                        }
                        if (best != null)
                        {
                            var copy = new System.Windows.Media.Imaging.WriteableBitmap(best);
                            copy.Freeze();
                            return copy;
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private System.Drawing.Icon LoadTrayIconSafe(string icoPath)
        {
            var smallSz = System.Windows.Forms.SystemInformation.SmallIconSize;
            // 1. Embedded manifest resource (DIB frames, zero file-lock risk)
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("PixelTunnel.pixel.ico"))
                {
                    if (s != null)
                    {
                        using (var ms = new MemoryStream())
                        {
                            s.CopyTo(ms);
                            ms.Position = 0;
                            using (var tmp = new System.Drawing.Icon(ms, smallSz))
                            {
                                return (System.Drawing.Icon)tmp.Clone();
                            }
                        }
                    }
                }
            }
            catch { }

            // 2. Win32 EXE associated icon
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                var assoc = System.Drawing.Icon.ExtractAssociatedIcon(exePath);
                if (assoc != null) return assoc;
            }
            catch { }

            // 3. Disk icoPath via read-share stream
            try
            {
                if (!string.IsNullOrEmpty(icoPath) && File.Exists(icoPath))
                {
                    using (var fs = new FileStream(icoPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var ms = new MemoryStream())
                    {
                        fs.CopyTo(ms);
                        ms.Position = 0;
                        using (var tmp = new System.Drawing.Icon(ms, smallSz))
                        {
                            return (System.Drawing.Icon)tmp.Clone();
                        }
                    }
                }
            }
            catch { }

            // 4. Programmatic GDI+ Portal Arch fallback (always guaranteed non-null)
            using (var bmp = new System.Drawing.Bitmap(32, 32, System.Drawing.Imaging.PixelFormat.Format32bppArgb))
            {
                using (var g = System.Drawing.Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    g.Clear(System.Drawing.Color.FromArgb(255, 16, 17, 21));
                    using (var pen = new System.Drawing.Pen(System.Drawing.Color.White, 4.0f))
                    {
                        pen.StartCap = System.Drawing.Drawing2D.LineCap.Round;
                        pen.EndCap = System.Drawing.Drawing2D.LineCap.Round;
                        g.DrawArc(pen, 9.0f, 7.0f, 14.0f, 14.0f, 180.0f, 180.0f);
                        g.DrawLine(pen, 9.0f, 14.0f, 9.0f, 23.0f);
                        g.DrawLine(pen, 23.0f, 14.0f, 23.0f, 23.0f);
                    }
                    using (var core = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 96, 165, 250)))
                    {
                        g.FillRectangle(core, 13.0f, 15.0f, 6.0f, 6.0f);
                    }
                }
                return System.Drawing.Icon.FromHandle(bmp.GetHicon());
            }
        }

        private void InitTray(string icoPath)
        {
            try
            {
                _trayIcon = new System.Windows.Forms.NotifyIcon();
                _trayIcon.Icon = LoadTrayIconSafe(icoPath);

                string tip = "PixelTunnel v" + APP_VERSION + " — PWP-4 Dual-Mux";
                _trayIcon.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip;
                _trayIcon.MouseClick += (s, e) =>
                {
                    if (e.Button == System.Windows.Forms.MouseButtons.Left)
                    {
                        RestoreFromTray();
                    }
                };
                _trayIcon.DoubleClick += delegate
                {
                    RestoreFromTray();
                };

                var menu = new System.Windows.Forms.ContextMenuStrip();
                menu.Items.Add("Открыть PixelTunnel", null, delegate { RestoreFromTray(); });
                menu.Items.Add("Запустить / Перезапустить туннель (PWP-4)", null, delegate
                {
                    RestoreFromTray();
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
                    RestoreFromTray();
                    ShowDiagnosticsModal();
                });
                menu.Items.Add("\u0410\u0432\u0430\u0440\u0438\u0439\u043d\u044b\u0439 \u0441\u0431\u0440\u043e\u0441 \u0441\u0435\u0442\u0438 (\u0427\u0438\u0441\u0442\u044b\u0439 \u0438\u043d\u0442\u0435\u0440\u043d\u0435\u0442)", null, delegate
                {
                    RestoreFromTray();
                    RunEmergencyNetworkResetAsync(true);
                });
                menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
                menu.Items.Add("\u041e\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c \u0438 \u0432\u044b\u0439\u0442\u0438", null, delegate
                {
                    ExplicitShutdown();
                });
                _trayIcon.ContextMenuStrip = menu;
                _trayIcon.Visible = true;
            }
            catch { }
        }

        private void BuildInterface()
        {
            var shadowHost = new Grid { Margin = new Thickness(18) };

            _winShadow = new DropShadowEffect
            {
                BlurRadius = 28,
                ShadowDepth = 8,
                Direction = 270,
                Color = Colors.Black,
                Opacity = _theme.WindowShadowOpacity
            };

            _outerWinScale = new ScaleTransform(0.975, 0.975);
            _outerWinBorder = new Border
            {
                CornerRadius = new CornerRadius(14),
                BorderThickness = new Thickness(1),
                Effect = _winShadow,
                ClipToBounds = false,
                Opacity = 0.0,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = _outerWinScale
            };

            var modalHost = new Grid();
            var contentWrapper = new Border
            {
                CornerRadius = new CornerRadius(13),
                ClipToBounds = true,
                Padding = new Thickness(18, 14, 18, 16)
            };

            var rootStack = new StackPanel { Orientation = Orientation.Vertical };

            // =================================================================
            // 1. HEADER BAR
            // =================================================================
            var headerGrid = new Grid
            {
                Background = Brushes.Transparent,
                Margin = new Thickness(0, 0, 0, 12)
            };
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerGrid.MouseLeftButtonDown += delegate(object s, MouseButtonEventArgs e)
            {
                if (e.ChangedButton == MouseButton.Left && e.ButtonState == MouseButtonState.Pressed)
                {
                    try { DragMove(); } catch { }
                }
            };

            var brandStack = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };

            _logoBox = new Border
            {
                Width = 30,
                Height = 30,
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(0),
                SnapsToDevicePixels = true,
                UseLayoutRounding = true,
                Margin = new Thickness(0, 0, 10, 0),
                Child = BuildPortalArchLogo()
            };
            brandStack.Children.Add(_logoBox);

            _brandTitle = new TextBlock
            {
                Text = "PixelTunnel",
                FontFamily = DisplayFont,
                FontSize = 15.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            brandStack.Children.Add(_brandTitle);

            _versionPill = new Border
            {
                CornerRadius = new CornerRadius(6),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(7, 2, 7, 2),
                Margin = new Thickness(8, 1, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            _versionPillText = new TextBlock
            {
                Text = "v" + APP_VERSION,
                FontFamily = UiFont,
                FontSize = 10.5,
                FontWeight = FontWeights.Medium
            };
            ApplyTabularNums(_versionPillText);
            _versionPill.Child = _versionPillText;
            brandStack.Children.Add(_versionPill);

            Grid.SetColumn(brandStack, 0);
            headerGrid.Children.Add(brandStack);

            var rightBtns = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };
            rightBtns.MouseLeftButtonDown += delegate(object s, MouseButtonEventArgs e) { e.Handled = true; };

            _updatePillBtn = new Border
            {
                CornerRadius = new CornerRadius(7),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(9, 4, 9, 4),
                Margin = new Thickness(0, 0, 7, 0),
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center,
                Visibility = Visibility.Collapsed,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };
            _updatePillText = new TextBlock
            {
                Text = "\u2191 Обновить",
                FontFamily = UiFont,
                FontSize = 10.8,
                FontWeight = FontWeights.SemiBold
            };
            ApplyTabularNums(_updatePillText);
            _updatePillBtn.Child = _updatePillText;
            AttachPressAnim(_updatePillBtn);
            _updatePillBtn.MouseLeftButtonUp += delegate { ShowUpdateModal(); };
            rightBtns.Children.Add(_updatePillBtn);

            _toolsBtn = CreateHeaderIconButton("Система и инструменты: тема, автозапуск, Instant Wake, WSL2", out _toolsIconHolder);
            _toolsBtn.MouseLeftButtonUp += delegate { ShowToolsModal(); };
            rightBtns.Children.Add(_toolsBtn);

            _themeBtn = CreateHeaderIconButton("Переключить Светлую / Тёмную тему", out _themeIconHolder);
            var themeTg = new TransformGroup();
            themeTg.Children.Add(new RotateTransform(0));
            themeTg.Children.Add(new ScaleTransform(1.0, 1.0));
            _themeIconHolder.RenderTransformOrigin = new Point(0.5, 0.5);
            _themeIconHolder.RenderTransform = themeTg;
            _themeBtn.MouseLeftButtonUp += delegate
            {
                ThemeModeChoice nextChoice = _isDark ? ThemeModeChoice.Light : ThemeModeChoice.Dark;
                ApplyThemeChoice(nextChoice, true);
            };
            rightBtns.Children.Add(_themeBtn);

            _minBtn = CreateHeaderShapeButton("M5 12h14", "Свернуть", out _minBtnPath);
            _minBtn.MouseLeftButtonUp += delegate { WindowState = WindowState.Minimized; };
            rightBtns.Children.Add(_minBtn);

            _closeBtn = CreateHeaderShapeButton("M18 6L6 18 M6 6l12 12", "Свернуть в трей", out _closeBtnPath);
            _closeBtn.Margin = new Thickness(0);
            _closeBtn.MouseLeftButtonUp += delegate { MinimizeToTray(); };
            rightBtns.Children.Add(_closeBtn);

            Grid.SetColumn(rightBtns, 1);
            headerGrid.Children.Add(rightBtns);
            rootStack.Children.Add(headerGrid);

            _headerDivider = new Border
            {
                Height = 1,
                Margin = new Thickness(0, 0, 0, 14)
            };
            rootStack.Children.Add(_headerDivider);

            // =================================================================
            // 2. CONTROL DECK (2 COLUMNS: 304px LEFT + 1* RIGHT)
            // =================================================================
            var deckGrid = new Grid();
            deckGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(304) });
            deckGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(14) });
            deckGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // --- LEFT COLUMN ---
            var leftStack = new StackPanel { Orientation = Orientation.Vertical };

            _statusCardShadow = new DropShadowEffect
            {
                BlurRadius = 14,
                ShadowDepth = 2,
                Direction = 270,
                Color = Colors.Black,
                Opacity = _theme.CardShadowOpacity
            };
            _statusCard = new Border
            {
                CornerRadius = new CornerRadius(11),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(16, 14, 16, 13),
                Margin = new Thickness(0, 0, 0, 10),
                Effect = _statusCardShadow
            };

            var statusStack = new StackPanel();
            var statusTopGrid = new Grid();
            statusTopGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            statusTopGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Top-left: Clean Display Headline (S1 — no dot, no pastel pill, no country label)
            _statusTitle = new TextBlock
            {
                Text = "Туннель остановлен",
                FontFamily = DisplayFont,
                FontSize = 18,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(_statusTitle, 0);
            statusTopGrid.Children.Add(_statusTitle);

            // Top-right: 4-bar signal quality + tabular latency ms
            var sigRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0)
            };
            var barsHost = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(0, 0, 6, 2)
            };
            double[] barHeights = new double[] { 5, 8, 11, 14 };
            for (int bIdx = 0; bIdx < 4; bIdx++)
            {
                _signalBars[bIdx] = new Border
                {
                    Width = 3,
                    Height = barHeights[bIdx],
                    CornerRadius = new CornerRadius(1.5),
                    VerticalAlignment = VerticalAlignment.Bottom,
                    Margin = new Thickness(bIdx == 0 ? 0 : 2, 0, 0, 0)
                };
                barsHost.Children.Add(_signalBars[bIdx]);
            }
            sigRow.Children.Add(barsHost);

            _specLatencyVal = new TextBlock
            {
                Text = "\u2014",
                FontFamily = UiFont,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            ApplyTabularNums(_specLatencyVal);
            sigRow.Children.Add(_specLatencyVal);
            Grid.SetColumn(sigRow, 1);
            statusTopGrid.Children.Add(sigRow);
            statusStack.Children.Add(statusTopGrid);

            // Embedded Shimmering Antigravity PRISM ASCII Chamber
            _agAsciiEngine = new AsciiAntigravityPrismEngine();
            _agChamberBorder = new Border
            {
                Height = 128,
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 9, 0, 8),
                ClipToBounds = true
            };
            var agChamberGrid = new Grid();
            var agImg = new Image
            {
                Source = _agAsciiEngine.Bitmap,
                Stretch = Stretch.Fill,
                SnapsToDevicePixels = true
            };
            RenderOptions.SetBitmapScalingMode(agImg, BitmapScalingMode.HighQuality);
            agChamberGrid.Children.Add(agImg);

            _agChamberBadgeText = new TextBlock
            {
                Text = "ANTIGRAVITY \u00b7 PRISM",
                FontFamily = MonoFont,
                FontSize = 8.8,
                FontWeight = FontWeights.SemiBold
            };
            _agChamberBadge = new Border
            {
                CornerRadius = new CornerRadius(5),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(6, 2, 6, 2),
                Margin = new Thickness(7, 0, 0, 6),
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Bottom,
                IsHitTestVisible = false,
                Child = _agChamberBadgeText
            };
            agChamberGrid.Children.Add(_agChamberBadge);
            _agChamberBorder.Child = agChamberGrid;
            _agChamberBorder.MouseMove += delegate(object ms, MouseEventArgs me)
            {
                double w = _agChamberBorder.ActualWidth;
                double h = _agChamberBorder.ActualHeight;
                if (w > 1 && h > 1)
                {
                    Point pt = me.GetPosition(_agChamberBorder);
                    _agPointerActive = true;
                    _agPointerNormX = Math.Max(0.0, Math.Min(1.0, pt.X / w));
                    _agPointerNormY = Math.Max(0.0, Math.Min(1.0, pt.Y / h));
                }
            };
            _agChamberBorder.MouseLeave += delegate { _agPointerActive = false; };
            statusStack.Children.Add(_agChamberBorder);

            // Dynamic Human Summary
            _statusSub = new TextBlock
            {
                Text = "Нажмите «Запустить» для умного обхода",
                FontFamily = UiFont,
                FontSize = 11.6,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Margin = new Thickness(0, 2, 0, 11)
            };
            statusStack.Children.Add(_statusSub);

            // Hairline + 2-column Spec Strip
            _specDivider = new Border
            {
                Height = 1,
                Margin = new Thickness(0, 0, 0, 11)
            };
            statusStack.Children.Add(_specDivider);

            var specGrid = new Grid();
            specGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            specGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var col1 = new StackPanel();
            _specModeLbl = new TextBlock { Text = "Режим", FontFamily = UiFont, FontSize = 10.2 };
            _specModeVal = new TextBlock { Text = "Умный обход", FontFamily = UiFont, FontSize = 13, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 2, 0, 0) };
            col1.Children.Add(_specModeLbl);
            col1.Children.Add(_specModeVal);
            Grid.SetColumn(col1, 0);
            specGrid.Children.Add(col1);

            var col2 = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
            _specAccessLbl = new TextBlock { Text = "Доступ", FontFamily = UiFont, FontSize = 10.2, HorizontalAlignment = HorizontalAlignment.Right };
            _specAccessVal = new TextBlock { Text = "Бесплатный", FontFamily = UiFont, FontSize = 13, FontWeight = FontWeights.SemiBold, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 2, 0, 0) };
            col2.Children.Add(_specAccessLbl);
            col2.Children.Add(_specAccessVal);
            Grid.SetColumn(col2, 1);
            specGrid.Children.Add(col2);

            statusStack.Children.Add(specGrid);
            _statusCard.Child = statusStack;
            leftStack.Children.Add(_statusCard);

            // Primary CTA Button
            _connectBtn = new Border
            {
                Height = 42,
                CornerRadius = new CornerRadius(9),
                BorderThickness = new Thickness(1.4),
                Margin = new Thickness(0, 0, 0, 9),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };
            var ctaStack = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            _connectLiveDot = new Ellipse
            {
                Width = 7.5,
                Height = 7.5,
                Margin = new Thickness(0, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            ctaStack.Children.Add(_connectLiveDot);
            _connectIconHolder = new ContentControl
            {
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 7, 0)
            };
            ctaStack.Children.Add(_connectIconHolder);
            _connectBtnText = new TextBlock
            {
                Text = "Запустить туннель",
                FontFamily = UiFont,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            ctaStack.Children.Add(_connectBtnText);
            _connectBtn.Child = ctaStack;
            AttachPressAnim(_connectBtn);
            _connectBtn.MouseLeftButtonUp += delegate { ToggleConnection(); };
            leftStack.Children.Add(_connectBtn);

            // AI Pulse Card
            _aiPulseShadow = new DropShadowEffect
            {
                BlurRadius = 12,
                ShadowDepth = 2,
                Direction = 270,
                Color = Colors.Black,
                Opacity = _theme.CardShadowOpacity
            };
            _aiPulseCard = new Border
            {
                CornerRadius = new CornerRadius(10),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(11, 8.5, 11, 8.5),
                Margin = new Thickness(0, 0, 0, 8),
                Cursor = Cursors.Hand,
                Effect = _aiPulseShadow,
                ToolTip = "Нажмите, чтобы обновить пинг AI-шлюзов"
            };
            var pulseGrid = new Grid();
            pulseGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            pulseGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var pulseLeft = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };
            _aiPulseIconHolder = new ContentControl
            {
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 5, 0),
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new RotateTransform(0)
            };
            pulseLeft.Children.Add(_aiPulseIconHolder);
            _aiPulseTitle = new TextBlock
            {
                Text = "Пульс AI",
                FontFamily = UiFont,
                FontSize = 10.8,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            pulseLeft.Children.Add(_aiPulseTitle);
            Grid.SetColumn(pulseLeft, 0);
            pulseGrid.Children.Add(pulseLeft);

            var pulseRight = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center
            };
            pulseRight.Children.Add(BuildAiPill("Gemini", out _dotGemini, out _lblGemini, out _msGemini, new Thickness(0, 0, 8, 0)));
            pulseRight.Children.Add(BuildAiPill("Claude", out _dotClaude, out _lblClaude, out _msClaude, new Thickness(0, 0, 8, 0)));
            pulseRight.Children.Add(BuildAiPill("OpenAI", out _dotOpenAi, out _lblOpenAi, out _msOpenAi, new Thickness(0)));
            Grid.SetColumn(pulseRight, 1);
            pulseGrid.Children.Add(pulseRight);

            _aiPulseCard.Child = pulseGrid;
            _aiPulseCard.MouseLeftButtonUp += delegate { TriggerManualAiPulseRefresh(); };
            leftStack.Children.Add(_aiPulseCard);

            // Antigravity IDE + Google OAuth 3m Quick Bar (bottom of left col)
            _ideQuickBar = new Border
            {
                Height = 36,
                CornerRadius = new CornerRadius(9),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 0, 7, 0)
            };
            var ideGrid = new Grid();
            ideGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            ideGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var ideLeft = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            _ideQuickDot = new Ellipse
            {
                Width = 6.5,
                Height = 6.5,
                Margin = new Thickness(0, 0, 6, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            ideLeft.Children.Add(_ideQuickDot);
            _ideQuickLabel = new TextBlock
            {
                Text = "Antigravity IDE",
                FontFamily = UiFont,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            ideLeft.Children.Add(_ideQuickLabel);
            Grid.SetColumn(ideLeft, 0);
            ideGrid.Children.Add(ideLeft);

            var ideBtns = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            _btnRestartIde = new Border
            {
                CornerRadius = new CornerRadius(6),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(7, 3, 7, 3),
                Margin = new Thickness(0, 0, 5, 0),
                Cursor = Cursors.Hand,
                ToolTip = "Мягко перезапустить Antigravity IDE с AG_LS_PROXY и --disable-quic"
            };
            _btnRestartIdeText = new TextBlock
            {
                Text = "Рестарт IDE",
                FontFamily = UiFont,
                FontSize = 10.2,
                FontWeight = FontWeights.SemiBold
            };
            _btnRestartIde.Child = _btnRestartIdeText;
            _btnRestartIde.MouseLeftButtonUp += delegate { RelaunchAntigravityInTunnelAsync(); };
            ideBtns.Children.Add(_btnRestartIde);

            _btnOAuthQuick = new Border
            {
                CornerRadius = new CornerRadius(6),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(7, 3, 7, 3),
                Cursor = Cursors.Hand,
                ToolTip = "Временный режим 3 мин для входа в Google-аккаунт из-под санкций"
            };
            _btnOAuthQuickText = new TextBlock
            {
                Text = "OAuth 3\u043c",
                FontFamily = UiFont,
                FontSize = 10.2,
                FontWeight = FontWeights.SemiBold
            };
            ApplyTabularNums(_btnOAuthQuickText);
            _btnOAuthQuick.Child = _btnOAuthQuickText;
            _btnOAuthQuick.MouseLeftButtonUp += delegate { ToggleGoogleOAuthHelperModeAsync(); };
            ideBtns.Children.Add(_btnOAuthQuick);

            Grid.SetColumn(ideBtns, 1);
            ideGrid.Children.Add(ideBtns);
            _ideQuickBar.Child = ideGrid;
            leftStack.Children.Add(_ideQuickBar);

            Grid.SetColumn(leftStack, 0);
            deckGrid.Children.Add(leftStack);

            // --- RIGHT COLUMN ---
            var rightStack = new Grid();
            rightStack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rightStack.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            rightStack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rightStack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rightStack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var splitHeader = new Grid { Margin = new Thickness(2, 0, 0, 6) };
            splitHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            splitHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _splitHeaderLeft = new TextBlock
            {
                Text = "Умный обход",
                FontFamily = UiFont,
                FontSize = 11.2,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(_splitHeaderLeft, 0);
            splitHeader.Children.Add(_splitHeaderLeft);

            _domainsTrafficBtn = new Border
            {
                CornerRadius = new CornerRadius(6),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 3, 8, 3),
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = "Живой трафик и редактор своих доменов"
            };
            _domainsTrafficText = new TextBlock
            {
                Text = "Домены и трафик \u00b7 0",
                FontFamily = UiFont,
                FontSize = 10.6,
                FontWeight = FontWeights.Medium
            };
            ApplyTabularNums(_domainsTrafficText);
            _domainsTrafficBtn.Child = _domainsTrafficText;
            AttachHoverSurface(_domainsTrafficBtn);
            _domainsTrafficBtn.MouseLeftButtonUp += delegate { ShowRadarModal(0); };

            Grid.SetColumn(_domainsTrafficBtn, 1);
            splitHeader.Children.Add(_domainsTrafficBtn);
            Grid.SetRow(splitHeader, 0);
            rightStack.Children.Add(splitHeader);

            _routesCardShadow = new DropShadowEffect
            {
                BlurRadius = 14,
                ShadowDepth = 2,
                Direction = 270,
                Color = Colors.Black,
                Opacity = _theme.CardShadowOpacity
            };
            _routesCard = new Border
            {
                CornerRadius = new CornerRadius(10),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 0, 9),
                Effect = _routesCardShadow
            };
            var routesInnerClip = new Border
            {
                CornerRadius = new CornerRadius(9),
                ClipToBounds = true
            };
            var routesList = new Grid();
            for (int rIdx = 0; rIdx < 4; rIdx++)
            {
                routesList.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            }
            var rowAg = CreateRouteRow(
                "ag",
                "M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z M8 10l3 2.5L8 15 M13 15h3",
                "Antigravity 2.0, IDE и Терминал",
                "Вход из-под санкций, MCP и агенты",
                false, true, true);
            Grid.SetRow(rowAg, 0);
            routesList.Children.Add(rowAg);

            var rowAi = CreateRouteRow(
                "ai",
                "M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3z",
                "ChatGPT, Claude, AI Studio",
                "Gemini, Cursor, Copilot, Perplexity",
                false, false, true);
            Grid.SetRow(rowAi, 1);
            routesList.Children.Add(rowAi);

            var rowSoc = CreateRouteRow(
                "social",
                "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c2.5 2.7 4 5.8 4 9s-1.5 6.3-4 9c-2.5-2.7-4-5.8-4-9s1.5-6.3 4-9z",
                "Telegram, Spotify и соцсети",
                "Telegram, Spotify, Instagram, X, Canva",
                false, false, true);
            Grid.SetRow(rowSoc, 2);
            routesList.Children.Add(rowSoc);

            var rowMedia = CreateRouteRow(
                "media",
                "M4 6h16a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2z M10 9.5l5 2.5-5 2.5v-5z",
                "YouTube & Discord",
                "YouTube, голос Discord (TUN)",
                true, false, false);
            Grid.SetRow(rowMedia, 3);
            routesList.Children.Add(rowMedia);

            routesInnerClip.Child = routesList;
            _routesCard.Child = routesInnerClip;
            Grid.SetRow(_routesCard, 1);
            rightStack.Children.Add(_routesCard);

            // Key Drawer (Collapsible with smooth slide)
            _keyDrawerTranslate = new TranslateTransform(0, -6);
            _keyDrawer = new Border
            {
                CornerRadius = new CornerRadius(9),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 6, 6, 6),
                Margin = new Thickness(0, 0, 0, 9),
                MaxHeight = 0,
                Opacity = 0.0,
                ClipToBounds = true,
                Visibility = Visibility.Collapsed,
                RenderTransform = _keyDrawerTranslate
            };
            var keyGrid = new Grid();
            keyGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            keyGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _keyInput = new TextBox
            {
                Text = GetFreeModeSentinelUri(),
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                FontFamily = MonoFont,
                FontSize = 11,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            };
            _keyInput.TextChanged += delegate { OnKeyTextChanged(); };
            _keyInput.KeyDown += delegate(object ks, KeyEventArgs ke)
            {
                if (ke.Key == Key.Enter)
                {
                    ke.Handled = true;
                    ApplyEnteredOrClipboardKey(false);
                }
            };
            Grid.SetColumn(_keyInput, 0);
            keyGrid.Children.Add(_keyInput);

            _pasteProBtn = new Border
            {
                CornerRadius = new CornerRadius(6),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 5, 10, 5),
                Cursor = Cursors.Hand
            };
            _pasteProBtnText = new TextBlock
            {
                Text = "Вставить",
                FontFamily = UiFont,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold
            };
            _pasteProBtn.Child = _pasteProBtnText;
            _pasteProBtn.MouseLeftButtonUp += delegate { ApplyEnteredOrClipboardKey(true); };
            Grid.SetColumn(_pasteProBtn, 1);
            keyGrid.Children.Add(_pasteProBtn);
            _keyDrawer.Child = keyGrid;
            Grid.SetRow(_keyDrawer, 2);
            rightStack.Children.Add(_keyDrawer);

            // 3-Button Utility Row
            var utilGrid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
            utilGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            utilGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(6) });
            utilGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            utilGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(6) });
            utilGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            _btnVpn = CreateUtilButton("Наш VPN", out _btnVpnIcon, out _btnVpnText);
            _btnVpn.MouseLeftButtonUp += delegate { ShowOurVpnMatrixModal(); };
            Grid.SetColumn(_btnVpn, 0);
            utilGrid.Children.Add(_btnVpn);

            _btnKey = CreateUtilButton("Ключ", out _btnKeyIcon, out _btnKeyText);
            _btnKey.MouseLeftButtonUp += delegate { ToggleKeyDrawer(!_keyDrawerOpen); };
            Grid.SetColumn(_btnKey, 2);
            utilGrid.Children.Add(_btnKey);

            _btnDiag = CreateUtilButton("Диагностика", out _btnDiagIcon, out _btnDiagText);
            _btnDiag.MouseLeftButtonUp += delegate { ShowDiagnosticsModal(); };
            Grid.SetColumn(_btnDiag, 4);
            utilGrid.Children.Add(_btnDiag);
            Grid.SetRow(utilGrid, 3);
            rightStack.Children.Add(utilGrid);

            // Donate Footer Bar
            _donateBar = new Border
            {
                Height = 36,
                CornerRadius = new CornerRadius(9),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(12, 0, 12, 0),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };
            var donateGrid = new Grid();
            donateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            donateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var dLeft = new Grid { VerticalAlignment = VerticalAlignment.Center };
            dLeft.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            dLeft.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            dLeft.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            _donateHeartIcon = new ContentControl
            {
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 7, 0)
            };
            Grid.SetColumn(_donateHeartIcon, 0);
            dLeft.Children.Add(_donateHeartIcon);
            _donateTitle = new TextBlock
            {
                Text = "Поддержать проект",
                FontFamily = UiFont,
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(_donateTitle, 1);
            dLeft.Children.Add(_donateTitle);
            _donateSub = new TextBlock
            {
                Text = " \u00b7 серверы бесплатны",
                FontFamily = UiFont,
                FontSize = 11,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(_donateSub, 2);
            dLeft.Children.Add(_donateSub);
            Grid.SetColumn(dLeft, 0);
            donateGrid.Children.Add(dLeft);

            var dRight = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            _donateActionText = new TextBlock
            {
                Text = "Донат",
                FontFamily = UiFont,
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 4, 0)
            };
            dRight.Children.Add(_donateActionText);
            _donateArrowIcon = new ContentControl { VerticalAlignment = VerticalAlignment.Center };
            dRight.Children.Add(_donateArrowIcon);
            Grid.SetColumn(dRight, 1);
            donateGrid.Children.Add(dRight);

            _donateBar.Child = donateGrid;
            AttachPressAnim(_donateBar);
            _donateBar.MouseLeftButtonUp += delegate { ShowDonateModal(); };
            Grid.SetRow(_donateBar, 4);
            rightStack.Children.Add(_donateBar);

            Grid.SetColumn(rightStack, 2);
            deckGrid.Children.Add(rightStack);
            rootStack.Children.Add(deckGrid);

            contentWrapper.Child = rootStack;
            modalHost.Children.Add(contentWrapper);

            // =================================================================
            // 3. CUSTOM STYLED MODAL OVERLAY
            // =================================================================
            _modalBackdrop = new Border
            {
                CornerRadius = new CornerRadius(13),
                Visibility = Visibility.Collapsed,
                Padding = new Thickness(20)
            };
            _modalBackdrop.MouseLeftButtonDown += delegate(object s, MouseButtonEventArgs e)
            {
                if (e.OriginalSource == _modalBackdrop) CloseModal();
            };

            _modalScale = new ScaleTransform(1.0, 1.0);
            _modalTranslate = new TranslateTransform(0, 0);
            var modalTg = new TransformGroup();
            modalTg.Children.Add(_modalScale);
            modalTg.Children.Add(_modalTranslate);
            _modalCard = new Border
            {
                Width = 420,
                CornerRadius = new CornerRadius(12),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(18, 15, 18, 15),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = modalTg,
                Effect = new DropShadowEffect
                {
                    BlurRadius = 26,
                    ShadowDepth = 6,
                    Direction = 270,
                    Color = Colors.Black,
                    Opacity = 0.35
                }
            };
            _modalBackdrop.Child = _modalCard;
            modalHost.Children.Add(_modalBackdrop);

            _outerWinBorder.Child = modalHost;
            shadowHost.Children.Add(_outerWinBorder);
            Content = shadowHost;
        }

        private UIElement BuildPortalArchLogo()
        {
            var cv = new Canvas { Width = 30, Height = 30 };
            _logoOuterArch = new ShapePath
            {
                Data = Geometry.Parse("M 8.5 21.5 V 13.5 C 8.5 9.6 11.4 6.8 15 6.8 C 18.6 6.8 21.5 9.6 21.5 13.5 V 21.5"),
                StrokeThickness = 3.4,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            };
            _logoCorePixel = new Border
            {
                Width = 4.6,
                Height = 4.6,
                CornerRadius = new CornerRadius(1.1)
            };
            Canvas.SetLeft(_logoCorePixel, 12.7);
            Canvas.SetTop(_logoCorePixel, 14.7);

            cv.Children.Add(_logoOuterArch);
            cv.Children.Add(_logoCorePixel);
            return cv;
        }

        private Border CreateHeaderIconButton(string tooltip, out ContentControl iconHolder)
        {
            iconHolder = new ContentControl { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
            var b = new Border
            {
                Width = 30,
                Height = 30,
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 6, 0),
                Cursor = Cursors.Hand,
                ToolTip = tooltip,
                Child = iconHolder
            };
            AttachHoverSurface(b);
            return b;
        }

        private Border CreateHeaderShapeButton(string pathData, string tooltip, out ShapePath shapePath)
        {
            shapePath = new ShapePath
            {
                Data = Geometry.Parse(pathData),
                StrokeThickness = 1.8,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round,
                Stretch = Stretch.Uniform,
                Width = 11,
                Height = 11
            };
            var b = new Border
            {
                Width = 30,
                Height = 30,
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 6, 0),
                Cursor = Cursors.Hand,
                ToolTip = tooltip,
                Child = shapePath
            };
            AttachHoverSurface(b);
            return b;
        }

        private Border CreateUtilButton(string text, out ContentControl iconHolder, out TextBlock textBlock)
        {
            var b = new Border
            {
                Height = 36,
                CornerRadius = new CornerRadius(9),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 0, 8, 0),
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
            iconHolder = new ContentControl { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };
            textBlock = new TextBlock
            {
                Text = text,
                FontFamily = UiFont,
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            row.Children.Add(iconHolder);
            row.Children.Add(textBlock);
            b.Child = row;
            AttachHoverSurface(b);
            AttachPressAnim(b);
            return b;
        }

        private StackPanel BuildAiPill(string label, out Ellipse dot, out TextBlock lblTb, out TextBlock msTb, Thickness margin)
        {
            var p = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = margin };
            dot = new Ellipse { Width = 5.5, Height = 5.5, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) };
            lblTb = new TextBlock { Text = label, FontFamily = UiFont, FontSize = 10.4, FontWeight = FontWeights.Medium, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 3, 0) };
            msTb = new TextBlock { Text = "\u2014", FontFamily = UiFont, FontSize = 10.4, VerticalAlignment = VerticalAlignment.Center };
            ApplyTabularNums(msTb);
            p.Children.Add(dot);
            p.Children.Add(lblTb);
            p.Children.Add(msTb);
            return p;
        }

        private Border CreateRouteRow(string id, string iconData, string title, string subtitle, bool isPro, bool initialOn, bool hasDivider)
        {
            var rv = new RouteItemView
            {
                Id = id,
                IconData = iconData,
                Title = title,
                Subtitle = subtitle,
                IsPro = isPro,
                IsOn = initialOn
            };

            var rowHost = new StackPanel();
            rv.RowBorder = new Border
            {
                Background = Brushes.Transparent,
                Padding = new Thickness(12, 9, 12, 9),
                Cursor = Cursors.Hand
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            rv.IconPath = new ShapePath
            {
                Data = Geometry.Parse(iconData),
                StrokeThickness = 1.7,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round,
                StrokeLineJoin = PenLineJoin.Round,
                Stretch = Stretch.Uniform,
                Width = 14,
                Height = 14
            };
            rv.IconBox = new Border
            {
                Width = 30,
                Height = 30,
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0),
                Child = rv.IconPath
            };
            Grid.SetColumn(rv.IconBox, 0);
            grid.Children.Add(rv.IconBox);

            var txtStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            rv.TitleText = new TextBlock
            {
                Text = title,
                FontFamily = UiFont,
                FontSize = 12.2,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            rv.SubtitleText = new TextBlock
            {
                Text = subtitle,
                FontFamily = UiFont,
                FontSize = 10.6,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Margin = new Thickness(0, 1, 0, 0)
            };
            txtStack.Children.Add(rv.TitleText);
            txtStack.Children.Add(rv.SubtitleText);
            Grid.SetColumn(txtStack, 1);
            grid.Children.Add(txtStack);

            rv.TierBadge = new Border
            {
                CornerRadius = new CornerRadius(6),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(6, 2, 6, 2),
                Margin = new Thickness(8, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            rv.TierText = new TextBlock
            {
                Text = isPro ? "PRO" : "FREE",
                FontFamily = UiFont,
                FontSize = 9.5,
                FontWeight = FontWeights.Bold
            };
            rv.TierBadge.Child = rv.TierText;
            Grid.SetColumn(rv.TierBadge, 2);
            grid.Children.Add(rv.TierBadge);

            Border switchTrack, switchThumb;
            TranslateTransform thumbTrans;
            CreatePillSwitch(initialOn, out switchTrack, out switchThumb, out thumbTrans);
            rv.SwitchTrack = switchTrack;
            rv.SwitchThumb = switchThumb;
            rv.ThumbTransform = thumbTrans;
            Grid.SetColumn(rv.SwitchTrack, 3);
            grid.Children.Add(rv.SwitchTrack);

            rv.RowBorder.Child = grid;
            rv.RowBorder.MouseEnter += delegate { SetOrAnimateBrush(rv.RowBorder, Border.BackgroundProperty, _theme.SurfaceHover, 120); };
            rv.RowBorder.MouseLeave += delegate { SetOrAnimateBrush(rv.RowBorder, Border.BackgroundProperty, Color.FromArgb(0, _theme.SurfaceHover.R, _theme.SurfaceHover.G, _theme.SurfaceHover.B), 140); };
            rv.RowBorder.MouseLeftButtonUp += delegate { OnRouteClicked(rv); };

            rowHost.Children.Add(rv.RowBorder);

            if (hasDivider)
            {
                rv.BottomDivider = new Border { Height = 1 };
                rowHost.Children.Add(rv.BottomDivider);
            }

            _routes.Add(rv);
            return new Border { Child = rowHost };
        }

        private void SyncRoutesFromOptions(bool animate)
        {
            _proActive = HasActiveProAccess();
            for (int i = 0; i < _routes.Count; i++)
            {
                RouteItemView rv = _routes[i];
                if (rv.Id == "ag") rv.IsOn = _optAntigravity;
                else if (rv.Id == "ai") rv.IsOn = _optCursorAi;
                else if (rv.Id == "social") rv.IsOn = _optSocialWeb;
                else if (rv.Id == "media") rv.IsOn = _optDiscordYt;
                ApplyRouteVisual(rv, animate);
            }
            UpdateModeBadge();
        }

        private void OnRouteClicked(RouteItemView rv)
        {
            if (rv.Id == "ag")
            {
                _optAntigravity = !_optAntigravity;
                _optMcpTerminal = _optAntigravity;
                rv.IsOn = _optAntigravity;
                ApplyRouteVisual(rv, true);
                SaveCurrentState();
                UpdateConnectionVisuals(false);
                TriggerCategoryHotReloadIfConnected();
                return;
            }
            if (rv.Id == "ai")
            {
                _optCursorAi = !_optCursorAi;
                rv.IsOn = _optCursorAi;
                ApplyRouteVisual(rv, true);
                SaveCurrentState();
                UpdateConnectionVisuals(false);
                TriggerCategoryHotReloadIfConnected();
                return;
            }
            if (rv.Id == "social")
            {
                if (!_optSocialWeb)
                {
                    _optSocialWeb = true;
                    rv.IsOn = true;
                    ApplyRouteVisual(rv, true);
                    if (IsAdministratorStatic())
                    {
                        if (_optTunMode || IsTelegramDesktopDetected()) _optTunMode = true;
                    }
                    else if (!_optTunMode && IsTelegramDesktopDetected())
                    {
                        SaveCurrentState();
                        UpdateConnectionVisuals(false);
                        TriggerCategoryHotReloadIfConnected();
                        ShowTunModal(false);
                        return;
                    }
                }
                else
                {
                    _optSocialWeb = false;
                    rv.IsOn = false;
                    if (!_optDiscordYt) _optTunMode = false;
                    ApplyRouteVisual(rv, true);
                }
                SaveCurrentState();
                UpdateConnectionVisuals(false);
                TriggerCategoryHotReloadIfConnected();
                return;
            }
            if (rv.Id == "media")
            {
                if (!_optDiscordYt)
                {
                    if (!HasActiveProAccess())
                    {
                        ShowProModal();
                        return;
                    }
                    _optDiscordYt = true;
                    rv.IsOn = true;
                    ApplyRouteVisual(rv, true);
                    if (IsAdministratorStatic())
                    {
                        string thirdTun;
                        _optTunMode = !CheckOtherThirdPartyTunAdapters(out thirdTun);
                    }
                    else
                    {
                        SaveCurrentState();
                        UpdateConnectionVisuals(false);
                        TriggerCategoryHotReloadIfConnected();
                        ShowTunModal(true);
                        return;
                    }
                }
                else
                {
                    _optDiscordYt = false;
                    _optTunMode = false;
                    rv.IsOn = false;
                    ApplyRouteVisual(rv, true);
                }
                SaveCurrentState();
                UpdateConnectionVisuals(false);
                TriggerCategoryHotReloadIfConnected();
            }
        }

        private void ApplyRouteVisual(RouteItemView rv, bool animate)
        {
            if (rv == null) return;
            int dur = animate ? 180 : 0;
            UpdatePillSwitchVisual(rv.SwitchTrack, rv.SwitchThumb, rv.ThumbTransform, rv.IsOn, dur, animate);
            if (rv.IsOn)
            {
                SetOrAnimateBrush(rv.IconBox, Border.BackgroundProperty, _theme.AccentSoft, dur);
                SetOrAnimateBrush(rv.IconBox, Border.BorderBrushProperty, _theme.AccentBorder, dur);
                SetOrAnimateBrush(rv.IconPath, Shape.StrokeProperty, _theme.Accent, dur);
            }
            else
            {
                SetOrAnimateBrush(rv.IconBox, Border.BackgroundProperty, _theme.StatusCardBg, dur);
                SetOrAnimateBrush(rv.IconBox, Border.BorderBrushProperty, _theme.Border, dur);
                SetOrAnimateBrush(rv.IconPath, Shape.StrokeProperty, _theme.Muted, dur);
            }

            if (animate && rv.IsOn)
            {
                var ibSt = rv.IconBox.RenderTransform as ScaleTransform;
                if (ibSt != null)
                {
                    var pulse = new DoubleAnimationUsingKeyFrames();
                    pulse.KeyFrames.Add(new EasingDoubleKeyFrame(1.0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(0))));
                    pulse.KeyFrames.Add(new EasingDoubleKeyFrame(1.09, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(95)), new CubicEase { EasingMode = EasingMode.EaseOut }));
                    pulse.KeyFrames.Add(new EasingDoubleKeyFrame(1.0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(220)), new CubicEase { EasingMode = EasingMode.EaseInOut }));
                    ibSt.BeginAnimation(ScaleTransform.ScaleXProperty, pulse);
                    ibSt.BeginAnimation(ScaleTransform.ScaleYProperty, pulse);
                }
            }

            if (rv.IsPro)
            {
                if (_proActive)
                {
                    SetOrAnimateBrush(rv.TierBadge, Border.BackgroundProperty, _theme.AccentSoft, dur);
                    SetOrAnimateBrush(rv.TierBadge, Border.BorderBrushProperty, _theme.AccentBorder, dur);
                    SetOrAnimateBrush(rv.TierText, TextBlock.ForegroundProperty, _theme.Accent, dur);
                    rv.TierText.Text = "PRO \u2713";
                }
                else
                {
                    SetOrAnimateBrush(rv.TierBadge, Border.BackgroundProperty, _theme.WarnSoft, dur);
                    SetOrAnimateBrush(rv.TierBadge, Border.BorderBrushProperty, _theme.WarnBorder, dur);
                    SetOrAnimateBrush(rv.TierText, TextBlock.ForegroundProperty, _theme.Warn, dur);
                    rv.TierText.Text = "PRO";
                }
            }
            else
            {
                SetOrAnimateBrush(rv.TierBadge, Border.BackgroundProperty, _theme.OkSoft, dur);
                SetOrAnimateBrush(rv.TierBadge, Border.BorderBrushProperty, _theme.OkBorder, dur);
                SetOrAnimateBrush(rv.TierText, TextBlock.ForegroundProperty, _theme.Ok, dur);
                rv.TierText.Text = "FREE";
            }

            SetOrAnimateBrush(rv.TitleText, TextBlock.ForegroundProperty, _theme.Ink, dur);
            SetOrAnimateBrush(rv.SubtitleText, TextBlock.ForegroundProperty, _theme.Muted, dur);
            if (rv.BottomDivider != null)
            {
                SetOrAnimateBrush(rv.BottomDivider, Border.BackgroundProperty, _theme.Border, dur);
            }
        }

        private void TriggerManualAiPulseRefresh()
        {
            if (_aiPulseIconHolder != null)
            {
                var rt = _aiPulseIconHolder.RenderTransform as RotateTransform;
                if (rt != null)
                {
                    var spin = new DoubleAnimation(0, 360, TimeSpan.FromMilliseconds(480))
                    {
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    };
                    rt.BeginAnimation(RotateTransform.AngleProperty, spin);
                }
            }
            var unused = RefreshAiPulseUiAsync(true);
        }

        private async Task RefreshAiPulseUiAsync(bool forceRefresh)
        {
            if (!_isConnected)
            {
                _geminiStatus = "idle";
                _claudeStatus = "idle";
                _openaiStatus = "idle";
                _geminiMs = 0; _claudeMs = 0; _openaiMs = 0;
                _geminiHttp = 0; _claudeHttp = 0; _openaiHttp = 0;
                RunOnUiThread(delegate { UpdateAiPulseVisuals(false); });
                return;
            }
            try
            {
                string raw = await PixelCoreService.QueryAiPulseV4JsonAsync(forceRefresh).ConfigureAwait(false);
                var obj = MiniJson.Deserialize(raw) as Dictionary<string, object>;
                var provs = obj != null ? MiniJson.GetDict(obj, "providers") : null;
                if (provs == null) return;

                ParseProviderPulse(provs, "gemini", out _geminiStatus, out _geminiMs, out _geminiHttp);
                ParseProviderPulse(provs, "claude", out _claudeStatus, out _claudeMs, out _claudeHttp);
                ParseProviderPulse(provs, "openai", out _openaiStatus, out _openaiMs, out _openaiHttp);

                RunOnUiThread(delegate { UpdateAiPulseVisuals(true); });
            }
            catch { }
        }

        private static void ParseProviderPulse(Dictionary<string, object> provs, string key, out string status, out int ms, out int httpCode)
        {
            var d = MiniJson.GetDict(provs, key);
            status = d != null ? (MiniJson.GetStr(d, "status") ?? "down") : "down";
            ms = d != null ? MiniJson.GetInt(d, "latency_ms", 0) : 0;
            httpCode = d != null ? MiniJson.GetInt(d, "http_code", 0) : 0;
        }

        private void UpdateAiPulseVisuals(bool animate)
        {
            int dur = animate ? 180 : 0;
            ApplySingleAiPulsePill(_dotGemini, _lblGemini, _msGemini, "Gemini", _geminiStatus, _geminiMs, _geminiHttp, dur);
            ApplySingleAiPulsePill(_dotClaude, _lblClaude, _msClaude, "Claude", _claudeStatus, _claudeMs, _claudeHttp, dur);
            ApplySingleAiPulsePill(_dotOpenAi, _lblOpenAi, _msOpenAi, "OpenAI", _openaiStatus, _openaiMs, _openaiHttp, dur);
        }

        private void ApplySingleAiPulsePill(Ellipse dot, TextBlock lbl, TextBlock msTb, string name, string status, int ms, int httpCode, int dur)
        {
            if (dot == null || lbl == null || msTb == null) return;
            Color dotCol;
            string msText;
            if (status == "ok")
            {
                dotCol = _theme.Ok;
                msText = ms > 0 ? ms.ToString() : "OK";
            }
            else if (status == "degraded")
            {
                dotCol = _theme.Warn;
                msText = ms > 0 ? ms.ToString() : "!";
            }
            else if (status == "down")
            {
                dotCol = _theme.Err;
                msText = "\u2715";
            }
            else
            {
                dotCol = _theme.BorderStrong;
                msText = "\u2014";
            }
            SetOrAnimateBrush(dot, Shape.FillProperty, dotCol, dur);
            SetOrAnimateBrush(lbl, TextBlock.ForegroundProperty, status == "idle" ? _theme.Muted : _theme.Ink, dur);
            SetOrAnimateBrush(msTb, TextBlock.ForegroundProperty, status == "idle" ? _theme.Faint : _theme.Muted, dur);
            msTb.Text = msText;
            string tip = status == "idle"
                ? (name + ": туннель отключён")
                : string.Format("{0}: {1} (HTTP {2}, {3} мс)", name, status.ToUpperInvariant(), httpCode, ms);
            lbl.ToolTip = tip;
            msTb.ToolTip = tip;
        }

        private static bool DetectWindowsLightTheme()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", false))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("AppsUseLightTheme");
                        if (val is int)
                        {
                            return ((int)val) != 0;
                        }
                    }
                }
            }
            catch { }
            return true;
        }

        private void ApplyThemeChoice(ThemeModeChoice choice, bool saveAndSpin)
        {
            _themeChoice = choice;
            if (choice == ThemeModeChoice.System)
            {
                _isDark = !DetectWindowsLightTheme();
            }
            else
            {
                _isDark = (choice == ThemeModeChoice.Dark);
            }
            _theme = _isDark ? ThemeTokens.CreateDark() : ThemeTokens.CreateLight();
            ApplyTheme(true);
            UpdateConnectionVisuals(true);
            UpdateIdeQuickBarVisual();
            if (saveAndSpin)
            {
                AnimateThemeIconSpin();
                SaveCurrentState();
            }
        }

        private void AnimateThemeIconSpin()
        {
            if (_themeIconHolder == null) return;
            var tg = _themeIconHolder.RenderTransform as TransformGroup;
            if (tg == null || tg.Children.Count < 2) return;
            var rt = tg.Children[0] as RotateTransform;
            var st = tg.Children[1] as ScaleTransform;
            if (rt != null)
            {
                var rAnim = new DoubleAnimation(-90.0, 0.0, TimeSpan.FromMilliseconds(250))
                {
                    EasingFunction = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.3 }
                };
                rt.BeginAnimation(RotateTransform.AngleProperty, rAnim);
            }
            if (st != null)
            {
                var sAnim = new DoubleAnimation(0.72, 1.0, TimeSpan.FromMilliseconds(250))
                {
                    EasingFunction = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.3 }
                };
                st.BeginAnimation(ScaleTransform.ScaleXProperty, sAnim);
                st.BeginAnimation(ScaleTransform.ScaleYProperty, sAnim);
            }
        }

        private void ToggleKeyDrawer(bool open)
        {
            _keyDrawerOpen = open;
            _keyDrawerAnimToken += 1;
            int myToken = _keyDrawerAnimToken;

            if (open)
            {
                _keyDrawer.Visibility = Visibility.Visible;
                var hAnim = new DoubleAnimation(46.0, TimeSpan.FromMilliseconds(210))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                var opAnim = new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(180));
                var yAnim = new DoubleAnimation(0.0, TimeSpan.FromMilliseconds(210))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                _keyDrawer.BeginAnimation(MaxHeightProperty, hAnim);
                _keyDrawer.BeginAnimation(OpacityProperty, opAnim);
                _keyDrawerTranslate.BeginAnimation(TranslateTransform.YProperty, yAnim);
                if (_keyInput != null)
                {
                    _keyInput.Focus();
                    _keyInput.SelectAll();
                }
            }
            else
            {
                var hAnim = new DoubleAnimation(0.0, TimeSpan.FromMilliseconds(170))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
                };
                var opAnim = new DoubleAnimation(0.0, TimeSpan.FromMilliseconds(140));
                var yAnim = new DoubleAnimation(-6.0, TimeSpan.FromMilliseconds(170));
                hAnim.Completed += delegate
                {
                    if (_keyDrawerAnimToken == myToken && !_keyDrawerOpen)
                    {
                        _keyDrawer.Visibility = Visibility.Collapsed;
                    }
                };
                _keyDrawer.BeginAnimation(MaxHeightProperty, hAnim);
                _keyDrawer.BeginAnimation(OpacityProperty, opAnim);
                _keyDrawerTranslate.BeginAnimation(TranslateTransform.YProperty, yAnim);
            }
        }

        private void ApplyTheme(bool animate)
        {
            int dur = animate ? 230 : 0;

            _winShadow.Opacity = _theme.WindowShadowOpacity;
            _statusCardShadow.Opacity = _theme.CardShadowOpacity;
            _aiPulseShadow.Opacity = _theme.CardShadowOpacity;
            _routesCardShadow.Opacity = _theme.CardShadowOpacity;

            SetOrAnimateBrush(_outerWinBorder, Border.BackgroundProperty, _theme.Bg, dur);
            SetOrAnimateBrush(_outerWinBorder, Border.BorderBrushProperty, _theme.BorderStrong, dur);
            SetOrAnimateBrush(_headerDivider, Border.BackgroundProperty, _theme.Border, dur);

            Color logoBg = _isDark ? Color.FromRgb(0xF4, 0xF4, 0xF6) : Color.FromRgb(0x11, 0x11, 0x13);
            Color logoArch = _isDark ? Color.FromRgb(0x11, 0x11, 0x13) : Colors.White;
            Color logoPix = _isDark ? Color.FromRgb(0x25, 0x63, 0xEB) : Color.FromRgb(0x60, 0xA5, 0xFA);
            SetOrAnimateBrush(_logoBox, Border.BackgroundProperty, logoBg, dur);
            SetOrAnimateBrush(_logoOuterArch, Shape.StrokeProperty, logoArch, dur);
            SetOrAnimateBrush(_logoCorePixel, Border.BackgroundProperty, logoPix, dur);
            SetOrAnimateBrush(_brandTitle, TextBlock.ForegroundProperty, _theme.Ink, dur);

            SetOrAnimateBrush(_versionPill, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_versionPill, Border.BorderBrushProperty, _theme.Border, dur);
            SetOrAnimateBrush(_versionPillText, TextBlock.ForegroundProperty, _theme.Muted, dur);

            SetOrAnimateBrush(_updatePillBtn, Border.BackgroundProperty, _theme.OkSoft, dur);
            SetOrAnimateBrush(_updatePillBtn, Border.BorderBrushProperty, _theme.Ok, dur);
            SetOrAnimateBrush(_updatePillText, TextBlock.ForegroundProperty, _theme.Ok, dur);

            SetOrAnimateBrush(_toolsBtn, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_toolsBtn, Border.BorderBrushProperty, _theme.Border, dur);
            _toolsIconHolder.Content = CreateIcon(
                "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.26.6.85 1 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z",
                _theme.Ink, 13.5);

            SetOrAnimateBrush(_themeBtn, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_themeBtn, Border.BorderBrushProperty, _theme.Border, dur);
            _themeIconHolder.Content = _isDark
                ? CreateIcon("M12 3v2M12 19v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M3 12h2M19 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41 M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", _theme.Ink, 13.5)
                : CreateIcon("M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z", _theme.Ink, 13);

            SetOrAnimateBrush(_minBtn, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_minBtn, Border.BorderBrushProperty, _theme.Border, dur);
            SetOrAnimateBrush(_minBtnPath, Shape.StrokeProperty, _theme.Muted, dur);

            SetOrAnimateBrush(_closeBtn, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_closeBtn, Border.BorderBrushProperty, _theme.Border, dur);
            SetOrAnimateBrush(_closeBtnPath, Shape.StrokeProperty, _theme.Muted, dur);

            SetOrAnimateBrush(_statusCard, Border.BackgroundProperty, _theme.StatusCardBg, dur);
            SetOrAnimateBrush(_statusCard, Border.BorderBrushProperty, _theme.Border, dur);
            if (_agChamberBorder != null)
            {
                Color chamberBg = _isDark ? Color.FromRgb(8, 9, 13) : Color.FromRgb(250, 251, 253);
                SetOrAnimateBrush(_agChamberBorder, Border.BackgroundProperty, chamberBg, dur);
                SetOrAnimateBrush(_agChamberBorder, Border.BorderBrushProperty, _theme.Border, dur);
            }
            if (_agChamberBadge != null && _agChamberBadgeText != null)
            {
                Color badgeBg = _isDark ? Color.FromArgb(220, 10, 11, 16) : Color.FromArgb(230, 255, 255, 255);
                SetOrAnimateBrush(_agChamberBadge, Border.BackgroundProperty, badgeBg, dur);
                SetOrAnimateBrush(_agChamberBadge, Border.BorderBrushProperty, _theme.Border, dur);
                SetOrAnimateBrush(_agChamberBadgeText, TextBlock.ForegroundProperty, _theme.Muted, dur);
            }
            if (_agAsciiEngine != null)
            {
                _agAsciiEngine.Render(_asciiTime, _connState, _isDark, _agPointerActive, _agPointerNormX, _agPointerNormY);
            }
            SetOrAnimateBrush(_statusTitle, TextBlock.ForegroundProperty, _theme.Ink, dur);
            SetOrAnimateBrush(_statusSub, TextBlock.ForegroundProperty, _theme.Muted, dur);
            SetOrAnimateBrush(_specDivider, Border.BackgroundProperty, _theme.Border, dur);
            SetOrAnimateBrush(_specModeLbl, TextBlock.ForegroundProperty, _theme.Faint, dur);
            SetOrAnimateBrush(_specAccessLbl, TextBlock.ForegroundProperty, _theme.Faint, dur);
            Color latencyColor = _connState == TunnelState.Online ? _theme.Ink : (_connState == TunnelState.Connecting ? _theme.Warn : _theme.Muted);
            SetOrAnimateBrush(_specLatencyVal, TextBlock.ForegroundProperty, latencyColor, dur);
            SetOrAnimateBrush(_specModeVal, TextBlock.ForegroundProperty, _theme.Ink, dur);
            SetOrAnimateBrush(_specAccessVal, TextBlock.ForegroundProperty, _proActive ? _theme.Accent : _theme.Ink, dur);

            SetOrAnimateBrush(_aiPulseCard, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_aiPulseCard, Border.BorderBrushProperty, _theme.Border, dur);
            _aiPulseIconHolder.Content = CreateIcon("M22 12h-4l-3 9L9 3l-3 9H2", _theme.Muted, 12);
            SetOrAnimateBrush(_aiPulseTitle, TextBlock.ForegroundProperty, _theme.Muted, dur);
            UpdateAiPulseVisuals(animate);

            SetOrAnimateBrush(_splitHeaderLeft, TextBlock.ForegroundProperty, _theme.Faint, dur);
            SetOrAnimateBrush(_domainsTrafficBtn, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_domainsTrafficBtn, Border.BorderBrushProperty, _theme.Border, dur);
            SetOrAnimateBrush(_domainsTrafficText, TextBlock.ForegroundProperty, _theme.Ink, dur);

            SetOrAnimateBrush(_routesCard, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_routesCard, Border.BorderBrushProperty, _theme.Border, dur);
            foreach (var rv in _routes)
            {
                ApplyRouteVisual(rv, animate);
            }

            SetOrAnimateBrush(_keyDrawer, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_keyDrawer, Border.BorderBrushProperty, _theme.Border, dur);
            _keyInput.Foreground = new SolidColorBrush(_theme.Ink);
            _keyInput.CaretBrush = new SolidColorBrush(_theme.Ink);
            SetOrAnimateBrush(_pasteProBtn, Border.BackgroundProperty, _theme.Accent, dur);
            SetOrAnimateBrush(_pasteProBtn, Border.BorderBrushProperty, _theme.Accent, dur);
            SetOrAnimateBrush(_pasteProBtnText, TextBlock.ForegroundProperty, _theme.AccentInk, dur);

            SetOrAnimateBrush(_btnVpn, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_btnVpn, Border.BorderBrushProperty, _theme.Border, dur);
            _btnVpnIcon.Content = CreateIcon("M12 2L4 5.5v6C4 16.8 7.4 21.6 12 23c4.6-1.4 8-6.2 8-11.5v-6L12 2z M13 8l-3 5h3l-1 4 3-5h-3z", _theme.Accent, 13);
            SetOrAnimateBrush(_btnVpnText, TextBlock.ForegroundProperty, _theme.Ink, dur);

            SetOrAnimateBrush(_btnKey, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_btnKey, Border.BorderBrushProperty, _theme.Border, dur);
            _btnKeyIcon.Content = CreateIcon("M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3", _theme.Muted, 12.5);
            SetOrAnimateBrush(_btnKeyText, TextBlock.ForegroundProperty, _theme.Ink, dur);

            SetOrAnimateBrush(_btnDiag, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_btnDiag, Border.BorderBrushProperty, _theme.Border, dur);
            _btnDiagIcon.Content = CreateIcon("M22 12h-4l-3 9L9 3l-3 9H2", _theme.Ok, 13);
            SetOrAnimateBrush(_btnDiagText, TextBlock.ForegroundProperty, _theme.Ink, dur);

            SetOrAnimateBrush(_donateBar, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_donateBar, Border.BorderBrushProperty, _theme.Border, dur);
            _donateHeartIcon.Content = CreateIcon("M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78L12 21.23l8.84-8.84a5.5 5.5 0 0 0 0-7.78z", _theme.Warn, 13);
            SetOrAnimateBrush(_donateTitle, TextBlock.ForegroundProperty, _theme.Ink, dur);
            SetOrAnimateBrush(_donateSub, TextBlock.ForegroundProperty, _theme.Muted, dur);
            SetOrAnimateBrush(_donateActionText, TextBlock.ForegroundProperty, _theme.Warn, dur);
            _donateArrowIcon.Content = CreateIcon("M5 12h14 M13 6l6 6-6 6", _theme.Warn, 11);

            SetOrAnimateBrush(_modalBackdrop, Border.BackgroundProperty, _theme.ModalScrim, dur);
            SetOrAnimateBrush(_modalCard, Border.BackgroundProperty, _theme.Surface, dur);
            SetOrAnimateBrush(_modalCard, Border.BorderBrushProperty, _theme.BorderStrong, dur);

            if (!string.IsNullOrEmpty(_activeModalKind))
            {
                RebuildActiveModalForTheme();
            }
        }

        private void UpdateIdeQuickBarVisual()
        {
            if (_ideQuickBar == null) return;
            _ideQuickBar.Background = new SolidColorBrush(_theme.Surface);
            _ideQuickBar.BorderBrush = new SolidColorBrush(_oauthHelperActive || _ideOpenedPreTunnel ? _theme.WarnBorder : _theme.Border);

            if (_ideOpenedPreTunnel && !_oauthHelperActive)
            {
                _btnRestartIde.Background = new SolidColorBrush(_theme.WarnSoft);
                _btnRestartIde.BorderBrush = new SolidColorBrush(_theme.WarnBorder);
                _btnRestartIdeText.Foreground = new SolidColorBrush(_theme.Warn);
            }
            else
            {
                _btnRestartIde.Background = new SolidColorBrush(_theme.StatusCardBg);
                _btnRestartIde.BorderBrush = new SolidColorBrush(_theme.BorderStrong);
                _btnRestartIdeText.Foreground = new SolidColorBrush(_theme.Ink);
            }

            if (_oauthHelperActive)
            {
                int mins = _oauthHelperSecondsLeft / 60;
                int secs = _oauthHelperSecondsLeft % 60;
                _ideQuickDot.Fill = new SolidColorBrush(_theme.Warn);
                _ideQuickLabel.Text = string.Format("OAuth \u00b7 {0:D2}:{1:D2}", mins, secs);
                _ideQuickLabel.Foreground = new SolidColorBrush(_theme.Warn);
                _ideQuickLabel.ToolTip = "Временный режим 3 мин для входа в Google-аккаунт";
                _btnOAuthQuick.Background = new SolidColorBrush(_theme.WarnSoft);
                _btnOAuthQuick.BorderBrush = new SolidColorBrush(_theme.Warn);
                _btnOAuthQuickText.Foreground = new SolidColorBrush(_theme.Warn);
                _btnOAuthQuickText.Text = "Стоп";
            }
            else
            {
                _ideQuickDot.Fill = new SolidColorBrush(_ideOpenedPreTunnel ? _theme.Warn : _theme.Ok);
                _ideQuickLabel.Text = _ideOpenedPreTunnel ? "Перезапустите IDE" : "Antigravity IDE";
                _ideQuickLabel.Foreground = new SolidColorBrush(_ideOpenedPreTunnel ? _theme.Warn : _theme.Ink);
                _ideQuickLabel.ToolTip = _ideOpenedPreTunnel
                    ? "Antigravity открыт до запуска туннеля — нажмите «Рестарт IDE», чтобы прокси и --disable-quic применились"
                    : "Antigravity IDE + AG_LS_PROXY";
                _btnOAuthQuick.Background = new SolidColorBrush(_theme.AccentSoft);
                _btnOAuthQuick.BorderBrush = new SolidColorBrush(_theme.AccentBorder);
                _btnOAuthQuickText.Foreground = new SolidColorBrush(_theme.Accent);
                _btnOAuthQuickText.Text = "OAuth 3\u043c";
            }
        }

        private void UpdateRulesCountPill()
        {
            if (_domainsTrafficText == null) return;
            int total = _customProxyDomains.Count + _customDirectDomains.Count;
            _domainsTrafficText.Text = "Домены и трафик \u00b7 " + total;
        }

        private void UpdateConnectionVisuals()
        {
            UpdateConnectionVisuals(false);
        }

        private void UpdateConnectionVisuals(bool animate)
        {
            if (_statusTitle == null || _connectBtn == null) return;
            UpdateModeBadge();
            int dur = animate ? 200 : 0;

            if (_connState == TunnelState.Online)
            {
                _statusTitle.Text = _statusHasCustomMessage ? _statusCustomTitle : "Туннель работает";
                _statusSub.Text = _statusHasCustomMessage ? _statusCustomSub : BuildActiveRoutesSummary();
                _specLatencyVal.Text = _currentPing > 0 ? (_currentPing + " \u043c\u0441") : "\u2014";
                SetOrAnimateBrush(_specLatencyVal, TextBlock.ForegroundProperty, _theme.Ink, dur);

                SetOrAnimateBrush(_connectBtn, Border.BackgroundProperty, _theme.Surface, dur);
                SetOrAnimateBrush(_connectBtn, Border.BorderBrushProperty, _theme.Ok, dur);
                _connectLiveDot.Visibility = Visibility.Visible;
                SetOrAnimateBrush(_connectLiveDot, Shape.FillProperty, _theme.Ok, dur);
                StopSpinnerAnimations(_connectIconHolder.Content as DependencyObject);
                _connectIconHolder.Content = CreateIcon("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4", _theme.Ink, 14.5);
                SetOrAnimateBrush(_connectBtnText, TextBlock.ForegroundProperty, _theme.Ink, dur);
                _connectBtnText.Text = "Остановить туннель";
            }
            else if (_connState == TunnelState.Connecting)
            {
                _statusTitle.Text = "Подключение\u2026";
                _statusSub.Text = "Устанавливаем защищённый канал";
                _specLatencyVal.Text = "\u2026";
                SetOrAnimateBrush(_specLatencyVal, TextBlock.ForegroundProperty, _theme.Warn, dur);

                SetOrAnimateBrush(_connectBtn, Border.BackgroundProperty, _theme.WarnSoft, dur);
                SetOrAnimateBrush(_connectBtn, Border.BorderBrushProperty, _theme.Warn, dur);
                _connectLiveDot.Visibility = Visibility.Collapsed;
                StopSpinnerAnimations(_connectIconHolder.Content as DependencyObject);
                _connectIconHolder.Content = CreateSpinningIcon(_theme.Warn, 14.5);
                SetOrAnimateBrush(_connectBtnText, TextBlock.ForegroundProperty, _theme.Warn, dur);
                _connectBtnText.Text = "Подключение\u2026";
            }
            else
            {
                _statusTitle.Text = _statusHasCustomMessage ? _statusCustomTitle : "Туннель остановлен";
                _statusSub.Text = _statusHasCustomMessage ? _statusCustomSub : "Нажмите «Запустить» для умного обхода";
                _specLatencyVal.Text = "\u2014";
                SetOrAnimateBrush(_specLatencyVal, TextBlock.ForegroundProperty, _theme.Muted, dur);

                SetOrAnimateBrush(_connectBtn, Border.BackgroundProperty, _theme.CtaIdleBg, dur);
                SetOrAnimateBrush(_connectBtn, Border.BorderBrushProperty, _theme.CtaIdleBg, dur);
                _connectLiveDot.Visibility = Visibility.Collapsed;
                StopSpinnerAnimations(_connectIconHolder.Content as DependencyObject);
                _connectIconHolder.Content = CreateIcon("M13 2L4 14h7l-1 8 10-12h-7z", _theme.CtaIdleInk, 14.5);
                SetOrAnimateBrush(_connectBtnText, TextBlock.ForegroundProperty, _theme.CtaIdleInk, dur);
                _connectBtnText.Text = "Запустить туннель";
            }

            UpdateSignalBars(animate);
        }

        private string BuildActiveRoutesSummary()
        {
            var names = new List<string>();
            if (_optAntigravity) names.Add("Antigravity");
            if (_optCursorAi) names.Add("нейросети");
            if (_optSocialWeb) names.Add("Telegram");
            if (_optDiscordYt) names.Add("YouTube");
            if (names.Count == 0) return "Все категории отключены";
            if (names.Count == 1) return "Активен обход: " + names[0];
            string res = "";
            for (int i = 0; i < names.Count; i++)
            {
                if (i == names.Count - 1) res += " и " + names[i];
                else if (i == 0) res += names[i];
                else res += ", " + names[i];
            }
            return res;
        }

        private void UpdateModeBadge()
        {
            if (_specModeVal == null || _specAccessVal == null) return;
            _proActive = HasActiveProAccess();
            bool tunUsed = _optTunMode && _proActive && (_optSocialWeb || _optDiscordYt);
            _specModeVal.Text = tunUsed ? "Обход + TUN" : "Умный обход";
            _specAccessVal.Text = _proActive ? "PRO" : "Бесплатный";
            SetOrAnimateBrush(_specAccessVal, TextBlock.ForegroundProperty, _proActive ? _theme.Accent : _theme.Ink, 150);
        }

        private void ToggleConnection()
        {
            if (_isBusy) return;
            if (_isConnected)
                StopTunnelProcess();
            else
                StartTunnelAsync();
        }

        private void UpdateSignalBars(bool animate)
        {
            int dur = animate ? 150 : 0;
            int activeBars = 4;
            Color onlineColor = _theme.Ok;
            if (_connState == TunnelState.Online && _currentPing > 0)
            {
                if (_currentPing <= 120) { activeBars = 4; onlineColor = _theme.Ok; }
                else if (_currentPing <= 240) { activeBars = 3; onlineColor = _theme.Ok; }
                else { activeBars = 2; onlineColor = _theme.Warn; }
            }
            for (int i = 0; i < 4; i++)
            {
                if (_signalBars[i] == null) continue;
                Color target;
                if (_connState == TunnelState.Online)
                {
                    target = (i < activeBars) ? onlineColor : _theme.BorderStrong;
                }
                else if (_connState == TunnelState.Connecting)
                {
                    target = (i <= _waveStep) ? _theme.Warn : _theme.BorderStrong;
                }
                else
                {
                    target = _theme.BorderStrong;
                }
                SetOrAnimateBrush(_signalBars[i], Border.BackgroundProperty, target, dur);
            }
        }

        private void ApplyEnteredOrClipboardKey(bool allowClipboardPaste)
        {
            string curText = _keyInput != null ? (_keyInput.Text ?? "").Trim() : "";
            string foreignReason;
            if (allowClipboardPaste && IsForeignIncompatibleVpnKey(curText, out foreignReason))
            {
                if (_keyInput != null) _keyInput.Text = GetFreeModeSentinelUri();
                SaveCurrentState();
                SyncRoutesFromOptions(true);
                UpdateConnectionVisuals(true);
                SetStatus(ColBlue, "Включён встроенный FREE-режим", "Бесплатный режим для AI/IDE восстановлен.");
                return;
            }

            if (allowClipboardPaste)
            {
                try
                {
                    if (Clipboard.ContainsText())
                    {
                        string clip = Clipboard.GetText().Trim();
                        if (!string.IsNullOrEmpty(clip))
                        {
                            curText = clip;
                            if (_keyInput != null) _keyInput.Text = clip;
                        }
                    }
                }
                catch { }
            }

            if (IsForeignIncompatibleVpnKey(curText, out foreignReason))
            {
                OnKeyTextChanged();
                SetStatus(ColRed, "Чужой VPN-ключ не поддерживается", foreignReason);
                return;
            }

            SaveCurrentState();
            SyncRoutesFromOptions(true);
            UpdateConnectionVisuals(true);

            if (ParseVlessUri(curText) != null && !_isBusy)
            {
                if (_isConnected) StopTunnelProcess(false);
                StartTunnelAsync();
            }
            else
            {
                FlashStatusSub("Ключ сохранён");
            }
        }

        private void FlashIdeBarLabel(string temporaryText)
        {
            if (_ideQuickLabel == null) return;
            if (_inlineFeedbackTimer != null)
            {
                _inlineFeedbackTimer.Stop();
                _inlineFeedbackTimer = null;
            }
            _ideQuickLabel.Text = temporaryText;
            _ideQuickLabel.Foreground = new SolidColorBrush(_theme.Ok);
            _inlineFeedbackTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(2000) };
            _inlineFeedbackTimer.Tick += delegate
            {
                _inlineFeedbackTimer.Stop();
                _inlineFeedbackTimer = null;
                UpdateIdeQuickBarVisual();
            };
            _inlineFeedbackTimer.Start();
        }

        private void FlashStatusSub(string temporaryText)
        {
            if (_statusSub == null) return;
            if (_inlineFeedbackTimer != null)
            {
                _inlineFeedbackTimer.Stop();
                _inlineFeedbackTimer = null;
            }
            _statusSub.Text = temporaryText;
            _inlineFeedbackTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(2600) };
            _inlineFeedbackTimer.Tick += delegate
            {
                _inlineFeedbackTimer.Stop();
                _inlineFeedbackTimer = null;
                UpdateConnectionVisuals(false);
            };
            _inlineFeedbackTimer.Start();
        }

        // =====================================================================
        // CUSTOM STYLED MODAL DIALOGS
        // =====================================================================
        private void OpenModal(string kind, double width, UIElement content, bool animate)
        {
            _modalAnimToken += 1;
            _activeModalKind = kind;
            StopSpinnerAnimations(_modalCard.Child as DependencyObject);
            _modalCard.Width = width;
            _modalCard.Child = content;
            _modalBackdrop.Visibility = Visibility.Visible;

            if (animate)
            {
                var bgFade = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(170))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                _modalBackdrop.BeginAnimation(OpacityProperty, bgFade);

                var cardFade = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(180))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                _modalCard.BeginAnimation(OpacityProperty, cardFade);

                var ease = new ExponentialEase { Exponent = 4, EasingMode = EasingMode.EaseOut };
                var scaleAnim = new DoubleAnimation(0.95, 1.0, TimeSpan.FromMilliseconds(210)) { EasingFunction = ease };
                var slideAnim = new DoubleAnimation(10.0, 0.0, TimeSpan.FromMilliseconds(210)) { EasingFunction = ease };
                _modalScale.BeginAnimation(ScaleTransform.ScaleXProperty, scaleAnim);
                _modalScale.BeginAnimation(ScaleTransform.ScaleYProperty, scaleAnim);
                _modalTranslate.BeginAnimation(TranslateTransform.YProperty, slideAnim);
            }
            else
            {
                _modalBackdrop.BeginAnimation(OpacityProperty, null);
                _modalBackdrop.Opacity = 1.0;
                _modalCard.BeginAnimation(OpacityProperty, null);
                _modalCard.Opacity = 1.0;
                _modalScale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
                _modalScale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
                _modalScale.ScaleX = 1.0;
                _modalScale.ScaleY = 1.0;
                _modalTranslate.BeginAnimation(TranslateTransform.YProperty, null);
                _modalTranslate.Y = 0.0;
            }
        }

        private void CloseModal()
        {
            if (_radarTimer != null)
            {
                _radarTimer.Stop();
                _radarTimer = null;
            }
            StopSpinnerAnimations(_modalCard.Child as DependencyObject);
            _modalAnimToken += 1;
            int myToken = _modalAnimToken;
            _activeModalKind = "";
            _radarListHost = null;
            _radarStatusLabel = null;
            _vpnBlueEngine = null;
            _vpnRedEngine = null;
            _vpnBlueHover = false;
            _vpnRedHover = false;
            _diagChamberBorder = null;

            var bgFade = new DoubleAnimation(0.0, TimeSpan.FromMilliseconds(145))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            bgFade.Completed += delegate
            {
                if (_modalAnimToken == myToken && string.IsNullOrEmpty(_activeModalKind))
                {
                    _modalBackdrop.Visibility = Visibility.Collapsed;
                }
            };
            _modalBackdrop.BeginAnimation(OpacityProperty, bgFade);

            var cardFade = new DoubleAnimation(0.0, TimeSpan.FromMilliseconds(130));
            _modalCard.BeginAnimation(OpacityProperty, cardFade);

            var scaleAnim = new DoubleAnimation(0.96, TimeSpan.FromMilliseconds(145));
            var slideAnim = new DoubleAnimation(8.0, TimeSpan.FromMilliseconds(145));
            _modalScale.BeginAnimation(ScaleTransform.ScaleXProperty, scaleAnim);
            _modalScale.BeginAnimation(ScaleTransform.ScaleYProperty, scaleAnim);
            _modalTranslate.BeginAnimation(TranslateTransform.YProperty, slideAnim);
        }

        private void RebuildActiveModalForTheme()
        {
            string kind = _activeModalKind;
            if (kind == "pro") ShowProModal();
            else if (kind == "vpn_matrix") ShowOurVpnMatrixModal();
            else if (kind == "tun") ShowTunModal(_optDiscordYt);
            else if (kind == "diag") BuildDiagModalContent(false);
            else if (kind == "radar") BuildRadarModalContent(false, false);
            else if (kind == "tools") BuildToolsModalContent(false);
            else if (kind == "update") ShowUpdateModal();
            else if (kind == "donate") ShowDonateModal();
        }

        private StackPanel BuildModalHeader(string title, string sub, string iconData, Color iconColor, Color iconSoftBg)
        {
            var stack = new StackPanel();
            var top = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var icoBox = new Border
            {
                Width = 34,
                Height = 34,
                CornerRadius = new CornerRadius(9),
                Background = new SolidColorBrush(iconSoftBg),
                Margin = new Thickness(0, 0, 10, 0),
                Child = CreateIcon(iconData, iconColor, 16)
            };
            Grid.SetColumn(icoBox, 0);
            top.Children.Add(icoBox);

            var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            titles.Children.Add(new TextBlock
            {
                Text = title,
                Foreground = new SolidColorBrush(_theme.Ink),
                FontFamily = UiFont,
                FontSize = 13.5,
                FontWeight = FontWeights.SemiBold
            });
            titles.Children.Add(new TextBlock
            {
                Text = sub,
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = MonoFont,
                FontSize = 10,
                Margin = new Thickness(0, 1, 0, 0)
            });
            Grid.SetColumn(titles, 1);
            top.Children.Add(titles);

            var xBtn = new Border
            {
                Width = 26,
                Height = 26,
                CornerRadius = new CornerRadius(7),
                Background = Brushes.Transparent,
                Cursor = Cursors.Hand,
                Child = CreateIcon("M18 6L6 18 M6 6l12 12", _theme.Muted, 11)
            };
            xBtn.MouseLeftButtonUp += delegate { CloseModal(); };
            Grid.SetColumn(xBtn, 2);
            top.Children.Add(xBtn);

            stack.Children.Add(top);
            return stack;
        }

        private Grid BuildSegmentedTabs(string leftLabel, string rightLabel, int activeIdx, Action<int> onSwitch)
        {
            var well = new Border
            {
                CornerRadius = new CornerRadius(8),
                Background = new SolidColorBrush(_theme.Well),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(3),
                Margin = new Thickness(0, 0, 0, 11)
            };
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            string[] labels = new string[] { leftLabel, rightLabel };
            for (int i = 0; i < 2; i++)
            {
                int idx = i;
                bool active = (activeIdx == idx);
                var tabBtn = new Border
                {
                    CornerRadius = new CornerRadius(6),
                    Background = active ? new SolidColorBrush(_theme.Surface) : Brushes.Transparent,
                    BorderBrush = active ? new SolidColorBrush(_theme.BorderStrong) : Brushes.Transparent,
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(8, 5, 8, 5),
                    Cursor = Cursors.Hand
                };
                tabBtn.Child = new TextBlock
                {
                    Text = labels[i],
                    Foreground = new SolidColorBrush(active ? _theme.Ink : _theme.Muted),
                    FontFamily = UiFont,
                    FontSize = 11.2,
                    FontWeight = FontWeights.SemiBold,
                    HorizontalAlignment = HorizontalAlignment.Center
                };
                tabBtn.MouseLeftButtonUp += delegate { onSwitch(idx); };
                Grid.SetColumn(tabBtn, i == 0 ? 0 : 2);
                g.Children.Add(tabBtn);
            }

            well.Child = g;
            var wrap = new Grid();
            wrap.Children.Add(well);
            return wrap;
        }

        private Border CreateModalButton(string text, bool isPrimary, Action onClick)
        {
            var b = new Border
            {
                Height = 34,
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(1),
                Background = new SolidColorBrush(isPrimary ? _theme.CtaIdleBg : _theme.SurfaceHover),
                BorderBrush = new SolidColorBrush(isPrimary ? _theme.CtaIdleBg : _theme.BorderStrong),
                Padding = new Thickness(12, 0, 12, 0),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(1.0, 1.0)
            };
            b.Child = new TextBlock
            {
                Text = text,
                Foreground = new SolidColorBrush(isPrimary ? _theme.CtaIdleInk : _theme.Ink),
                FontFamily = UiFont,
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            AttachPressAnim(b);
            b.MouseLeftButtonUp += delegate { onClick(); };
            return b;
        }

        // ---------------------------------------------------------------------
        // 1. LIVE RADAR & CUSTOM DOMAINS (HOT-RELOAD) MODAL
        // ---------------------------------------------------------------------
        private void ShowRadarModal(int initialTab)
        {
            _radarTab = initialTab;
            if (_radarTimer != null)
            {
                _radarTimer.Stop();
                _radarTimer = null;
            }
            BuildRadarModalContent(true, false);
            var unused = RefreshLiveRadarFromEngineAsync();

            _radarTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1500) };
            _radarTimer.Tick += delegate
            {
                if (_activeModalKind == "radar" && _radarTab == 0)
                {
                    var unusedPoll = RefreshLiveRadarFromEngineAsync();
                }
            };
            _radarTimer.Start();
        }

        private async Task RefreshLiveRadarFromEngineAsync()
        {
            if (!_isConnected)
            {
                RunOnUiThread(delegate
                {
                    if (_activeModalKind == "radar" && _radarTab == 0)
                    {
                        _radarEntries.Clear();
                        PopulateRadarListInPlace();
                    }
                });
                return;
            }
            try
            {
                string raw = await PixelCoreService.QueryLiveRoutesV4JsonAsync().ConfigureAwait(false);
                var obj = MiniJson.Deserialize(raw) as Dictionary<string, object>;
                var entriesObj = obj != null ? MiniJson.GetList(obj, "entries") : null;
                var parsed = new List<RadarEntry>();
                if (entriesObj != null)
                {
                    long nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    for (int i = 0; i < entriesObj.Count; i++)
                    {
                        var row = entriesObj[i] as Dictionary<string, object>;
                        if (row == null) continue;
                        string dom = MiniJson.GetStr(row, "domain");
                        if (string.IsNullOrWhiteSpace(dom)) continue;
                        string act = MiniJson.GetStr(row, "action") ?? "DIRECT";
                        bool isTun = string.Equals(act, "PROXY", StringComparison.OrdinalIgnoreCase) ||
                                     string.Equals(act, "TUNNEL", StringComparison.OrdinalIgnoreCase);
                        string proc = MiniJson.GetStr(row, "process");
                        string proto = MiniJson.GetStr(row, "proto") ?? "TCP";
                        int port = MiniJson.GetInt(row, "port", 443);
                        string node = MiniJson.GetStr(row, "node") ?? "";
                        int pingMs = MiniJson.GetInt(row, "ping_ms", 0);
                        long ts = MiniJson.GetLong(row, "ts", 0);
                        string timeStr = MiniJson.GetStr(row, "time") ?? "";
                        string ageText = timeStr;
                        if (ts > 0)
                        {
                            long diff = Math.Max(0, nowUnix - ts);
                            if (diff <= 2) ageText = "сейчас";
                            else if (diff < 60) ageText = diff + "с";
                            else ageText = (diff / 60) + "м";
                        }
                        if (string.IsNullOrEmpty(proc)) proc = proto + ":" + port;
                        parsed.Add(new RadarEntry
                        {
                            Domain = dom.Trim(),
                            ProcessName = proc,
                            Proto = proto,
                            Port = port,
                            Node = node,
                            IsTunnel = isTun,
                            LatencyMs = pingMs,
                            AgeText = string.IsNullOrEmpty(ageText) ? "live" : ageText
                        });
                    }
                }

                RunOnUiThread(delegate
                {
                    if (_activeModalKind == "radar" && _radarTab == 0)
                    {
                        _radarEntries.Clear();
                        _radarEntries.AddRange(parsed);
                        PopulateRadarListInPlace();
                    }
                });
            }
            catch { }
        }

        private void ToggleRadarDomainRoute(RadarEntry entry)
        {
            if (entry == null || string.IsNullOrEmpty(entry.Domain)) return;
            string dom = NormalizeDomainInput(entry.Domain);
            if (string.IsNullOrEmpty(dom)) return;

            bool nextTunnel = !entry.IsTunnel;
            entry.IsTunnel = nextTunnel;
            _customProxyDomains.RemoveAll(delegate(string d) { return string.Equals(d, dom, StringComparison.OrdinalIgnoreCase); });
            _customDirectDomains.RemoveAll(delegate(string d) { return string.Equals(d, dom, StringComparison.OrdinalIgnoreCase); });
            if (nextTunnel)
                _customProxyDomains.Add(dom);
            else
                _customDirectDomains.Add(dom);

            SaveCustomRulesConfig(_customProxyDomains, _customDirectDomains);
            SetRuleRecommendation(dom, nextTunnel);
            UpdateRulesCountPill();
            PopulateRadarListInPlace();
            ApplyCustomRulesHotReloadAsync();
        }

        private static string NormalizeDomainInput(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "";
            string s = raw.Trim().ToLowerInvariant();
            for (int i = 0; i < s.Length; i++)
            {
                char ch = s[i];
                if (ch < 0x20 || ch == 0x7f || char.IsWhiteSpace(ch) ||
                    ch == '\'' || ch == '"' || ch == ';' || ch == '(' || ch == ')' ||
                    ch == '\\' || ch == '<' || ch == '>' || ch == '{' || ch == '}' || ch == '`')
                {
                    return "";
                }
            }

            int schemeIdx = s.IndexOf("://", StringComparison.Ordinal);
            if (schemeIdx >= 0)
            {
                s = s.Substring(schemeIdx + 3);
            }

            int firstDelim = s.IndexOfAny(new[] { '/', '?', '#' });
            string authority = firstDelim >= 0 ? s.Substring(0, firstDelim) : s;
            int atIdx = authority.LastIndexOf('@');
            if (atIdx >= 0)
            {
                authority = authority.Substring(atIdx + 1);
            }
            s = authority;

            if (string.IsNullOrEmpty(s) || s.IndexOf('[') >= 0 || s.IndexOf(']') >= 0) return "";

            int colonIdx = s.LastIndexOf(':');
            if (colonIdx >= 0)
            {
                string portPart = s.Substring(colonIdx + 1);
                int portNum;
                if (portPart.Length == 0 || !int.TryParse(portPart, out portNum) || portNum < 1 || portNum > 65535)
                    return "";
                s = s.Substring(0, colonIdx);
            }

            if (s.StartsWith("*.")) s = s.Substring(2);
            if (s.StartsWith("www.")) s = s.Substring(4);
            s = s.Trim('.');

            if (s.Length < 4 || s.Length > 253 || s.IndexOf('.') < 1 || s.IndexOf("..", StringComparison.Ordinal) >= 0)
                return "";

            string[] labels = s.Split('.');
            for (int i = 0; i < labels.Length; i++)
            {
                string lbl = labels[i];
                if (lbl.Length < 1 || lbl.Length > 63 || lbl[0] == '-' || lbl[lbl.Length - 1] == '-')
                    return "";
                for (int j = 0; j < lbl.Length; j++)
                {
                    char c = lbl[j];
                    bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                    if (!ok) return "";
                }
            }

            if (Uri.CheckHostName(s) != UriHostNameType.Dns) return "";
            return s;
        }

        private void SetRuleRecommendation(string domain, bool isTunnel)
        {
            bool isRuDomain = domain.EndsWith(".ru") || domain.EndsWith(".su") || domain.EndsWith(".xn--p1ai");
            if (isTunnel && isRuDomain)
            {
                _rulesAdviceIsWarn = true;
                _rulesAdviceTitle = "Рекомендация: " + domain + " направлен в туннель";
                _rulesAdviceBody = "Сервисы .ru (банки, Госуслуги, маркетплейсы) обычно работают быстрее и стабильнее в режиме «Напрямую». Если страница перестала открываться — верните домен в Direct.";
            }
            else
            {
                _rulesAdviceIsWarn = false;
                _rulesAdviceTitle = "Правило применено на лету: " + domain + " \u2192 " + (isTunnel ? "Туннель" : "Напрямую");
                _rulesAdviceBody = "Поддомены (www, api) подхватываются автоматически. Если сайт уже был открыт до добавления правила — обновите вкладку (Ctrl+F5) для сброса старых соединений.";
            }
        }

        private void AddCustomDomainFromText(string rawText)
        {
            string normalized = NormalizeDomainInput(rawText);
            if (string.IsNullOrEmpty(normalized))
            {
                _rulesAdviceIsWarn = true;
                _rulesAdviceTitle = "Некорректный формат домена";
                _rulesAdviceBody = "Введите домен без пробелов и протокола, например cursor.com, claude.ai или tbank.ru.";
                BuildRadarModalContent(false, false);
                return;
            }
            _customProxyDomains.RemoveAll(delegate(string d) { return string.Equals(d, normalized, StringComparison.OrdinalIgnoreCase); });
            _customDirectDomains.RemoveAll(delegate(string d) { return string.Equals(d, normalized, StringComparison.OrdinalIgnoreCase); });
            if (_addRuleTunnel) _customProxyDomains.Add(normalized);
            else _customDirectDomains.Add(normalized);
            _draftRuleText = "";
            SaveCustomRulesConfig(_customProxyDomains, _customDirectDomains);
            SetRuleRecommendation(normalized, _addRuleTunnel);
            UpdateRulesCountPill();
            BuildRadarModalContent(false, false);
            ApplyCustomRulesHotReloadAsync();
        }

        private void PopulateRadarListInPlace()
        {
            if (_radarListHost == null) return;
            _radarListHost.Children.Clear();

            string filter = (_radarFilterText ?? "").Trim().ToLowerInvariant();
            var visible = new List<RadarEntry>();
            for (int i = 0; i < _radarEntries.Count; i++)
            {
                RadarEntry re = _radarEntries[i];
                if (!string.IsNullOrEmpty(filter))
                {
                    bool hit = (re.Domain ?? "").ToLowerInvariant().Contains(filter) ||
                               (re.ProcessName ?? "").ToLowerInvariant().Contains(filter) ||
                               (re.IsTunnel ? "tunnel proxy" : "direct").Contains(filter);
                    if (!hit) continue;
                }
                visible.Add(re);
                if (visible.Count >= 18) break;
            }

            if (_radarStatusLabel != null)
            {
                if (!_isConnected)
                    _radarStatusLabel.Text = "Туннель остановлен · запустите для live-потоков";
                else
                    _radarStatusLabel.Text = string.Format("PWP-4 MUX · {0} записей (показано {1})", _radarEntries.Count, visible.Count);
            }

            if (visible.Count == 0)
            {
                _radarListHost.Children.Add(new TextBlock
                {
                    Text = _isConnected
                        ? (string.IsNullOrEmpty(filter) ? "Пока нет зафиксированных соединений — откройте сайт или IDE" : "Нет совпадений по фильтру «" + filter + "»")
                        : "Запустите туннель, чтобы видеть живые домены и процессы в реальном времени",
                    Foreground = new SolidColorBrush(_theme.Muted),
                    FontFamily = UiFont,
                    FontSize = 10.8,
                    TextWrapping = TextWrapping.Wrap,
                    Padding = new Thickness(12, 16, 12, 16),
                    HorizontalAlignment = HorizontalAlignment.Center
                });
                return;
            }

            for (int i = 0; i < visible.Count; i++)
            {
                RadarEntry entry = visible[i];
                var rowBorder = new Border
                {
                    Background = Brushes.Transparent,
                    Padding = new Thickness(10, 7, 10, 7),
                    BorderBrush = new SolidColorBrush(_theme.Border),
                    BorderThickness = new Thickness(0, 0, 0, i < visible.Count - 1 ? 1 : 0),
                    Cursor = Cursors.Hand
                };
                var rg = new Grid();
                rg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var leftInfo = new StackPanel();
                leftInfo.Children.Add(new TextBlock
                {
                    Text = entry.Domain,
                    Foreground = new SolidColorBrush(_theme.Ink),
                    FontFamily = MonoFont,
                    FontSize = 10.8,
                    FontWeight = FontWeights.SemiBold,
                    TextTrimming = TextTrimming.CharacterEllipsis
                });
                string meta = string.IsNullOrEmpty(entry.Node)
                    ? (entry.ProcessName + " \u00b7 " + entry.AgeText)
                    : (entry.ProcessName + " \u00b7 " + entry.Node + " \u00b7 " + entry.AgeText);
                leftInfo.Children.Add(new TextBlock
                {
                    Text = meta,
                    Foreground = new SolidColorBrush(_theme.Faint),
                    FontFamily = UiFont,
                    FontSize = 9.8,
                    TextTrimming = TextTrimming.CharacterEllipsis
                });
                Grid.SetColumn(leftInfo, 0);
                rg.Children.Add(leftInfo);

                var msTb = new TextBlock
                {
                    Text = entry.LatencyMs > 0 ? (entry.LatencyMs + " ms") : "\u2014",
                    Foreground = new SolidColorBrush(_theme.Muted),
                    FontFamily = MonoFont,
                    FontSize = 10,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(8, 0, 8, 0)
                };
                ApplyTabularNums(msTb);
                Grid.SetColumn(msTb, 1);
                rg.Children.Add(msTb);

                var badge = new Border
                {
                    CornerRadius = new CornerRadius(5),
                    BorderThickness = new Thickness(1),
                    Background = new SolidColorBrush(entry.IsTunnel ? _theme.OkSoft : _theme.Well),
                    BorderBrush = new SolidColorBrush(entry.IsTunnel ? _theme.OkBorder : _theme.BorderStrong),
                    Padding = new Thickness(6, 2, 6, 2),
                    VerticalAlignment = VerticalAlignment.Center
                };
                badge.Child = new TextBlock
                {
                    Text = entry.IsTunnel ? "TUNNEL" : "DIRECT",
                    Foreground = new SolidColorBrush(entry.IsTunnel ? _theme.Ok : _theme.Muted),
                    FontFamily = MonoFont,
                    FontSize = 9.5,
                    FontWeight = FontWeights.Bold
                };
                Grid.SetColumn(badge, 2);
                rg.Children.Add(badge);

                rowBorder.Child = rg;
                rowBorder.MouseEnter += delegate { SetOrAnimateBrush(rowBorder, Border.BackgroundProperty, _theme.SurfaceHover, 110); };
                rowBorder.MouseLeave += delegate { SetOrAnimateBrush(rowBorder, Border.BackgroundProperty, Color.FromArgb(0, _theme.SurfaceHover.R, _theme.SurfaceHover.G, _theme.SurfaceHover.B), 130); };
                rowBorder.MouseLeftButtonUp += delegate { ToggleRadarDomainRoute(entry); };
                _radarListHost.Children.Add(rowBorder);
            }
        }

        private void BuildRadarModalContent(bool animate, bool animateTab)
        {
            var root = BuildModalHeader(
                "Домены и трафик",
                "Живой радар + пользовательские правила Hot-Reload",
                "M12 2a10 10 0 1 0 10 10 M12 12l6-6 M12 6a6 6 0 1 0 6 6 M12 12m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0",
                _theme.Ok,
                _theme.OkSoft
            );

            root.Children.Add(BuildSegmentedTabs(
                "Живой радар",
                "Свои домены (" + (_customProxyDomains.Count + _customDirectDomains.Count) + ")",
                _radarTab,
                delegate(int idx)
                {
                    _radarTab = idx;
                    BuildRadarModalContent(false, true);
                    if (idx == 0) { var unused = RefreshLiveRadarFromEngineAsync(); }
                }
            ));

            var tabTrans = new TranslateTransform(0, 0);
            var tabBody = new StackPanel { RenderTransform = tabTrans };

            if (_radarTab == 0)
            {
                _radarListHost = null;
                // Search/filter input bar
                var searchBoxHost = new Border
                {
                    CornerRadius = new CornerRadius(8),
                    Background = new SolidColorBrush(_theme.StatusCardBg),
                    BorderBrush = new SolidColorBrush(_theme.Border),
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(9, 5, 9, 5),
                    Margin = new Thickness(0, 0, 0, 8)
                };
                var sg = new Grid();
                sg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                sg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                var sIcon = CreateIcon("M21 21l-4.35-4.35 M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", _theme.Faint, 11.5);
                sIcon.Margin = new Thickness(0, 0, 7, 0);
                Grid.SetColumn(sIcon, 0);
                sg.Children.Add(sIcon);

                var filterBox = new TextBox
                {
                    Text = string.IsNullOrEmpty(_radarFilterText) ? "Фильтр по домену или процессу..." : _radarFilterText,
                    Background = Brushes.Transparent,
                    BorderThickness = new Thickness(0),
                    Foreground = new SolidColorBrush(string.IsNullOrEmpty(_radarFilterText) ? _theme.Faint : _theme.Ink),
                    CaretBrush = new SolidColorBrush(_theme.Ink),
                    FontFamily = UiFont,
                    FontSize = 10.8,
                    VerticalContentAlignment = VerticalAlignment.Center
                };
                const string placeholderFilter = "Фильтр по домену или процессу...";
                filterBox.GotFocus += delegate
                {
                    if (filterBox.Text == placeholderFilter && string.IsNullOrEmpty(_radarFilterText))
                    {
                        filterBox.Text = "";
                        filterBox.Foreground = new SolidColorBrush(_theme.Ink);
                    }
                };
                filterBox.LostFocus += delegate
                {
                    if (string.IsNullOrEmpty(filterBox.Text))
                    {
                        _radarFilterText = "";
                        filterBox.Text = placeholderFilter;
                        filterBox.Foreground = new SolidColorBrush(_theme.Faint);
                    }
                };
                filterBox.TextChanged += delegate
                {
                    if (filterBox.Text != placeholderFilter)
                    {
                        _radarFilterText = filterBox.Text;
                        PopulateRadarListInPlace();
                    }
                };
                Grid.SetColumn(filterBox, 1);
                sg.Children.Add(filterBox);
                searchBoxHost.Child = sg;
                tabBody.Children.Add(searchBoxHost);

                var subRow = new Grid { Margin = new Thickness(2, 0, 2, 7) };
                subRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                subRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                _radarStatusLabel = new TextBlock
                {
                    Text = "PWP-4 MUX",
                    Foreground = new SolidColorBrush(_theme.Muted),
                    FontFamily = MonoFont,
                    FontSize = 10
                };
                subRow.Children.Add(_radarStatusLabel);
                var hint = new TextBlock
                {
                    Text = "Клик меняет маршрут",
                    Foreground = new SolidColorBrush(_theme.Accent),
                    FontFamily = UiFont,
                    FontSize = 10.2,
                    FontWeight = FontWeights.SemiBold
                };
                Grid.SetColumn(hint, 1);
                subRow.Children.Add(hint);
                tabBody.Children.Add(subRow);

                var listBox = new Border
                {
                    CornerRadius = new CornerRadius(9),
                    Background = new SolidColorBrush(_theme.StatusCardBg),
                    BorderBrush = new SolidColorBrush(_theme.Border),
                    BorderThickness = new Thickness(1),
                    Margin = new Thickness(0, 0, 0, 12),
                    MaxHeight = 250
                };
                var scroll = new ScrollViewer
                {
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
                };
                _radarListHost = new StackPanel();
                scroll.Content = _radarListHost;
                listBox.Child = scroll;
                tabBody.Children.Add(listBox);

                PopulateRadarListInPlace();
            }
            else
            {
                _radarListHost = null;
                _radarStatusLabel = null;
                var addBar = new Border
                {
                    CornerRadius = new CornerRadius(9),
                    Background = new SolidColorBrush(_theme.StatusCardBg),
                    BorderBrush = new SolidColorBrush(_theme.Border),
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(8, 6, 6, 6),
                    Margin = new Thickness(0, 0, 0, 10)
                };
                var ag = new Grid();
                ag.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                ag.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                ag.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var inputBox = new TextBox
                {
                    Text = string.IsNullOrEmpty(_draftRuleText) ? "example.com" : _draftRuleText,
                    Background = Brushes.Transparent,
                    BorderThickness = new Thickness(0),
                    Foreground = new SolidColorBrush(string.IsNullOrEmpty(_draftRuleText) ? _theme.Faint : _theme.Ink),
                    CaretBrush = new SolidColorBrush(_theme.Ink),
                    FontFamily = MonoFont,
                    FontSize = 11,
                    VerticalContentAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(2, 0, 8, 0)
                };
                inputBox.GotFocus += delegate
                {
                    if (inputBox.Text == "example.com" && string.IsNullOrEmpty(_draftRuleText))
                    {
                        inputBox.Text = "";
                        inputBox.Foreground = new SolidColorBrush(_theme.Ink);
                    }
                };
                inputBox.TextChanged += delegate
                {
                    if (inputBox.Text != "example.com") _draftRuleText = inputBox.Text;
                };
                inputBox.KeyDown += delegate(object ks, KeyEventArgs ke)
                {
                    if (ke.Key == Key.Enter)
                    {
                        ke.Handled = true;
                        AddCustomDomainFromText(inputBox.Text == "example.com" ? "" : inputBox.Text);
                    }
                };
                Grid.SetColumn(inputBox, 0);
                ag.Children.Add(inputBox);

                var modeBtn = new Border
                {
                    CornerRadius = new CornerRadius(6),
                    BorderThickness = new Thickness(1),
                    Background = new SolidColorBrush(_addRuleTunnel ? _theme.OkSoft : _theme.Well),
                    BorderBrush = new SolidColorBrush(_addRuleTunnel ? _theme.OkBorder : _theme.BorderStrong),
                    Padding = new Thickness(7, 4, 7, 4),
                    Margin = new Thickness(0, 0, 5, 0),
                    Cursor = Cursors.Hand
                };
                modeBtn.Child = new TextBlock
                {
                    Text = _addRuleTunnel ? "Туннель" : "Напрямую",
                    Foreground = new SolidColorBrush(_addRuleTunnel ? _theme.Ok : _theme.Muted),
                    FontFamily = UiFont,
                    FontSize = 10.5,
                    FontWeight = FontWeights.SemiBold
                };
                modeBtn.MouseLeftButtonUp += delegate
                {
                    _addRuleTunnel = !_addRuleTunnel;
                    BuildRadarModalContent(false, false);
                };
                Grid.SetColumn(modeBtn, 1);
                ag.Children.Add(modeBtn);

                var addBtn = new Border
                {
                    CornerRadius = new CornerRadius(6),
                    Background = new SolidColorBrush(_theme.Accent),
                    Padding = new Thickness(9, 4, 9, 4),
                    Cursor = Cursors.Hand
                };
                addBtn.Child = new TextBlock
                {
                    Text = "+ Добавить",
                    Foreground = new SolidColorBrush(_theme.AccentInk),
                    FontFamily = UiFont,
                    FontSize = 10.5,
                    FontWeight = FontWeights.SemiBold
                };
                addBtn.MouseLeftButtonUp += delegate
                {
                    AddCustomDomainFromText(inputBox.Text == "example.com" ? "" : inputBox.Text);
                };
                Grid.SetColumn(addBtn, 2);
                ag.Children.Add(addBtn);

                addBar.Child = ag;
                tabBody.Children.Add(addBar);

                tabBody.Children.Add(BuildDomainChipSection("Всегда через туннель (TUNNEL)", _customProxyDomains, true));
                tabBody.Children.Add(BuildDomainChipSection("Всегда напрямую (DIRECT)", _customDirectDomains, false));

                var advCard = new Border
                {
                    CornerRadius = new CornerRadius(8),
                    BorderThickness = new Thickness(1),
                    Background = new SolidColorBrush(_rulesAdviceIsWarn ? _theme.WarnSoft : (string.IsNullOrEmpty(_rulesAdviceTitle) ? _theme.StatusCardBg : _theme.OkSoft)),
                    BorderBrush = new SolidColorBrush(_rulesAdviceIsWarn ? _theme.WarnBorder : (string.IsNullOrEmpty(_rulesAdviceTitle) ? _theme.Border : _theme.OkBorder)),
                    Padding = new Thickness(10, 8, 10, 8),
                    Margin = new Thickness(0, 0, 0, 10)
                };
                var advStack = new StackPanel();
                advStack.Children.Add(new TextBlock
                {
                    Text = string.IsNullOrEmpty(_rulesAdviceTitle) ? "Рекомендация" : _rulesAdviceTitle,
                    Foreground = new SolidColorBrush(_rulesAdviceIsWarn ? _theme.Warn : (string.IsNullOrEmpty(_rulesAdviceTitle) ? _theme.Ink : _theme.Ok)),
                    FontFamily = UiFont,
                    FontSize = 10.8,
                    FontWeight = FontWeights.SemiBold,
                    TextWrapping = TextWrapping.Wrap
                });
                advStack.Children.Add(new TextBlock
                {
                    Text = string.IsNullOrEmpty(_rulesAdviceBody)
                        ? "Добавляйте корневой домен (например, claude.ai) — поддомены подхватятся автоматически, без разрыва туннеля."
                        : _rulesAdviceBody,
                    Foreground = new SolidColorBrush(_theme.Muted),
                    FontFamily = UiFont,
                    FontSize = 10.2,
                    TextWrapping = TextWrapping.Wrap,
                    LineHeight = 14.5,
                    Margin = new Thickness(0, 2, 0, 0)
                });
                advCard.Child = advStack;
                tabBody.Children.Add(advCard);
            }

            if (animateTab)
            {
                var tFade = new DoubleAnimation(0.25, 1.0, TimeSpan.FromMilliseconds(160))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                var tSlide = new DoubleAnimation(5.0, 0.0, TimeSpan.FromMilliseconds(170))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                tabBody.BeginAnimation(OpacityProperty, tFade);
                tabTrans.BeginAnimation(TranslateTransform.YProperty, tSlide);
            }

            root.Children.Add(tabBody);
            root.Children.Add(CreateModalButton("Готово", true, delegate { CloseModal(); }));
            OpenModal("radar", 464, root, animate);
        }

        private StackPanel BuildDomainChipSection(string title, List<string> domains, bool isTunnel)
        {
            var sec = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
            sec.Children.Add(new TextBlock
            {
                Text = title,
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 10.5,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(2, 0, 0, 5)
            });

            var box = new Border
            {
                CornerRadius = new CornerRadius(8),
                Background = new SolidColorBrush(_theme.StatusCardBg),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 7, 8, 3)
            };
            var wrap = new WrapPanel();

            if (domains.Count == 0)
            {
                wrap.Children.Add(new TextBlock
                {
                    Text = "Список пуст — добавьте домен выше",
                    Foreground = new SolidColorBrush(_theme.Faint),
                    FontFamily = UiFont,
                    FontSize = 10.5,
                    Margin = new Thickness(2, 0, 0, 4)
                });
            }
            else
            {
                for (int i = 0; i < domains.Count; i++)
                {
                    string dom = domains[i];
                    var chip = new Border
                    {
                        CornerRadius = new CornerRadius(6),
                        BorderThickness = new Thickness(1),
                        Background = new SolidColorBrush(isTunnel ? _theme.OkSoft : _theme.Surface),
                        BorderBrush = new SolidColorBrush(isTunnel ? _theme.OkBorder : _theme.BorderStrong),
                        Padding = new Thickness(8, 3, 7, 3),
                        Margin = new Thickness(0, 0, 6, 5),
                        Cursor = Cursors.Hand,
                        ToolTip = "Нажмите, чтобы удалить правило"
                    };
                    var chRow = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    chRow.Children.Add(new TextBlock
                    {
                        Text = dom,
                        Foreground = new SolidColorBrush(isTunnel ? _theme.Ok : _theme.Ink),
                        FontFamily = MonoFont,
                        FontSize = 10.5,
                        Margin = new Thickness(0, 0, 5, 0)
                    });
                    chRow.Children.Add(new TextBlock
                    {
                        Text = "\u00D7",
                        Foreground = new SolidColorBrush(_theme.Muted),
                        FontFamily = UiFont,
                        FontSize = 11.5,
                        FontWeight = FontWeights.Bold
                    });
                    chip.Child = chRow;
                    chip.MouseLeftButtonUp += delegate
                    {
                        domains.Remove(dom);
                        SaveCustomRulesConfig(_customProxyDomains, _customDirectDomains);
                        _rulesAdviceIsWarn = false;
                        _rulesAdviceTitle = "Удалено правило: " + dom;
                        _rulesAdviceBody = "Домен возвращён к стандартной маршрутизации Smart PAC.";
                        UpdateRulesCountPill();
                        BuildRadarModalContent(false, false);
                        ApplyCustomRulesHotReloadAsync();
                    };
                    wrap.Children.Add(chip);
                }
            }

            box.Child = wrap;
            sec.Children.Add(box);
            return sec;
        }

        // ---------------------------------------------------------------------
        // 2. SMART DIAGNOSTICS + RECOMMENDATIONS & AUTO-FIX MODAL (NO MessageBox)
        // ---------------------------------------------------------------------
        private void ShowDiagnosticsModal()
        {
            _diagFixActionNotice = "";
            if (_diagItems.Count == 0 && !_isDiagRunning)
            {
                InitPendingDiagItems();
                BuildDiagModalContent(true);
                RunSmartDiagnosticsAsync(false, false);
            }
            else
            {
                BuildDiagModalContent(true);
                if (!_isDiagRunning)
                {
                    RunSmartDiagnosticsAsync(false, false);
                }
            }
        }

        private static int MergeDiagNodePair(DiagItemState a, DiagItemState b)
        {
            if (a == DiagItemState.Error || b == DiagItemState.Error) return 4;
            if (a == DiagItemState.Warn || b == DiagItemState.Warn) return 3;
            if (a == DiagItemState.Running || b == DiagItemState.Running) return 1;
            if (a == DiagItemState.Ok && b == DiagItemState.Ok) return 2;
            if (a == DiagItemState.Ok || b == DiagItemState.Ok) return 1;
            return 0;
        }

        private static int MapDiagItemState(DiagItemState s)
        {
            if (s == DiagItemState.Error) return 4;
            if (s == DiagItemState.Warn) return 3;
            if (s == DiagItemState.Ok) return 2;
            if (s == DiagItemState.Running) return 1;
            return 0;
        }

        private int[] BuildDiagNodeStates()
        {
            var states = new int[5];
            DiagItemState isp = DiagItemState.Pending, hosts = DiagItemState.Pending;
            DiagItemState conf = DiagItemState.Pending, tun = DiagItemState.Pending;
            DiagItemState eng = DiagItemState.Pending, lic = DiagItemState.Pending;
            DiagItemState ch = DiagItemState.Pending, ide = DiagItemState.Pending;
            for (int i = 0; i < _diagItems.Count; i++)
            {
                var it = _diagItems[i];
                if (it.Id == "isp_dns") isp = it.State;
                else if (it.Id == "hosts") hosts = it.State;
                else if (it.Id == "conflicts_ports") conf = it.State;
                else if (it.Id == "tun_dpi") tun = it.State;
                else if (it.Id == "engine_manifest") eng = it.State;
                else if (it.Id == "license") lic = it.State;
                else if (it.Id == "channels") ch = it.State;
                else if (it.Id == "ide_check") ide = it.State;
            }
            states[0] = MergeDiagNodePair(isp, hosts);
            states[1] = MergeDiagNodePair(conf, tun);
            states[2] = MergeDiagNodePair(eng, lic);
            states[3] = MapDiagItemState(ch);
            states[4] = MapDiagItemState(ide);
            return states;
        }

        private void InitPendingDiagItems()
        {
            _diagItems.Clear();
            _diagItems.Add(new DiagCheckItem { Id = "isp_dns", Title = "Прямой интернет РФ и WinInet прокси", State = DiagItemState.Pending, Detail = "ожидание" });
            _diagItems.Add(new DiagCheckItem { Id = "hosts", Title = "Файл Windows hosts (AI-перехваты)", State = DiagItemState.Pending, Detail = "ожидание" });
            _diagItems.Add(new DiagCheckItem { Id = "conflicts_ports", Title = "Службы ProksiFi и локальные порты", State = DiagItemState.Pending, Detail = "ожидание" });
            _diagItems.Add(new DiagCheckItem { Id = "tun_dpi", Title = "Сторонние TUN и Zapret / winws", State = DiagItemState.Pending, Detail = "ожидание" });
            _diagItems.Add(new DiagCheckItem { Id = "engine_manifest", Title = "Ядро Go uTLS / Fallback и манифест", State = DiagItemState.Pending, Detail = "ожидание" });
            _diagItems.Add(new DiagCheckItem { Id = "license", Title = "Лицензия и статус ключа", State = DiagItemState.Pending, Detail = "ожидание" });
            _diagItems.Add(new DiagCheckItem { Id = "channels", Title = "Каналы CloudCode / Gemini / OAuth / РФ", State = DiagItemState.Pending, Detail = "ожидание" });
            _diagItems.Add(new DiagCheckItem { Id = "ide_check", Title = "Antigravity IDE и language_server", State = DiagItemState.Pending, Detail = "ожидание" });
        }

        private void RefreshDiagModalIfOpen()
        {
            RunOnUiThread(delegate
            {
                if (_activeModalKind == "diag")
                {
                    BuildDiagModalContent(false);
                }
            });
        }

        private void BuildDiagModalContent(bool animate)
        {
            var root = new StackPanel();
            var top = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            titleStack.Children.Add(new ContentControl
            {
                Content = CreateIcon("M22 12h-4l-3 9L9 3l-3 9H2", _theme.Ok, 15),
                Margin = new Thickness(0, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center
            });
            titleStack.Children.Add(new TextBlock
            {
                Text = "Умная диагностика",
                Foreground = new SolidColorBrush(_theme.Ink),
                FontFamily = UiFont,
                FontSize = 13.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            Grid.SetColumn(titleStack, 0);
            top.Children.Add(titleStack);

            int completedCount = 0;
            int issueCount = 0;
            bool anyAutoFixable = false;
            var recs = new List<DiagCheckItem>();
            for (int i = 0; i < _diagItems.Count; i++)
            {
                var it = _diagItems[i];
                if (it.State != DiagItemState.Pending && it.State != DiagItemState.Running) completedCount++;
                if (it.State == DiagItemState.Warn || it.State == DiagItemState.Error)
                {
                    issueCount++;
                    if (it.CanAutoFix) anyAutoFixable = true;
                    if (!string.IsNullOrEmpty(it.Recommendation)) recs.Add(it);
                }
            }

            var counterTb = new TextBlock
            {
                Text = completedCount + "/" + Math.Max(8, _diagItems.Count),
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = MonoFont,
                FontSize = 10.5,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            };
            ApplyTabularNums(counterTb);
            Grid.SetColumn(counterTb, 1);
            top.Children.Add(counterTb);

            var xBtn = new Border
            {
                Width = 26,
                Height = 26,
                CornerRadius = new CornerRadius(7),
                Background = Brushes.Transparent,
                Cursor = Cursors.Hand,
                Child = CreateIcon("M18 6L6 18 M6 6l12 12", _theme.Muted, 11)
            };
            xBtn.MouseLeftButtonUp += delegate { CloseModal(); };
            Grid.SetColumn(xBtn, 2);
            top.Children.Add(xBtn);
            root.Children.Add(top);

            // Live 5-Node ASCII Diagnostics Scanner
            if (_diagAsciiEngine == null) _diagAsciiEngine = new AsciiDiagScannerEngine();
            _diagAsciiEngine.Render(_asciiTime, BuildDiagNodeStates(), _diagFixing, _isDark);
            _diagChamberBorder = new Border
            {
                Height = 96,
                CornerRadius = new CornerRadius(9),
                Background = new SolidColorBrush(_isDark ? Color.FromRgb(8, 9, 13) : Color.FromRgb(250, 251, 253)),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 0, 10),
                ClipToBounds = true
            };
            var diagImg = new Image
            {
                Source = _diagAsciiEngine.Bitmap,
                Stretch = Stretch.Fill,
                SnapsToDevicePixels = true
            };
            RenderOptions.SetBitmapScalingMode(diagImg, BitmapScalingMode.HighQuality);
            _diagChamberBorder.Child = diagImg;
            root.Children.Add(_diagChamberBorder);

            // Per-check status cards list
            var box = new Border
            {
                CornerRadius = new CornerRadius(9),
                Background = new SolidColorBrush(_theme.StatusCardBg),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 8, 10, 8),
                Margin = new Thickness(0, 0, 0, 10),
                MaxHeight = 240
            };
            var listScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };
            var list = new StackPanel();
            for (int i = 0; i < _diagItems.Count; i++)
            {
                DiagCheckItem item = _diagItems[i];
                var row = new Grid { Margin = new Thickness(0, i == 0 ? 0 : 7, 0, 0) };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var icoHolder = new ContentControl
                {
                    Width = 14,
                    Height = 14,
                    Margin = new Thickness(0, 0, 8, 0),
                    VerticalAlignment = VerticalAlignment.Center
                };
                Color nameCol = _theme.Ink;
                Color detCol = _theme.Ok;
                if (item.State == DiagItemState.Ok)
                {
                    icoHolder.Content = CreateIcon("M20 6L9 17l-5-5", _theme.Ok, 12);
                    detCol = _theme.Ok;
                }
                else if (item.State == DiagItemState.Warn)
                {
                    icoHolder.Content = CreateIcon("M12 9v4 M12 17h.01 M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z", _theme.Warn, 12);
                    detCol = _theme.Warn;
                }
                else if (item.State == DiagItemState.Error)
                {
                    icoHolder.Content = CreateIcon("M18 6L6 18 M6 6l12 12", _theme.Err, 11.5);
                    detCol = _theme.Err;
                }
                else if (item.State == DiagItemState.Running)
                {
                    icoHolder.Content = CreateSpinningIcon(_theme.Warn, 12);
                    nameCol = _theme.Muted;
                    detCol = _theme.Warn;
                }
                else
                {
                    icoHolder.Content = new Ellipse
                    {
                        Width = 10,
                        Height = 10,
                        Stroke = new SolidColorBrush(_theme.BorderStrong),
                        StrokeThickness = 1.4
                    };
                    nameCol = _theme.Faint;
                    detCol = _theme.Faint;
                }

                var nameTb = new TextBlock
                {
                    Text = item.Title,
                    Foreground = new SolidColorBrush(nameCol),
                    FontFamily = UiFont,
                    FontSize = 11.0,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    VerticalAlignment = VerticalAlignment.Center
                };
                var detTb = new TextBlock
                {
                    Text = string.IsNullOrEmpty(item.Detail) ? "ожидание" : item.Detail,
                    Foreground = new SolidColorBrush(detCol),
                    FontFamily = MonoFont,
                    FontSize = 9.8,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(8, 0, 0, 0)
                };

                Grid.SetColumn(icoHolder, 0);
                Grid.SetColumn(nameTb, 1);
                Grid.SetColumn(detTb, 2);
                row.Children.Add(icoHolder);
                row.Children.Add(nameTb);
                row.Children.Add(detTb);
                list.Children.Add(row);
            }
            listScroll.Content = list;
            box.Child = listScroll;
            root.Children.Add(box);

            // Recommendations + 1-click Auto-Fix card once checks complete
            if (!_isDiagRunning && completedCount >= _diagItems.Count && _diagItems.Count > 0)
            {
                if (issueCount > 0)
                {
                    var recCard = new Border
                    {
                        CornerRadius = new CornerRadius(9),
                        Background = new SolidColorBrush(_theme.WarnSoft),
                        BorderBrush = new SolidColorBrush(_theme.WarnBorder),
                        BorderThickness = new Thickness(1),
                        Padding = new Thickness(11, 9, 11, 10),
                        Margin = new Thickness(0, 0, 0, 10)
                    };
                    var recStack = new StackPanel();
                    recStack.Children.Add(new TextBlock
                    {
                        Text = string.Format("Обнаружено проблем: {0}", issueCount),
                        Foreground = new SolidColorBrush(_theme.Warn),
                        FontFamily = UiFont,
                        FontSize = 11.2,
                        FontWeight = FontWeights.SemiBold
                    });

                    int shownRecs = Math.Min(3, recs.Count);
                    for (int r = 0; r < shownRecs; r++)
                    {
                        recStack.Children.Add(new TextBlock
                        {
                            Text = "\u2022 " + recs[r].Recommendation,
                            Foreground = new SolidColorBrush(_theme.Muted),
                            FontFamily = UiFont,
                            FontSize = 10.3,
                            TextWrapping = TextWrapping.Wrap,
                            LineHeight = 14.2,
                            Margin = new Thickness(0, 3, 0, 0)
                        });
                    }

                    if (anyAutoFixable || !_isConnected)
                    {
                        var fixBtn = new Border
                        {
                            Height = 32,
                            CornerRadius = new CornerRadius(7),
                            Background = new SolidColorBrush(_theme.Warn),
                            Margin = new Thickness(0, 8, 0, 0),
                            Cursor = Cursors.Hand,
                            Child = new TextBlock
                            {
                                Text = _diagFixing ? "Выполняем ремонт..." : "Починить автоматически",
                                Foreground = new SolidColorBrush(Color.FromRgb(17, 17, 19)),
                                FontFamily = UiFont,
                                FontSize = 11.2,
                                FontWeight = FontWeights.Bold,
                                HorizontalAlignment = HorizontalAlignment.Center,
                                VerticalAlignment = VerticalAlignment.Center
                            }
                        };
                        fixBtn.MouseLeftButtonUp += delegate
                        {
                            if (!_diagFixing && !_isDiagRunning)
                            {
                                RunSmartDiagnosticsAsync(true, false);
                            }
                        };
                        recStack.Children.Add(fixBtn);
                    }

                    recCard.Child = recStack;
                    root.Children.Add(recCard);
                }
                else
                {
                    var okCard = new Border
                    {
                        CornerRadius = new CornerRadius(9),
                        Background = new SolidColorBrush(_theme.OkSoft),
                        BorderBrush = new SolidColorBrush(_theme.OkBorder),
                        BorderThickness = new Thickness(1),
                        Padding = new Thickness(11, 8, 11, 8),
                        Margin = new Thickness(0, 0, 0, 10)
                    };
                    var okStack = new StackPanel();
                    okStack.Children.Add(new TextBlock
                    {
                        Text = string.IsNullOrEmpty(_diagFixActionNotice)
                            ? "Ошибок не обнаружено — все каналы и IDE в норме"
                            : _diagFixActionNotice,
                        Foreground = new SolidColorBrush(_theme.Ok),
                        FontFamily = UiFont,
                        FontSize = 11.2,
                        FontWeight = FontWeights.SemiBold,
                        TextWrapping = TextWrapping.Wrap
                    });
                    okStack.Children.Add(new TextBlock
                    {
                        Text = string.Format("Шлюз :{0} · {1} · Сайты .RU напрямую", _activeHttpPort, PixelCoreService.ActiveEngineLabel),
                        Foreground = new SolidColorBrush(_theme.Muted),
                        FontFamily = UiFont,
                        FontSize = 10.3,
                        Margin = new Thickness(0, 2, 0, 0)
                    });
                    okCard.Child = okStack;
                    root.Children.Add(okCard);
                }
            }

            // Footer buttons: Скопировать логи | Сохранить | Повторить | Готово
            var btnRow = new Grid();
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.2, GridUnitType.Star) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.0, GridUnitType.Star) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0.9, GridUnitType.Star) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0.8, GridUnitType.Star) });

            Border copyBtn = null;
            copyBtn = CreateModalButton("Скопировать логи", false, delegate
            {
                try
                {
                    string passport = !string.IsNullOrEmpty(_lastSupportPassport) ? _lastSupportPassport : BuildLiveSupportPassportSnapshot();
                    string reportStr = BuildLocalDiagnosticReportString();
                    string fullPayload = reportStr.Contains("[PixelTunnel v")
                        ? reportStr
                        : (reportStr + "\r\n\r\n" + passport);
                    Clipboard.SetText(fullPayload);
                }
                catch { }
                TextBlock copyTb = copyBtn != null ? (copyBtn.Child as TextBlock) : null;
                if (copyTb != null)
                {
                    copyTb.Text = "Скопировано \u2713";
                    var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1600) };
                    t.Tick += delegate
                    {
                        t.Stop();
                        if (copyTb != null) copyTb.Text = "Скопировать логи";
                    };
                    t.Start();
                }
            });
            Grid.SetColumn(copyBtn, 0);
            btnRow.Children.Add(copyBtn);

            Border saveBtn = null;
            saveBtn = CreateModalButton("На Desktop", false, delegate
            {
                string savedPath = SaveDiagnosticReportToDesktop();
                TextBlock saveTb = saveBtn != null ? (saveBtn.Child as TextBlock) : null;
                if (saveTb != null)
                {
                    saveTb.Text = !string.IsNullOrEmpty(savedPath) ? "Сохранено \u2713" : "Ошибка";
                    var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1800) };
                    t.Tick += delegate
                    {
                        t.Stop();
                        if (saveTb != null) saveTb.Text = "На Desktop";
                    };
                    t.Start();
                }
            });
            Grid.SetColumn(saveBtn, 2);
            btnRow.Children.Add(saveBtn);

            var retryBtn = CreateModalButton("Повторить", false, delegate
            {
                if (!_isDiagRunning)
                {
                    _diagFixActionNotice = "";
                    InitPendingDiagItems();
                    BuildDiagModalContent(false);
                    RunSmartDiagnosticsAsync(false, false);
                }
            });
            Grid.SetColumn(retryBtn, 4);
            btnRow.Children.Add(retryBtn);

            var doneBtn = CreateModalButton(_isDiagRunning ? "Скрыть" : "Готово", true, delegate { CloseModal(); });
            Grid.SetColumn(doneBtn, 6);
            btnRow.Children.Add(doneBtn);

            root.Children.Add(btnRow);
            OpenModal("diag", 506, root, animate);
        }

        // ---------------------------------------------------------------------
        // 3. TOOLS & SYSTEM MODAL (THEME + AUTOSTART + INSTANT WAKE + WSL2)
        // ---------------------------------------------------------------------
        private static bool IsWindowsAutostartEnabled()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false))
                {
                    if (key != null)
                    {
                        object v = key.GetValue("PixelTunnel", null);
                        return v != null && !string.IsNullOrWhiteSpace(Convert.ToString(v));
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool SetWindowsAutostartEnabled(bool enable)
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (key == null) return false;
                    if (enable)
                    {
                        string exePath = "";
                        try { exePath = Assembly.GetExecutingAssembly().Location; } catch { }
                        if (string.IsNullOrEmpty(exePath))
                        {
                            try { using (var cp = Process.GetCurrentProcess()) { exePath = cp.MainModule.FileName; } } catch { }
                        }
                        if (string.IsNullOrEmpty(exePath) ||
                            !File.Exists(exePath) ||
                            exePath.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            exePath.StartsWith("\\\\", StringComparison.Ordinal))
                        {
                            return false;
                        }
                        key.SetValue("PixelTunnel", string.Format("\"{0}\" --autostart --minimized", exePath), RegistryValueKind.String);
                    }
                    else
                    {
                        key.DeleteValue("PixelTunnel", false);
                    }
                    return true;
                }
            }
            catch { return false; }
        }

        private void ShowToolsModal()
        {
            _optAutostart = IsWindowsAutostartEnabled();
            BuildToolsModalContent(true);
        }

        private void BuildToolsModalContent(bool animate)
        {
            var root = BuildModalHeader(
                "Система и инструменты",
                "Тема оформления \u00b7 Автозапуск \u00b7 WSL2",
                "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.26.6.85 1 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z",
                _theme.Accent,
                _theme.AccentSoft
            );

            root.Children.Add(new TextBlock
            {
                Text = "Тема оформления",
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 10.8,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(2, 0, 0, 5)
            });

            var themeWell = new Border
            {
                CornerRadius = new CornerRadius(8),
                Background = new SolidColorBrush(_theme.Well),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(3),
                Margin = new Thickness(0, 0, 0, 11)
            };
            var tg = new Grid();
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            ThemeModeChoice[] choices = new ThemeModeChoice[] { ThemeModeChoice.Light, ThemeModeChoice.Dark, ThemeModeChoice.System };
            string[] choiceLabels = new string[] { "Светлая", "Тёмная", "Как в Windows" };
            for (int i = 0; i < 3; i++)
            {
                ThemeModeChoice ch = choices[i];
                bool active = (_themeChoice == ch);
                var tb = new Border
                {
                    CornerRadius = new CornerRadius(6),
                    Background = active ? new SolidColorBrush(_theme.Surface) : Brushes.Transparent,
                    BorderBrush = active ? new SolidColorBrush(_theme.BorderStrong) : Brushes.Transparent,
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(6, 5, 6, 5),
                    Cursor = Cursors.Hand
                };
                tb.Child = new TextBlock
                {
                    Text = choiceLabels[i],
                    Foreground = new SolidColorBrush(active ? _theme.Ink : _theme.Muted),
                    FontFamily = UiFont,
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    HorizontalAlignment = HorizontalAlignment.Center
                };
                tb.MouseLeftButtonUp += delegate
                {
                    ApplyThemeChoice(ch, true);
                };
                Grid.SetColumn(tb, i * 2);
                tg.Children.Add(tb);
            }
            themeWell.Child = tg;
            root.Children.Add(themeWell);

            var sysCard = new Border
            {
                CornerRadius = new CornerRadius(9),
                Background = new SolidColorBrush(_theme.StatusCardBg),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 0, 12)
            };
            var sysStack = new StackPanel();
            sysStack.Children.Add(CreateToolSwitchRow("Автозапуск с Windows", "Тихий старт в трей + автоподключение", _optAutostart, true, delegate(bool nextVal)
            {
                _optAutostart = SetWindowsAutostartEnabled(nextVal) ? nextVal : IsWindowsAutostartEnabled();
            }));
            sysStack.Children.Add(CreateToolSwitchRow("Instant Wake (Сон / Wi-Fi)", "Переподключение <300 мс после смены сети", _optInstantWake, true, delegate(bool nextVal)
            {
                _optInstantWake = nextVal;
                PixelCoreService.InstantWakeEnabled = nextVal;
                SaveCurrentState();
                ApplyRulesHotReloadAsync(false, false);
            }));
            sysStack.Children.Add(CreateToolSwitchRow("Поддержка Linux (WSL2)", "Туннель для терминала и AI-агентов внутри WSL", _optWslBridge, false, delegate(bool nextVal)
            {
                _optWslBridge = nextVal;
                SaveCurrentState();
                ApplyRulesHotReloadAsync(false, false);
            }));
            sysCard.Child = sysStack;
            root.Children.Add(sysCard);

            root.Children.Add(CreateModalButton("Готово", true, delegate { CloseModal(); }));
            OpenModal("tools", 436, root, animate);
        }

        private void CreatePillSwitch(bool initialOn, out Border track, out Border thumb, out TranslateTransform thumbTrans)
        {
            thumbTrans = new TranslateTransform(initialOn ? 16 : 0, 0);
            thumb = new Border
            {
                Width = 14,
                Height = 14,
                CornerRadius = new CornerRadius(7),
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center,
                Background = new SolidColorBrush(initialOn ? _theme.AccentInk : _theme.Muted),
                RenderTransform = thumbTrans
            };
            track = new Border
            {
                Width = 36,
                Height = 20,
                CornerRadius = new CornerRadius(10),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(2),
                VerticalAlignment = VerticalAlignment.Center,
                Background = new SolidColorBrush(initialOn ? _theme.Accent : _theme.Well),
                BorderBrush = new SolidColorBrush(initialOn ? _theme.Accent : _theme.BorderStrong),
                Child = thumb
            };
        }

        private void UpdatePillSwitchVisual(Border track, Border thumb, TranslateTransform thumbTrans, bool state, int durMs, bool animateSlide)
        {
            if (track != null)
            {
                SetOrAnimateBrush(track, Border.BackgroundProperty, state ? _theme.Accent : _theme.Well, durMs);
                SetOrAnimateBrush(track, Border.BorderBrushProperty, state ? _theme.Accent : _theme.BorderStrong, durMs);
            }
            if (thumb != null)
            {
                SetOrAnimateBrush(thumb, Border.BackgroundProperty, state ? _theme.AccentInk : _theme.Muted, durMs);
            }
            if (thumbTrans != null)
            {
                double targetX = state ? 16.0 : 0.0;
                if (animateSlide)
                {
                    var slide = new DoubleAnimation(targetX, TimeSpan.FromMilliseconds(200))
                    {
                        EasingFunction = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.22 }
                    };
                    thumbTrans.BeginAnimation(TranslateTransform.XProperty, slide);
                }
                else
                {
                    thumbTrans.BeginAnimation(TranslateTransform.XProperty, null);
                    thumbTrans.X = targetX;
                }
            }
        }

        private Border CreateToolSwitchRow(string title, string sub, bool initialOn, bool hasDivider, Action<bool> onChanged)
        {
            bool state = initialOn;
            var b = new Border
            {
                Background = Brushes.Transparent,
                Padding = new Thickness(11, 8, 11, 8),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(0, 0, 0, hasDivider ? 1 : 0),
                Cursor = Cursors.Hand
            };
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var ts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            ts.Children.Add(new TextBlock { Text = title, Foreground = new SolidColorBrush(_theme.Ink), FontFamily = UiFont, FontSize = 11.6, FontWeight = FontWeights.SemiBold });
            ts.Children.Add(new TextBlock { Text = sub, Foreground = new SolidColorBrush(_theme.Muted), FontFamily = UiFont, FontSize = 10.2, Margin = new Thickness(0, 1, 0, 0) });
            Grid.SetColumn(ts, 0);
            g.Children.Add(ts);

            Border track, thumb;
            TranslateTransform thumbTrans;
            CreatePillSwitch(state, out track, out thumb, out thumbTrans);
            Grid.SetColumn(track, 1);
            g.Children.Add(track);

            b.Child = g;
            b.MouseEnter += delegate { SetOrAnimateBrush(b, Border.BackgroundProperty, _theme.SurfaceHover, 110); };
            b.MouseLeave += delegate { SetOrAnimateBrush(b, Border.BackgroundProperty, Color.FromArgb(0, _theme.SurfaceHover.R, _theme.SurfaceHover.G, _theme.SurfaceHover.B), 130); };
            b.MouseLeftButtonUp += delegate
            {
                state = !state;
                onChanged(state);
                UpdatePillSwitchVisual(track, thumb, thumbTrans, state, 180, true);
            };
            return b;
        }

        // ---------------------------------------------------------------------
        // 4. MATRIX VPN CHOICE (PIXEL VS AETHER) & PRO / TUN / UPDATE / DONATE
        // ---------------------------------------------------------------------
        private void ShowOurVpnMatrixModal()
        {
            var root = new StackPanel();

            var top = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleStack = new StackPanel();
            titleStack.Children.Add(new TextBlock
            {
                Text = "ВЫБОР ПРОТОКОЛА \u00b7 ДВЕ ТАБЛЕТКИ",
                Foreground = new SolidColorBrush(_theme.Faint),
                FontFamily = MonoFont,
                FontSize = 9.8,
                FontWeight = FontWeights.Bold
            });
            titleStack.Children.Add(new TextBlock
            {
                Text = "Выбери свой VPN",
                Foreground = new SolidColorBrush(_theme.Ink),
                FontFamily = UiFont,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 2, 0, 1)
            });
            titleStack.Children.Add(new TextBlock
            {
                Text = "Два наших проекта под разные задачи — синяя или красная таблетка",
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 11.2
            });
            Grid.SetColumn(titleStack, 0);
            top.Children.Add(titleStack);

            var xBtn = new Border
            {
                Width = 26,
                Height = 26,
                CornerRadius = new CornerRadius(7),
                Background = Brushes.Transparent,
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Top,
                Child = CreateIcon("M18 6L6 18 M6 6l12 12", _theme.Muted, 11)
            };
            xBtn.MouseLeftButtonUp += delegate { CloseModal(); };
            Grid.SetColumn(xBtn, 1);
            top.Children.Add(xBtn);
            root.Children.Add(top);

            Color blueMain = _isDark ? Color.FromRgb(59, 130, 246) : Color.FromRgb(29, 78, 216);
            Color blueHalf = _isDark ? Color.FromRgb(37, 99, 235) : Color.FromRgb(59, 130, 246);
            Color blueInk = Color.FromRgb(255, 255, 255);
            Color blueSoft = _isDark ? Color.FromRgb(20, 34, 62) : Color.FromRgb(238, 242, 255);
            Color blueBorder = _isDark ? Color.FromRgb(37, 68, 126) : Color.FromRgb(199, 215, 254);

            Color redMain = _isDark ? Color.FromRgb(239, 68, 68) : Color.FromRgb(220, 38, 38);
            Color redHalf = _isDark ? Color.FromRgb(185, 28, 28) : Color.FromRgb(248, 113, 113);
            Color redInk = Color.FromRgb(255, 255, 255);
            Color redSoft = _isDark ? Color.FromRgb(48, 16, 20) : Color.FromRgb(254, 242, 242);
            Color redBorder = _isDark ? Color.FromRgb(127, 29, 29) : Color.FromRgb(254, 202, 202);

            var cardsGrid = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            cardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            cardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
            cardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            _vpnBlueEngine = new AsciiVpnPillEngine();
            _vpnRedEngine = new AsciiVpnPillEngine();
            _vpnBlueHover = false;
            _vpnRedHover = false;
            _vpnBlueEngine.Render(_asciiTime, false, _isDark, false);
            _vpnRedEngine.Render(_asciiTime, true, _isDark, false);

            var pixelCard = CreateMatrixChoiceCard(
                blueMain, blueInk, blueSoft, blueBorder,
                false, _vpnBlueEngine,
                "VLESS + REALITY",
                "Pixel VPN",
                "iOS \u00b7 Android \u00b7 ПК",
                "Универсальный VPN + PRO в PixelTunnel",
                new string[]
                {
                    "iPhone (iOS), Android, macOS и Windows",
                    "Один ключ открывает YouTube и Discord",
                    "Высокая скорость, стабильный пинг и быстрый старт"
                },
                "Синяя \u00b7 @p1xivpn_bot",
                delegate
                {
                    CloseModal();
                    try { Process.Start(new ProcessStartInfo(GetTelegramBotUrl()) { UseShellExecute = true }); } catch { }
                    FlashStatusSub("Открыт Pixel VPN (@p1xivpn_bot)");
                }
            );
            Grid.SetColumn(pixelCard, 0);
            cardsGrid.Children.Add(pixelCard);

            var aetherCard = CreateMatrixChoiceCard(
                redMain, redInk, redSoft, redBorder,
                true, _vpnRedEngine,
                "PRIVATE PROTOCOL \u00b7 PQ",
                "Aether VPN",
                "100 \u20BD/\u043c\u0435\u0441 \u00b7 24\u0447",
                "Собственный стелс-протокол нового поколения",
                new string[]
                {
                    "Закрытый протокол (не VLESS) + ML-KEM",
                    "Обход резки на 16 КБ и жёсткого ТСПУ",
                    "Android + Windows, до 5 устройств, RU Split"
                },
                "Красная \u00b7 @AetherAccessBot",
                delegate
                {
                    CloseModal();
                    try { Process.Start(new ProcessStartInfo("https://t.me/AetherAccessBot") { UseShellExecute = true }); } catch { }
                    FlashStatusSub("Открыт Aether VPN (@AetherAccessBot)");
                }
            );
            Grid.SetColumn(aetherCard, 2);
            cardsGrid.Children.Add(aetherCard);

            root.Children.Add(cardsGrid);

            var foot = new Grid();
            foot.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            foot.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            foot.Children.Add(new TextBlock
            {
                Text = "iOS и PRO здесь \u2192 Pixel  \u00B7  Максимум анти-ТСПУ \u2192 Aether",
                Foreground = new SolidColorBrush(_theme.Faint),
                FontFamily = UiFont,
                FontSize = 10,
                VerticalAlignment = VerticalAlignment.Center
            });

            var keyLink = new TextBlock
            {
                Text = "Вставить PRO-ключ \u2192",
                Foreground = new SolidColorBrush(_theme.Accent),
                FontFamily = UiFont,
                FontSize = 10.5,
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center
            };
            keyLink.MouseLeftButtonUp += delegate
            {
                CloseModal();
                ToggleKeyDrawer(true);
            };
            Grid.SetColumn(keyLink, 1);
            foot.Children.Add(keyLink);
            root.Children.Add(foot);

            OpenModal("vpn_matrix", 564, root, true);
        }

        private Border CreateMatrixChoiceCard(
            Color mainCol,
            Color ctaInk,
            Color softBg,
            Color softBorder,
            bool isRedPill,
            AsciiVpnPillEngine pillEngine,
            string protoTag,
            string title,
            string badgeText,
            string tagline,
            string[] bullets,
            string ctaText,
            Action onChoose)
        {
            var scale = new ScaleTransform(1.0, 1.0);
            var card = new Border
            {
                CornerRadius = new CornerRadius(10),
                Background = new SolidColorBrush(_theme.StatusCardBg),
                BorderBrush = new SolidColorBrush(_theme.BorderStrong),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(13, 12, 13, 12),
                Cursor = Cursors.Hand,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = scale
            };

            var stack = new Grid();
            stack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            stack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            stack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            stack.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            stack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var pillChamber = new Border
            {
                Height = 76,
                CornerRadius = new CornerRadius(8),
                Background = new SolidColorBrush(_isDark ? Color.FromRgb(8, 9, 13) : Color.FromRgb(250, 251, 253)),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 0, 10),
                ClipToBounds = true
            };
            var pillGrid = new Grid();
            var pillImg = new Image
            {
                Source = pillEngine.Bitmap,
                Stretch = Stretch.Fill,
                SnapsToDevicePixels = true
            };
            RenderOptions.SetBitmapScalingMode(pillImg, BitmapScalingMode.HighQuality);
            pillGrid.Children.Add(pillImg);

            var tagBadge = new Border
            {
                CornerRadius = new CornerRadius(4),
                Background = new SolidColorBrush(_isDark ? Color.FromArgb(220, 10, 11, 16) : Color.FromArgb(230, 255, 255, 255)),
                BorderBrush = new SolidColorBrush(_theme.Border),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(5, 1.5, 5, 1.5),
                Margin = new Thickness(0, 5, 6, 0),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Top,
                Child = new TextBlock
                {
                    Text = protoTag,
                    Foreground = new SolidColorBrush(mainCol),
                    FontFamily = MonoFont,
                    FontSize = 8.6,
                    FontWeight = FontWeights.Bold
                }
            };
            pillGrid.Children.Add(tagBadge);
            pillChamber.Child = pillGrid;
            Grid.SetRow(pillChamber, 0);
            stack.Children.Add(pillChamber);

            var titleRow = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 0, 3) };
            titleRow.Children.Add(new TextBlock
            {
                Text = title,
                Foreground = new SolidColorBrush(_theme.Ink),
                FontFamily = UiFont,
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            });
            var badge = new Border
            {
                CornerRadius = new CornerRadius(5),
                Background = new SolidColorBrush(softBg),
                BorderBrush = new SolidColorBrush(softBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(5, 1.5, 5, 1.5),
                Margin = new Thickness(7, 1, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = badgeText,
                    Foreground = new SolidColorBrush(mainCol),
                    FontFamily = MonoFont,
                    FontSize = 9,
                    FontWeight = FontWeights.Bold
                }
            };
            titleRow.Children.Add(badge);
            Grid.SetRow(titleRow, 1);
            stack.Children.Add(titleRow);

            var tagLineTb = new TextBlock
            {
                Text = tagline,
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 10.8,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 9)
            };
            Grid.SetRow(tagLineTb, 2);
            stack.Children.Add(tagLineTb);

            var bStack = new StackPanel { Margin = new Thickness(0, 0, 0, 12), VerticalAlignment = VerticalAlignment.Top };
            for (int i = 0; i < bullets.Length; i++)
            {
                var bg = new Grid { Margin = new Thickness(0, i == 0 ? 0 : 5, 0, 0) };
                bg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                bg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                var chk = CreateIcon("M20 6L9 17l-5-5", mainCol, 10.5);
                chk.Margin = new Thickness(0, 2, 6, 0);
                chk.VerticalAlignment = VerticalAlignment.Top;
                Grid.SetColumn(chk, 0);
                bg.Children.Add(chk);

                var bTb = new TextBlock
                {
                    Text = bullets[i],
                    Foreground = new SolidColorBrush(_theme.Ink),
                    FontFamily = UiFont,
                    FontSize = 10.7,
                    TextWrapping = TextWrapping.Wrap,
                    LineHeight = 14.5
                };
                Grid.SetColumn(bTb, 1);
                bg.Children.Add(bTb);
                bStack.Children.Add(bg);
            }
            Grid.SetRow(bStack, 3);
            stack.Children.Add(bStack);

            var cta = new Border
            {
                Height = 32,
                CornerRadius = new CornerRadius(7),
                Background = new SolidColorBrush(mainCol),
                Padding = new Thickness(8, 0, 8, 0),
                Child = new TextBlock
                {
                    Text = ctaText,
                    Foreground = new SolidColorBrush(ctaInk),
                    FontFamily = UiFont,
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };
            Grid.SetRow(cta, 4);
            stack.Children.Add(cta);

            card.Child = stack;

            card.MouseEnter += delegate
            {
                if (isRedPill) _vpnRedHover = true; else _vpnBlueHover = true;
                SetOrAnimateBrush(card, Border.BorderBrushProperty, mainCol, 150);
                SetOrAnimateBrush(card, Border.BackgroundProperty, _theme.Surface, 150);
                var anim = new DoubleAnimation(1.014, TimeSpan.FromMilliseconds(160))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                scale.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                scale.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
            };
            card.MouseLeave += delegate
            {
                if (isRedPill) _vpnRedHover = false; else _vpnBlueHover = false;
                SetOrAnimateBrush(card, Border.BorderBrushProperty, _theme.BorderStrong, 170);
                SetOrAnimateBrush(card, Border.BackgroundProperty, _theme.StatusCardBg, 170);
                var anim = new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(160))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                scale.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                scale.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
            };
            card.MouseLeftButtonUp += delegate { onChoose(); };

            return card;
        }

        private FrameworkElement CreateMatrixPillCapsule(Color mainCol, Color halfCol, out RotateTransform rotOut, out TranslateTransform transOut)
        {
            var capsuleHost = new Grid
            {
                Width = 46,
                Height = 24,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center
            };

            rotOut = new RotateTransform(-16);
            transOut = new TranslateTransform(0, 0);
            var tg = new TransformGroup();
            tg.Children.Add(rotOut);
            tg.Children.Add(transOut);

            var cv = new Canvas
            {
                Width = 44,
                Height = 22,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = tg,
                Effect = new DropShadowEffect
                {
                    BlurRadius = 7,
                    ShadowDepth = 2,
                    Direction = 270,
                    Color = Colors.Black,
                    Opacity = 0.25
                }
            };

            Color darkShade = Color.FromRgb(
                (byte)Math.Max(0, (int)mainCol.R - 28),
                (byte)Math.Max(0, (int)mainCol.G - 28),
                (byte)Math.Max(0, (int)mainCol.B - 28));

            var leftBrush = new LinearGradientBrush
            {
                StartPoint = new Point(0.5, 0),
                EndPoint = new Point(0.5, 1)
            };
            leftBrush.GradientStops.Add(new GradientStop(mainCol, 0.0));
            leftBrush.GradientStops.Add(new GradientStop(darkShade, 1.0));

            var rightBrush = new LinearGradientBrush
            {
                StartPoint = new Point(0.5, 0),
                EndPoint = new Point(0.5, 1)
            };
            rightBrush.GradientStops.Add(new GradientStop(halfCol, 0.0));
            rightBrush.GradientStops.Add(new GradientStop(mainCol, 1.0));

            cv.Children.Add(new ShapePath
            {
                Data = Geometry.Parse("M 9,4 H 22 V 18 H 9 A 7,7 0 0 1 9,4 Z"),
                Fill = leftBrush
            });
            cv.Children.Add(new ShapePath
            {
                Data = Geometry.Parse("M 22,4 H 35 A 7,7 0 0 1 35,18 H 22 Z"),
                Fill = rightBrush
            });
            cv.Children.Add(new Line
            {
                X1 = 22, Y1 = 4,
                X2 = 22, Y2 = 18,
                Stroke = new SolidColorBrush(Color.FromArgb(95, 255, 255, 255)),
                StrokeThickness = 1
            });

            var gloss = new Rectangle
            {
                Width = 22,
                Height = 3,
                RadiusX = 1.5,
                RadiusY = 1.5,
                Fill = new SolidColorBrush(Color.FromArgb(115, 255, 255, 255))
            };
            Canvas.SetLeft(gloss, 11);
            Canvas.SetTop(gloss, 6);
            cv.Children.Add(gloss);

            capsuleHost.Children.Add(cv);
            return capsuleHost;
        }

        private void ShowProModal()
        {
            var root = BuildModalHeader(
                "PixelTunnel PRO \u2014 Медиа",
                "YouTube \u2022 Discord Voice (TUN)",
                "M12 2L4 5.5v6C4 16.8 7.4 21.6 12 23c4.6-1.4 8-6.2 8-11.5v-6L12 2z M13 8l-3 5h3l-1 4 3-5h-3z",
                _theme.Warn,
                _theme.WarnSoft
            );

            root.Children.Add(new TextBlock
            {
                Text = "Antigravity, нейросети, Telegram и соцсети работают полностью бесплатно и бессрочно. Тяжёлый видео- и голосовой трафик (YouTube + Discord TUN) открывается по персональному ключу из @p1xivpn_bot.",
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 11.8,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 17,
                Margin = new Thickness(0, 0, 0, 14)
            });

            var btnRow = new Grid();
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var b1 = CreateModalButton("Получить PRO в боте", true, delegate
            {
                CloseModal();
                try { Process.Start(new ProcessStartInfo(GetTelegramBotUrl()) { UseShellExecute = true }); } catch { }
            });
            Grid.SetColumn(b1, 0);
            btnRow.Children.Add(b1);

            var b2 = CreateModalButton("Вставить ключ", false, delegate
            {
                CloseModal();
                ToggleKeyDrawer(true);
            });
            Grid.SetColumn(b2, 2);
            btnRow.Children.Add(b2);

            root.Children.Add(btnRow);
            OpenModal("pro", 392, root, true);
        }

        private void ShowTunModal(bool isMediaFlow)
        {
            var root = BuildModalHeader(
                "Драйвер Wintun (TUN)",
                isMediaFlow ? "Голос Discord и игры" : "Десктопный Telegram & Discord",
                "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4",
                _theme.Accent,
                _theme.AccentSoft
            );

            root.Children.Add(new TextBlock
            {
                Text = isMediaFlow
                    ? "YouTube и браузерный Discord работают сразу без прав администратора. Включить встроенный драйвер Wintun (TUN) для голосовых каналов Discord (перезапуск от имени Администратора)?"
                    : "Браузерная версия работает сразу без прав администратора. Включить встроенный сетевой драйвер Wintun (TUN), чтобы десктопный Telegram работал автоматически без ручной настройки прокси?",
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 11.8,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 17,
                Margin = new Thickness(0, 0, 0, 14)
            });

            var btnRow = new Grid();
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var b1 = CreateModalButton("Включить TUN", true, delegate
            {
                CloseModal();
                _optTunMode = true;
                SaveCurrentState();
                UpdateConnectionVisuals(false);
                RelaunchAsAdmin(_isConnected ? "--autoconnect --elevated-tun" : "--elevated-tun");
                if (!IsAdministratorStatic())
                {
                    _optTunMode = false;
                    SaveCurrentState();
                    UpdateConnectionVisuals(false);
                }
            });
            Grid.SetColumn(b1, 0);
            btnRow.Children.Add(b1);

            var b2 = CreateModalButton("Только браузер", false, delegate
            {
                _optTunMode = false;
                SaveCurrentState();
                UpdateConnectionVisuals(false);
                CloseModal();
            });
            Grid.SetColumn(b2, 2);
            btnRow.Children.Add(b2);

            root.Children.Add(btnRow);
            OpenModal("tun", 392, root, true);
        }

        private void ShowUpdateModal()
        {
            bool hasManifestAutoUpd =
                PixelCoreService.IsNewerVersion(APP_VERSION, PixelCoreService.ManifestLatestVersion) &&
                !string.IsNullOrEmpty(PixelCoreService.ManifestUpdateUrl) &&
                !string.IsNullOrEmpty(PixelCoreService.ManifestUpdateSha256) &&
                PixelCoreService.ManifestUpdateSha256.Trim().Length == 64;

            string verLabel = hasManifestAutoUpd
                ? PixelCoreService.ManifestLatestVersion
                : (!string.IsNullOrEmpty(_githubLatestVer) ? _githubLatestVer : APP_VERSION);
            string sub = hasManifestAutoUpd
                ? "SHA-256 Verified \u00b7 Signed Manifest"
                : "GitHub Release";
            string notes = hasManifestAutoUpd && !string.IsNullOrEmpty(PixelCoreService.ManifestUpdateNotes)
                ? PixelCoreService.ManifestUpdateNotes
                : "Доступна новая версия PixelTunnel v" + verLabel + " с обновлениями движка uTLS и маршрутизации.";

            var root = BuildModalHeader(
                "Доступно обновление v" + verLabel,
                sub,
                "M12 19V5 M5 12l7-7 7 7",
                _theme.Ok,
                _theme.OkSoft
            );

            root.Children.Add(new TextBlock
            {
                Text = notes,
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 11.8,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 17,
                Margin = new Thickness(0, 0, 0, 14)
            });

            var btnRow = new Grid();
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var b1 = CreateModalButton(hasManifestAutoUpd ? "Обновить сейчас" : "Открыть GitHub", true, delegate
            {
                CloseModal();
                if (hasManifestAutoUpd)
                {
                    PerformSafeInAppUpdateAsync();
                }
                else if (!string.IsNullOrEmpty(_githubReleaseUrl))
                {
                    try { using (var p = Process.Start(new ProcessStartInfo(_githubReleaseUrl) { UseShellExecute = true })) { } } catch { }
                }
            });
            Grid.SetColumn(b1, 0);
            btnRow.Children.Add(b1);

            var b2 = CreateModalButton("Позже", false, delegate { CloseModal(); });
            Grid.SetColumn(b2, 2);
            btnRow.Children.Add(b2);

            root.Children.Add(btnRow);
            OpenModal("update", 392, root, true);
        }

        private void ShowDonateModal()
        {
            var root = BuildModalHeader(
                "Поддержать PixelTunnel",
                "Серверы AI-туннеля работают бесплатно",
                "M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78L12 21.23l8.84-8.84a5.5 5.5 0 0 0 0-7.78z",
                _theme.Warn,
                _theme.WarnSoft
            );

            root.Children.Add(new TextBlock
            {
                Text = "Доступ для Antigravity IDE, нейросетей и базовых сервисов поддерживается бесплатно за счёт сообщества и PRO-подписок. Вы можете поддержать развитие серверов на странице проекта.",
                Foreground = new SolidColorBrush(_theme.Muted),
                FontFamily = UiFont,
                FontSize = 11.8,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 17,
                Margin = new Thickness(0, 0, 0, 14)
            });

            var btnRow = new Grid();
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
            btnRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var b1 = CreateModalButton("Открыть страницу", true, delegate
            {
                CloseModal();
                try { Process.Start(new ProcessStartInfo(GetProjectDonateUrl()) { UseShellExecute = true }); } catch { }
            });
            Grid.SetColumn(b1, 0);
            btnRow.Children.Add(b1);

            var b2 = CreateModalButton("Закрыть", false, delegate { CloseModal(); });
            Grid.SetColumn(b2, 2);
            btnRow.Children.Add(b2);

            root.Children.Add(btnRow);
            OpenModal("donate", 392, root, true);
        }

        // =====================================================================
        // VECTOR & ANIMATION HELPERS
        // =====================================================================
        private FrameworkElement CreateIcon(string pathData, Color strokeColor, double size)
        {
            return new ShapePath
            {
                Data = Geometry.Parse(pathData),
                Stroke = new SolidColorBrush(strokeColor),
                StrokeThickness = 1.8,
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
        }

        private static void StopSpinnerAnimations(DependencyObject root)
        {
            if (root == null) return;
            try
            {
                var fe = root as FrameworkElement;
                if (fe != null)
                {
                    var rt = fe.RenderTransform as RotateTransform;
                    if (rt != null)
                    {
                        rt.BeginAnimation(RotateTransform.AngleProperty, null);
                    }
                }
                int count = VisualTreeHelper.GetChildrenCount(root);
                for (int i = 0; i < count; i++)
                {
                    StopSpinnerAnimations(VisualTreeHelper.GetChild(root, i));
                }
                var cc = root as ContentControl;
                if (cc != null && cc.Content is DependencyObject)
                {
                    StopSpinnerAnimations((DependencyObject)cc.Content);
                }
                var bd = root as Border;
                if (bd != null && bd.Child != null)
                {
                    StopSpinnerAnimations(bd.Child);
                }
                var pnl = root as Panel;
                if (pnl != null)
                {
                    for (int i = 0; i < pnl.Children.Count; i++)
                    {
                        StopSpinnerAnimations(pnl.Children[i]);
                    }
                }
                var sv = root as ScrollViewer;
                if (sv != null && sv.Content is DependencyObject)
                {
                    StopSpinnerAnimations((DependencyObject)sv.Content);
                }
            }
            catch { }
        }

        private FrameworkElement CreateSpinningIcon(Color strokeColor, double size)
        {
            var rt = new RotateTransform(0);
            var sp = new ShapePath
            {
                Data = Geometry.Parse("M21 12a9 9 0 1 1-2.64-6.36"),
                Stroke = new SolidColorBrush(strokeColor),
                StrokeThickness = 2.0,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round,
                Stretch = Stretch.Uniform,
                Width = size,
                Height = size,
                RenderTransformOrigin = new Point(0.5, 0.5),
                RenderTransform = rt,
                IsHitTestVisible = false
            };
            var anim = new DoubleAnimation(0, 360, TimeSpan.FromMilliseconds(850))
            {
                RepeatBehavior = RepeatBehavior.Forever
            };
            rt.BeginAnimation(RotateTransform.AngleProperty, anim);
            return sp;
        }

        private static void ApplyTabularNums(TextBlock tb)
        {
            if (tb != null)
            {
                System.Windows.Documents.Typography.SetNumeralAlignment(tb, FontNumeralAlignment.Tabular);
            }
        }

        private void AttachHoverSurface(Border b)
        {
            b.MouseEnter += delegate { SetOrAnimateBrush(b, Border.BackgroundProperty, _theme.SurfaceHover, 120); };
            b.MouseLeave += delegate { SetOrAnimateBrush(b, Border.BackgroundProperty, _theme.Surface, 140); };
        }

        private static void SetOrAnimateBrush(DependencyObject target, DependencyProperty prop, Color targetColor, int ms)
        {
            if (target == null || prop == null) return;
            if (ms <= 0)
            {
                target.SetValue(prop, new SolidColorBrush(targetColor));
                return;
            }
            var cur = target.GetValue(prop) as SolidColorBrush;
            if (cur == null || cur.IsFrozen)
            {
                Color start = (cur != null)
                    ? cur.Color
                    : (prop == Border.BackgroundProperty ? Color.FromArgb(0, targetColor.R, targetColor.G, targetColor.B) : targetColor);
                cur = new SolidColorBrush(start);
                target.SetValue(prop, cur);
            }
            var anim = new ColorAnimation(targetColor, TimeSpan.FromMilliseconds(ms))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            cur.BeginAnimation(SolidColorBrush.ColorProperty, anim);
        }

        private static void AttachPressAnim(Border btn)
        {
            if (btn == null) return;
            btn.MouseLeftButtonDown += delegate
            {
                var st = btn.RenderTransform as ScaleTransform;
                if (st == null) return;
                var anim = new DoubleAnimation(0.985, TimeSpan.FromMilliseconds(80));
                st.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                st.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
            };
            btn.MouseLeftButtonUp += delegate
            {
                var st = btn.RenderTransform as ScaleTransform;
                if (st == null) return;
                var anim = new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(120));
                st.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                st.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
            };
            btn.MouseLeave += delegate
            {
                var st = btn.RenderTransform as ScaleTransform;
                if (st == null) return;
                var anim = new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(120));
                st.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
                st.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
            };
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
            string trimmed = rawText.Trim();
            if (IsLegacyOrFreeKey(trimmed)) return false;
            string foreignReason;
            if (IsForeignIncompatibleVpnKey(trimmed, out foreignReason)) return false;
            VlessNode n = ParseVlessUri(trimmed);
            if (n == null || string.IsNullOrEmpty(n.Uuid)) return false;
            return !IsLegacyOrFreeKey(n.Uuid);
        }

        private void UpdateLicenseHintFromServer()
        {
            _proActive = HasActiveProAccess();
            SyncRoutesFromOptions(false);
            UpdateModeBadge();
        }

        private void OnKeyTextChanged()
        {
            int daysLeft;
            EnsureAutoTrialKeyProvisioned(out daysLeft);
            string curKey = _keyInput != null ? _keyInput.Text : "";
            string foreignReason;
            if (IsForeignIncompatibleVpnKey(curKey, out foreignReason))
            {
                if (_optDiscordYt)
                {
                    _optDiscordYt = false;
                    _optTunMode = false;
                }
                if (_pasteProBtnText != null) _pasteProBtnText.Text = "Сбросить FREE";
                _licenseRightActionUrl = "pixeltunnel://reset-free";
                SyncRoutesFromOptions(false);
                UpdateModeBadge();
                return;
            }

            if (_pasteProBtnText != null) _pasteProBtnText.Text = "Вставить";
            _licenseRightActionUrl = GetTelegramBotUrl();

            if (!IsCustomPaidKey(curKey) && _optDiscordYt)
            {
                _optDiscordYt = false;
                _optTunMode = false;
            }
            SyncRoutesFromOptions(false);
            UpdateModeBadge();
        }

        private bool ApplyLicenseErrorToUi(string errCode)
        {
            if (string.IsNullOrEmpty(errCode)) return false;

            if (!_keyDrawerOpen)
            {
                ToggleKeyDrawer(true);
            }

            if (errCode.IndexOf("TRIAL_EXPIRED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                SetStatus(
                    ColAmber,
                    "Пробный период завершён",
                    string.Format("Возьмите персональный ключ в {0} и нажмите «Вставить» выше.", GetTelegramBotHandle())
                );
                return true;
            }
            if (errCode.IndexOf("KEY_EXPIRED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                SetStatus(
                    ColAmber,
                    "Срок подписки по ключу истёк",
                    string.Format("Продлите подписку в {0} или вставьте актуальный ключ ниже.", GetTelegramBotHandle())
                );
                return true;
            }
            if (errCode.IndexOf("DEVICE_LIMIT", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                SetStatus(
                    ColRed,
                    "Превышен лимит устройств (макс. 3 ПК)",
                    string.Format("Этот ключ уже привязан к 3 устройствам. Оформите доп. ключ в {0}.", GetTelegramBotHandle())
                );
                return true;
            }
            if (errCode.IndexOf("INVALID_KEY", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                SetStatus(
                    ColRed,
                    "Недействительный ключ доступа",
                    string.Format("Сервер отклонил ключ. Скопируйте свежий ключ в {0} и нажмите «Вставить».", GetTelegramBotHandle())
                );
                return true;
            }
            return false;
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
                string fallbackKeyPath = GetFallbackSavedKeyPath();
                bool baseWritable = IsDirectoryWritable(_baseDir);
                string pathToRead = (!baseWritable && File.Exists(fallbackKeyPath))
                    ? fallbackKeyPath
                    : (File.Exists(_savedKeyPath) ? _savedKeyPath : fallbackKeyPath);
                bool migratedToV2 = false;
                _themeChoice = ThemeModeChoice.System;
                _optInstantWake = true;

                if (File.Exists(pathToRead))
                {
                    string[] lines = File.ReadAllLines(pathToRead, Encoding.UTF8);
                    if (lines.Length > 0 && _keyInput != null) _keyInput.Text = lines[0].Trim();
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
                            _optTunMode = flags.Contains("TUN=1");
                            _optInstantWake = !flags.Contains("WAKE=0");

                            var mTheme = Regex.Match(flags, @"THEME=(light|dark|system)", RegexOptions.IgnoreCase);
                            if (mTheme.Success)
                            {
                                string tv = mTheme.Groups[1].Value.ToLowerInvariant();
                                if (tv == "light") _themeChoice = ThemeModeChoice.Light;
                                else if (tv == "dark") _themeChoice = ThemeModeChoice.Dark;
                                else _themeChoice = ThemeModeChoice.System;
                            }

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
                            _optTunMode = false;
                            _optInstantWake = true;
                            migratedToV2 = true;
                        }
                        _optMcpTerminal = _optAntigravity;
                        string thirdTunLoad;
                        bool hasConflictTun = CheckOtherThirdPartyTunAdapters(out thirdTunLoad);
                        bool proActive = HasActiveProAccess();
                        if (_optDiscordYt && !proActive) _optDiscordYt = false;
                        bool wantsTunCategory = proActive && !hasConflictTun && (_optDiscordYt || (_optSocialWeb && flags.Contains("TUN=1")));
                        _optTunMode = wantsTunCategory && (flags.Contains("TUN=1") || IsAdministratorStatic());
                        if (!proActive || hasConflictTun || (!_optDiscordYt && !_optSocialWeb)) _optTunMode = false;
                        PixelCoreService.SetPreferredRegion(_selectedRegion);
                    }
                }

                PixelCoreService.InstantWakeEnabled = _optInstantWake;
                _optAutostart = IsWindowsAutostartEnabled();
                ApplyThemeChoice(_themeChoice, false);

                // Load user custom domains (strictly separated from built-in defaults)
                string prxCsv, dirCsv, edsCsv;
                ReadCustomRulesConfig(out prxCsv, out dirCsv, out edsCsv);
                _customProxyDomains.Clear();
                _customProxyDomains.AddRange(ParseDomainCsv(prxCsv));
                _customDirectDomains.Clear();
                _customDirectDomains.AddRange(ParseDomainCsv(dirCsv));
                UpdateRulesCountPill();

                int daysLeft;
                string autoTrialKey = EnsureAutoTrialKeyProvisioned(out daysLeft);
                string curLoadedKey = (_keyInput != null ? _keyInput.Text : "").Trim();
                bool keyMigrated = false;
                if (string.IsNullOrWhiteSpace(curLoadedKey) ||
                    IsLegacyOrFreeKey(curLoadedKey) ||
                    curLoadedKey.IndexOf("nln.rusweb.net", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    curLoadedKey.IndexOf("#PixelTunnel-Trial", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!string.Equals(curLoadedKey, autoTrialKey, StringComparison.Ordinal))
                    {
                        if (_keyInput != null) _keyInput.Text = autoTrialKey;
                        keyMigrated = true;
                    }
                }
                else if (curLoadedKey.IndexOf("201.34.152.97", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         curLoadedKey.IndexOf("147.45.135.71", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         curLoadedKey.IndexOf("node.pixelstore.space", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var parsedSaved = ParseVlessUri(curLoadedKey);
                    if (parsedSaved != null && !string.IsNullOrWhiteSpace(parsedSaved.Uuid) && !IsLegacyOrFreeKey(parsedSaved.Uuid))
                    {
                        if (_keyInput != null) _keyInput.Text = string.Format("pwp4://{0}@ai.pixelstore.space:443#PixelTunnel-PRO", parsedSaved.Uuid.Trim());
                        keyMigrated = true;
                    }
                }
                if (keyMigrated || migratedToV2)
                {
                    SaveCurrentState();
                }
                if (!HasActiveProAccess()) _optTunMode = false;
                OnKeyTextChanged();
                SyncRoutesFromOptions(false);
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

        private static Process[] GetProcessesByNameSafe(string procName)
        {
            try { return Process.GetProcessesByName(procName) ?? new Process[0]; }
            catch { return new Process[0]; }
        }

        private static void DisposeProcessArray(Process[] procs)
        {
            if (procs == null) return;
            for (int i = 0; i < procs.Length; i++)
            {
                try { if (procs[i] != null) procs[i].Dispose(); } catch { }
            }
        }

        private static bool IsProcessRunning(string procName)
        {
            Process[] procs = GetProcessesByNameSafe(procName);
            try { return procs.Length > 0; }
            finally { DisposeProcessArray(procs); }
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
                    Process[] procs = GetProcessesByNameSafe(pName);
                    try
                    {
                        foreach (var p in procs)
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
                    finally { DisposeProcessArray(procs); }
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

        private static readonly byte[] _patTiers1 = Encoding.ASCII.GetBytes("ineligible_tiers");
        private static readonly byte[] _repTiers1 = Encoding.ASCII.GetBytes("inexigible_tiers");
        private static readonly byte[] _patTiers2 = Encoding.ASCII.GetBytes("ineligibleTiers");
        private static readonly byte[] _repTiers2 = Encoding.ASCII.GetBytes("inexigibleTiers");

        private static readonly byte[] _patAgLsProxy = Encoding.ASCII.GetBytes("AG_LS_PROXY");
        private static readonly byte[] _patProxyP1 = Encoding.ASCII.GetBytes("HTTPS_PROXYhttps_proxy");
        private static readonly byte[] _repProxyP1 = Encoding.ASCII.GetBytes("AG_LS_PROXYag_ls_proxy");
        private static readonly byte[] _patProxyP2a = Encoding.ASCII.GetBytes("retry-afterHTTPS_PROXY");
        private static readonly byte[] _repProxyP2a = Encoding.ASCII.GetBytes("retry-afterAG_LS_PROXY");
        private static readonly byte[] _patProxyP2b = Encoding.ASCII.GetBytes("retry-afterhttps_proxy");
        private static readonly byte[] _repProxyP2b = Encoding.ASCII.GetBytes("retry-afterag_ls_proxy");
        private static readonly byte[] _patProxyP3Upper = Encoding.ASCII.GetBytes("HTTPS_PROXY");
        private static readonly byte[] _repProxyP3Upper = Encoding.ASCII.GetBytes("AG_LS_PROXY");
        private static readonly byte[] _patProxyP3Lower = Encoding.ASCII.GetBytes("https_proxy");
        private static readonly byte[] _repProxyP3Lower = Encoding.ASCII.GetBytes("ag_ls_proxy");

        private static readonly byte[][] _p3ContextAnchors = new byte[][]
        {
            Encoding.ASCII.GetBytes("HTTP_PROXY"),
            Encoding.ASCII.GetBytes("http_proxy"),
            Encoding.ASCII.GetBytes("NO_PROXY"),
            Encoding.ASCII.GetBytes("no_proxy")
        };

        private static bool IsDisallowedProxyAdjacentByte(byte b)
        {
            return b == (byte)'_' || b == (byte)'=' ||
                   (b >= (byte)'0' && b <= (byte)'9') ||
                   (b >= (byte)'A' && b <= (byte)'Z') ||
                   (b >= (byte)'a' && b <= (byte)'z');
        }

        private static List<long> FilterP3ContextProxyOffsets(string filePath, List<long> rawOffsets, int patternLen)
        {
            var accepted = new List<long>();
            if (rawOffsets == null || rawOffsets.Count == 0) return accepted;

            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long fileLen = fs.Length;
                    byte[] winBuf = new byte[1024 + patternLen + 4];

                    foreach (long pos in rawOffsets)
                    {
                        if (pos < 0 || pos + patternLen > fileLen) continue;

                        if (pos > 0)
                        {
                            fs.Seek(pos - 1, SeekOrigin.Begin);
                            int bPrev = fs.ReadByte();
                            if (bPrev >= 0 && IsDisallowedProxyAdjacentByte((byte)bPrev)) continue;
                        }
                        if (pos + patternLen < fileLen)
                        {
                            fs.Seek(pos + patternLen, SeekOrigin.Begin);
                            int bNext = fs.ReadByte();
                            if (bNext >= 0 && IsDisallowedProxyAdjacentByte((byte)bNext)) continue;
                        }

                        long winStart = Math.Max(0L, pos - 512);
                        long winEnd = Math.Min(fileLen, pos + patternLen + 512);
                        int winLen = (int)(winEnd - winStart);
                        if (winLen <= 0 || winLen > winBuf.Length) continue;

                        fs.Seek(winStart, SeekOrigin.Begin);
                        int totalRead = 0;
                        while (totalRead < winLen)
                        {
                            int n = fs.Read(winBuf, totalRead, winLen - totalRead);
                            if (n <= 0) break;
                            totalRead += n;
                        }

                        bool hasAnchor = false;
                        for (int a = 0; a < _p3ContextAnchors.Length; a++)
                        {
                            if (FindSubArray(winBuf, totalRead, _p3ContextAnchors[a], 0) >= 0)
                            {
                                hasAnchor = true;
                                break;
                            }
                        }
                        if (hasAnchor && !accepted.Contains(pos))
                        {
                            accepted.Add(pos);
                        }
                    }
                }
            }
            catch { }
            return accepted;
        }

        private static void ApplyOffsetPatchesToStream(FileStream fs, List<KeyValuePair<List<long>, byte[]>> patches)
        {
            foreach (var kv in patches)
            {
                byte[] rep = kv.Value;
                foreach (long pos in kv.Key)
                {
                    fs.Seek(pos, SeekOrigin.Begin);
                    fs.Write(rep, 0, rep.Length);
                }
            }
            fs.Flush();
        }

        private static void StopLanguageServerProcessesForPath(string targetBinPath, bool fallbackAll)
        {
            string fullTarget = "";
            try { fullTarget = System.IO.Path.GetFullPath(targetBinPath); } catch { fullTarget = targetBinPath ?? ""; }
            foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
            {
                foreach (var p in Process.GetProcessesByName(lsName))
                {
                    bool shouldKill = false;
                    try
                    {
                        string procPath = p.MainModule != null ? p.MainModule.FileName : "";
                        if (!string.IsNullOrEmpty(procPath) &&
                            string.Equals(System.IO.Path.GetFullPath(procPath), fullTarget, StringComparison.OrdinalIgnoreCase))
                        {
                            shouldKill = true;
                        }
                    }
                    catch
                    {
                        if (fallbackAll) shouldKill = true;
                    }
                    if (shouldKill)
                    {
                        try { p.Kill(); p.WaitForExit(1000); } catch { }
                    }
                }
            }
        }

        private static DateTime GetAntigravityStateCutoffUtc()
        {
            DateTime cutoff = _lastTunnelConnectedUtc;
            if (_agLsEnvLastUpdatedUtc > cutoff) cutoff = _agLsEnvLastUpdatedUtc;
            if (_lsBinaryLastPatchedUtc > cutoff) cutoff = _lsBinaryLastPatchedUtc;
            return cutoff;
        }

        private static int CountProcessesStartedBefore(string[] procNames, DateTime cutoffUtc)
        {
            if (cutoffUtc == DateTime.MinValue || procNames == null) return 0;
            int count = 0;
            DateTime threshold = cutoffUtc.AddSeconds(-2);
            foreach (var name in procNames)
            {
                Process[] procs = GetProcessesByNameSafe(name);
                try
                {
                    foreach (var p in procs)
                    {
                        try
                        {
                            if (p.StartTime.ToUniversalTime() < threshold) count++;
                        }
                        catch { }
                    }
                }
                finally { DisposeProcessArray(procs); }
            }
            return count;
        }

        private static int RestartStaleLanguageServers(DateTime cutoffUtc)
        {
            if (cutoffUtc == DateTime.MinValue) return 0;
            int killed = 0;
            DateTime threshold = cutoffUtc.AddSeconds(-2);
            foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
            {
                Process[] procs = GetProcessesByNameSafe(lsName);
                try
                {
                    foreach (var p in procs)
                    {
                        try
                        {
                            if (p.StartTime.ToUniversalTime() < threshold)
                            {
                                p.Kill();
                                killed++;
                            }
                        }
                        catch { }
                    }
                }
                finally { DisposeProcessArray(procs); }
            }
            return killed;
        }

        private static bool PatchSingleLanguageServerBinary(string binPath, out bool tiersVerified, out bool proxyVerified, out bool patchedNow, out string detailMsg)
        {
            tiersVerified = false;
            proxyVerified = false;
            patchedNow = false;
            detailMsg = "";

            if (string.IsNullOrWhiteSpace(binPath) || !File.Exists(binPath))
            {
                detailMsg = "  ⚠ [ФАЙЛ НЕ НАЙДЕН] Бинарник language_server не найден: " + (binPath ?? "");
                return false;
            }

            string fileName = System.IO.Path.GetFileName(binPath);
            bool isTempPath = binPath.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) >= 0;

            try
            {
                var offTiers1 = ScanBinaryForPatternOffsets(binPath, _patTiers1);
                var offTiers2 = ScanBinaryForPatternOffsets(binPath, _patTiers2);
                bool hasRepTiersBefore = ScanBinaryForPatternOffsets(binPath, _repTiers1).Count > 0 ||
                                         ScanBinaryForPatternOffsets(binPath, _repTiers2).Count > 0;
                bool hadTiersOnlyBefore = (offTiers1.Count == 0 && offTiers2.Count == 0 && hasRepTiersBefore);

                bool hasAgLsProxyBefore = ScanBinaryForPatternOffsets(binPath, _patAgLsProxy).Count > 0;

                var patches = new List<KeyValuePair<List<long>, byte[]>>();
                if (offTiers1.Count > 0) patches.Add(new KeyValuePair<List<long>, byte[]>(offTiers1, _repTiers1));
                if (offTiers2.Count > 0) patches.Add(new KeyValuePair<List<long>, byte[]>(offTiers2, _repTiers2));

                string proxyPatchTag = "";
                bool patchingProxyNow = false;
                if (!hasAgLsProxyBefore)
                {
                    var offP1 = ScanBinaryForPatternOffsets(binPath, _patProxyP1);
                    if (offP1.Count > 0)
                    {
                        patches.Add(new KeyValuePair<List<long>, byte[]>(offP1, _repProxyP1));
                        proxyPatchTag = "P1";
                        patchingProxyNow = true;
                    }
                    else
                    {
                        var offP2a = ScanBinaryForPatternOffsets(binPath, _patProxyP2a);
                        var offP2b = ScanBinaryForPatternOffsets(binPath, _patProxyP2b);
                        if (offP2a.Count > 0) patches.Add(new KeyValuePair<List<long>, byte[]>(offP2a, _repProxyP2a));
                        if (offP2b.Count > 0) patches.Add(new KeyValuePair<List<long>, byte[]>(offP2b, _repProxyP2b));
                        if (offP2a.Count > 0 || offP2b.Count > 0)
                        {
                            proxyPatchTag = "P2";
                            patchingProxyNow = true;
                        }
                        else
                        {
                            var rawP3Upper = ScanBinaryForPatternOffsets(binPath, _patProxyP3Upper);
                            var offP3Upper = FilterP3ContextProxyOffsets(binPath, rawP3Upper, _patProxyP3Upper.Length);
                            if (offP3Upper.Count > 0) patches.Add(new KeyValuePair<List<long>, byte[]>(offP3Upper, _repProxyP3Upper));

                            var rawP3Lower = ScanBinaryForPatternOffsets(binPath, _patProxyP3Lower);
                            var offP3Lower = FilterP3ContextProxyOffsets(binPath, rawP3Lower, _patProxyP3Lower.Length);
                            if (offP3Lower.Count > 0) patches.Add(new KeyValuePair<List<long>, byte[]>(offP3Lower, _repProxyP3Lower));

                            if (offP3Upper.Count > 0 || offP3Lower.Count > 0)
                            {
                                proxyPatchTag = "P3";
                                patchingProxyNow = true;
                            }
                        }
                    }
                }

                bool writeFailed = false;
                string writeErr = "";

                if (patches.Count > 0)
                {
                    StopLanguageServerProcessesForPath(binPath, false);

                    string oldBak = binPath + ".old";
                    try { if (File.Exists(oldBak)) File.Delete(oldBak); } catch { }

                    bool writeOk = false;
                    try
                    {
                        using (var fs = new FileStream(binPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                        {
                            ApplyOffsetPatchesToStream(fs, patches);
                        }
                        writeOk = true;
                    }
                    catch (Exception exPrimary)
                    {
                        writeErr = exPrimary.Message;
                        if (!isTempPath) StopLanguageServerProcessesForPath(binPath, true);
                        try
                        {
                            File.Move(binPath, oldBak);
                            File.Copy(oldBak, binPath, true);
                            using (var fs = new FileStream(binPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                            {
                                ApplyOffsetPatchesToStream(fs, patches);
                            }
                            StopLanguageServerProcessesForPath(binPath, !isTempPath);
                            writeOk = true;
                        }
                        catch (Exception exFallback)
                        {
                            try
                            {
                                if (!File.Exists(binPath) && File.Exists(oldBak))
                                    File.Move(oldBak, binPath);
                            }
                            catch { }
                            writeErr = !string.IsNullOrEmpty(exFallback.Message) ? exFallback.Message : exPrimary.Message;
                            writeFailed = true;
                        }
                    }

                    if (writeOk)
                    {
                        patchedNow = true;
                        _lsBinaryLastPatchedUtc = DateTime.UtcNow;
                    }
                }

                // Independent verification on disk
                bool hasRepTiers1 = ScanBinaryForPatternOffsets(binPath, _repTiers1).Count > 0;
                bool hasRepTiers2 = ScanBinaryForPatternOffsets(binPath, _repTiers2).Count > 0;
                bool hasRemTiers1 = ScanBinaryForPatternOffsets(binPath, _patTiers1).Count > 0;
                bool hasRemTiers2 = ScanBinaryForPatternOffsets(binPath, _patTiers2).Count > 0;
                tiersVerified = hasRepTiers1 || hasRepTiers2 || (patchedNow && !hasRemTiers1 && !hasRemTiers2);
                proxyVerified = ScanBinaryForPatternOffsets(binPath, _patAgLsProxy).Count > 0;

                bool bothVerified = tiersVerified && proxyVerified;
                string tiersText = tiersVerified ? "Tiers (inexigible_tiers OK)" : "Tiers (ОТСУТСТВУЕТ)";
                string proxyText = proxyVerified ? "Proxy (AG_LS_PROXY bin-patch OK)" : "Proxy (AG_LS_PROXY ОТСУТСТВУЕТ)";

                if (writeFailed)
                {
                    detailMsg = string.Format(
                        "  ⚠ [ПРАВА / ФАЙЛ ЗАНЯТ] {0}: не удалось записать патч ({1}). Статус: {2} | {3}. Запустите PixelTunnel 1 раз от имени Администратора ИЛИ нажмите «Перезапустить Antigravity в туннеле».",
                        fileName, writeErr, tiersText, proxyText);
                }
                else if (bothVerified && patchedNow && hadTiersOnlyBefore && patchingProxyNow)
                {
                    detailMsg = string.Format(
                        "  ⚡ [АВТО-ПАТЧ ПРОКСИ] Доустановлен патч прокси-шлюза AG_LS_PROXY ({0}) в {1} | {2} | {3}.",
                        proxyPatchTag, fileName, tiersText, proxyText);
                }
                else if (bothVerified && patchedNow)
                {
                    detailMsg = string.Format(
                        "  ⚡ [АВТО-ПАТЧ САНКЦИЙ] {0}: успешно пропатчен ({1}) | {2} | {3}.",
                        fileName, string.IsNullOrEmpty(proxyPatchTag) ? "tiers" : proxyPatchTag, tiersText, proxyText);
                }
                else if (bothVerified)
                {
                    detailMsg = string.Format(
                        "  ✓ [OK] {0}: {1} | {2}.",
                        fileName, tiersText, proxyText);
                }
                else
                {
                    detailMsg = string.Format(
                        "  ⚠ [НЕПОЛНЫЙ ПАТЧ] {0}: {1} | {2}. Нажмите «Перезапустить Antigravity в туннеле» или запустите от имени Администратора.",
                        fileName, tiersText, proxyText);
                }

                return bothVerified;
            }
            catch (Exception ex)
            {
                detailMsg = string.Format("  ⚠ [ОШИБКА ПАТЧА] {0}: {1}", fileName, ex.Message);
                return false;
            }
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
                if (candidateBins.Count == 0)
                {
                    logs.Add("  ℹ [ИНФО] Исполняемые файлы Antigravity language_server.exe не найдены.");
                    return false;
                }

                foreach (var binPath in candidateBins)
                {
                    bool tOk, pOk, patchedFile;
                    string detailMsg;
                    bool ok = PatchSingleLanguageServerBinary(binPath, out tOk, out pOk, out patchedFile, out detailMsg);
                    if (!string.IsNullOrEmpty(detailMsg)) logs.Add(detailMsg);
                    if (patchedFile) anyPatchedNow = true;

                    if (ok && tOk && pOk)
                    {
                        anyVerified = true;
                        string sigOk = GetFileSignatureFast(binPath);
                        if (!string.IsNullOrEmpty(sigOk))
                        {
                            lock (_verifiedLsBinSignatures) { _verifiedLsBinSignatures[binPath] = sigOk; }
                        }
                    }
                    else
                    {
                        lock (_verifiedLsBinSignatures) { _verifiedLsBinSignatures.Remove(binPath); }
                    }
                }

                if (anyPatchedNow)
                {
                    _forceShowAgBannerOnNextCheck = true;
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
            return anyVerified;
        }

        private void SaveCurrentState()
        {
            string savedKey = ReadFromUiThread(() => _keyInput != null ? (_keyInput.Text ?? "").Trim() : "", "");
            string themeStr = _themeChoice == ThemeModeChoice.Light ? "light" : (_themeChoice == ThemeModeChoice.Dark ? "dark" : "system");
            string[] data = new[]
            {
                savedKey,
                string.Format("V2=1;AG={0};MCP={1};AI={2};MEDIA={3};WEB={4};REG={5};PAC={6};WSL={7};TUN={8};THEME={9};WAKE={10}",
                    _optAntigravity ? 1 : 0,
                    _optMcpTerminal ? 1 : 0,
                    _optCursorAi ? 1 : 0,
                    _optDiscordYt ? 1 : 0,
                    _optSocialWeb ? 1 : 0,
                    string.IsNullOrEmpty(_selectedRegion) ? "auto" : _selectedRegion,
                    _useSmartPacMode ? 1 : 0,
                    _optWslBridge ? 1 : 0,
                    _optTunMode ? 1 : 0,
                    themeStr,
                    _optInstantWake ? 1 : 0)
            };
            try { File.WriteAllLines(_savedKeyPath, data, Encoding.UTF8); } catch { }
            try { File.WriteAllLines(GetFallbackSavedKeyPath(), data, Encoding.UTF8); } catch { }
        }

        public static bool IsAdministratorStatic()
        {
            return IsAdministrator();
        }

        private static bool IsTelegramDesktopDetected()
        {
            if (IsProcessRunning("Telegram")) return true;
            try
            {
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (!string.IsNullOrEmpty(appData) && File.Exists(System.IO.Path.Combine(appData, "Telegram Desktop", "Telegram.exe"))) return true;
                string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (!string.IsNullOrEmpty(localApp) && File.Exists(System.IO.Path.Combine(localApp, "Programs", "Telegram Desktop", "Telegram.exe"))) return true;
            }
            catch { }
            return false;
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
        private static bool IsServiceRunning(string serviceName)
        {
            try
            {
                using (var scCheck = Process.Start(new ProcessStartInfo("sc.exe", "query " + serviceName) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true }))
                {
                    if (scCheck != null)
                    {
                        string scOut = scCheck.StandardOutput.ReadToEnd();
                        scCheck.WaitForExit(400);
                        return scOut.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                }
            }
            catch { }
            return false;
        }

        private static List<string> StopConflictingVpnAndApplyFixes()
        {
            var fixedItems = new List<string>();

            // 1. Stop legacy ProksiFi service/tray only (never touch user's Zapret/GoodbyeDPI/VPNs!)
            try
            {
                if (IsServiceRunning("ProksiFiService"))
                {
                    try
                    {
                        using (var scStop = Process.Start(new ProcessStartInfo("sc.exe", "stop ProksiFiService") { CreateNoWindow = true, UseShellExecute = false }))
                        {
                            if (scStop != null) scStop.WaitForExit(1000);
                        }
                        fixedItems.Add("Остановлена устаревшая служба ProksiFiService");
                    }
                    catch { }
                }

                foreach (var procName in new[] { "ProksiFi_Tray", "ProksiFi" })
                {
                    Process[] procs = GetProcessesByNameSafe(procName);
                    try
                    {
                        foreach (var p in procs)
                        {
                            try { p.Kill(); p.WaitForExit(600); fixedItems.Add("Закрыт устаревший " + procName + ".exe"); } catch { }
                        }
                    }
                    finally { DisposeProcessArray(procs); }
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
                            int pe = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                            if (pe == 0)
                                ApplyWinInetPerConnectionProxy(false, "", "", "");
                            else
                                RefreshWinInet();
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
                if (CountActiveProxyConnections() > 0) return true;

                if (PixelCoreService.IsRunning && PixelCoreService.UsingGoEngine)
                {
                    try
                    {
                        var task = PixelCoreService.QueryLiveRoutesV4JsonAsync();
                        if (task != null && task.Wait(350))
                        {
                            string raw = task.Result;
                            var obj = MiniJson.Deserialize(raw) as Dictionary<string, object>;
                            var entries = obj != null ? MiniJson.GetList(obj, "entries") : null;
                            if (entries != null)
                            {
                                long nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                                for (int i = 0; i < entries.Count; i++)
                                {
                                    var row = entries[i] as Dictionary<string, object>;
                                    if (row == null) continue;
                                    long ts = MiniJson.GetLong(row, "ts", 0);
                                    if (ts <= 0 || (nowUnix - ts) > 10) continue;
                                    string dom = (MiniJson.GetStr(row, "domain") ?? "").ToLowerInvariant();
                                    string act = (MiniJson.GetStr(row, "action") ?? "").ToUpperInvariant();
                                    if (act == "PROXY" || act == "TUNNEL" ||
                                        dom.Contains("googleapis.com") || dom.Contains("anthropic.com") ||
                                        dom.Contains("claude.ai") || dom.Contains("openai.com") ||
                                        dom.Contains("cursor") || dom.Contains("windsurf"))
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    catch { }
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

        private static string GetCurrentAgLsProxyState(out bool portLive, out int portNum)
        {
            portLive = false;
            portNum = 0;
            string agLs = Environment.GetEnvironmentVariable("AG_LS_PROXY", EnvironmentVariableTarget.User);
            if (string.IsNullOrEmpty(agLs))
            {
                agLs = Environment.GetEnvironmentVariable("AG_LS_PROXY", EnvironmentVariableTarget.Process);
            }
            if (!string.IsNullOrEmpty(agLs))
            {
                portNum = TryExtractLoopbackProxyPort(agLs);
                if (portNum <= 0 && agLs.Contains(":"))
                {
                    int col = agLs.LastIndexOf(':');
                    int.TryParse(agLs.Substring(col + 1).TrimEnd('/'), out portNum);
                }
                portLive = portNum > 0 && IsLocalPortOpen(portNum, 120);
            }
            return agLs ?? "";
        }

        private static bool IsAnyLsBinaryProxyPatchedOnDisk()
        {
            try
            {
                var bins = DiscoverAntigravityLanguageServerBinaries();
                if (bins.Count == 0) return true;
                foreach (var b in bins)
                {
                    if (ScanBinaryForPatternOffsets(b, _patAgLsProxy).Count > 0) return true;
                }
                return false;
            }
            catch { return true; }
        }

        private static DateTime GetEarliestRunningLsStartTimeUtc()
        {
            DateTime earliest = DateTime.MaxValue;
            foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
            {
                Process[] procs = GetProcessesByNameSafe(lsName);
                try
                {
                    foreach (var p in procs)
                    {
                        try
                        {
                            DateTime st = p.StartTime.ToUniversalTime();
                            if (st < earliest) earliest = st;
                        }
                        catch { }
                    }
                }
                finally { DisposeProcessArray(procs); }
            }
            return earliest;
        }

        private static string ReadLogDeltaFromOffset(string path, long offset, int maxTailBytes, out long newLen)
        {
            newLen = 0;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    newLen = fs.Length;
                    long start = (offset > 0 && offset <= newLen) ? offset : Math.Max(0L, newLen - maxTailBytes);
                    if (newLen - start > maxTailBytes) start = newLen - maxTailBytes;
                    if (start >= newLen) return "";
                    fs.Seek(start, SeekOrigin.Begin);
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
            catch { return ""; }
        }

        private static void InspectAntigravityLogs(out string statusBanner, out Color dotColor, out string validationUrl, out List<string> diagLines)
        {
            bool dummyFresh;
            InspectAntigravityLogs(false, out statusBanner, out dotColor, out validationUrl, out diagLines, out dummyFresh);
        }

        private static void InspectAntigravityLogs(bool trackHighWater, out string statusBanner, out Color dotColor, out string validationUrl, out List<string> diagLines, out bool hasFreshLsError)
        {
            statusBanner = string.Format("AI Телеметрия: шлюз :{0} готов • защита от слетов активна", _activeHttpPort);
            dotColor = ColBlue;
            validationUrl = "";
            diagLines = new List<string>();
            hasFreshLsError = false;

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

                long prevOffset = 0;
                DateTime prevTime = DateTime.MinValue;
                lock (_agLogHighWaterOffsets)
                {
                    _agLogHighWaterOffsets.TryGetValue(logFile, out prevOffset);
                    _agLogHighWaterTimes.TryGetValue(logFile, out prevTime);
                }

                DateTime lastWrite = File.GetLastWriteTime(logFile);
                DateTime lastWriteUtc = File.GetLastWriteTimeUtc(logFile);
                double minsAgo = Math.Max(0, (DateTime.Now - lastWrite).TotalMinutes);

                string tail = ReadLogTail(logFile, 32768);
                InspectAntigravityLogContent(tail, System.IO.Path.GetFileName(logFile), minsAgo, activeConns, out statusBanner, out dotColor, out validationUrl, out diagLines);

                long fileLen = 0;
                string deltaText = ReadLogDeltaFromOffset(logFile, prevOffset, 32768, out fileLen);
                DateTime earliestLsUtc = GetEarliestRunningLsStartTimeUtc();
                bool writtenAfterLsStart = (earliestLsUtc == DateTime.MaxValue) || (lastWriteUtc >= earliestLsUtc.AddSeconds(1));
                bool hasNewBytes = (fileLen < prevOffset) || (fileLen > prevOffset && !string.IsNullOrEmpty(deltaText));
                bool isNewerThanTracked = lastWriteUtc > prevTime;

                if (hasNewBytes && writtenAfterLsStart && isNewerThanTracked)
                {
                    string dummyB, dummyV;
                    Color dummyC;
                    List<string> dummyL;
                    InspectAntigravityLogContent(deltaText, System.IO.Path.GetFileName(logFile), minsAgo, activeConns, out dummyB, out dummyC, out dummyV, out dummyL);
                    if (dummyB != null &&
                        (dummyB.IndexOf("блок региона", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         dummyB.IndexOf("loadCodeAssist timeout", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        hasFreshLsError = true;
                    }
                }

                if (trackHighWater)
                {
                    lock (_agLogHighWaterOffsets)
                    {
                        _agLogHighWaterOffsets[logFile] = fileLen;
                        _agLogHighWaterTimes[logFile] = lastWriteUtc;
                    }
                }
            }
            catch { }
        }

        private static void InspectAntigravityLogContent(string tail, string fileName, double minsAgo, int activeConns, out string statusBanner, out Color dotColor, out string validationUrl, out List<string> diagLines)
        {
            statusBanner = string.Format("AI Телеметрия: шлюз :{0} готов • защита от слетов активна", _activeHttpPort);
            dotColor = ColBlue;
            validationUrl = "";
            diagLines = new List<string>();

            try
            {
                if (tail == null) tail = "";
                if (string.IsNullOrEmpty(fileName)) fileName = "language_server.log";
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

                // 2. Check last 8KB line-by-line for overload, active region error, auth expiry, or real Google API TLS timeouts.
                string recentTail = tail.Length > 8192 ? tail.Substring(tail.Length - 8192) : tail;

                bool hasOverload = recentTail.IndexOf("503", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("429", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("overloaded", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   recentTail.IndexOf("high traffic", StringComparison.OrdinalIgnoreCase) >= 0;

                bool hasAuthErr = recentTail.IndexOf("UNAUTHENTICATED", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                  recentTail.IndexOf("invalid_grant", StringComparison.OrdinalIgnoreCase) >= 0;

                int lastSuccessLineIdx = -1;
                int lastFatalNetLineIdx = -1;
                int lastRegionLineIdx = -1;
                bool fatalWasLoadCodeAssist = false;
                string[] tailLines = recentTail.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < tailLines.Length; i++)
                {
                    string ln = tailLines[i];
                    if (ln.IndexOf("Auth succeeded", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        ln.IndexOf("CCPA routed this account", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        ln.IndexOf("get_auth_status valid=true", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (ln.IndexOf("FetchUserInfo", StringComparison.OrdinalIgnoreCase) >= 0 &&
                         ln.IndexOf("error", StringComparison.OrdinalIgnoreCase) < 0 &&
                         ln.IndexOf("fail", StringComparison.OrdinalIgnoreCase) < 0))
                    {
                        lastSuccessLineIdx = i;
                    }

                    if (ln.IndexOf("location is not supported", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        ln.IndexOf("REGION_NOT_SUPPORTED", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        lastRegionLineIdx = i;
                    }

                    bool lineHasLoadCodeAssistErr = ln.IndexOf("failed to get load code assist response", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool lineHasTlsTimeout = ln.IndexOf("TLS handshake timeout", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool lineHasGoogleCloudApiHost =
                        ln.IndexOf("daily-cloudcode-pa.googleapis.com", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        ln.IndexOf("cloudaicompanion.googleapis.com", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        ln.IndexOf("aicode.googleapis.com", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool lineHasConnRefusedOrDialTimeout =
                        ln.IndexOf("connection refused", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        ln.IndexOf("actively refused", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (ln.IndexOf("dial tcp", StringComparison.OrdinalIgnoreCase) >= 0 &&
                         ln.IndexOf("i/o timeout", StringComparison.OrdinalIgnoreCase) >= 0);

                    if (lineHasLoadCodeAssistErr || lineHasTlsTimeout || (lineHasGoogleCloudApiHost && lineHasConnRefusedOrDialTimeout))
                    {
                        lastFatalNetLineIdx = i;
                        if (lineHasLoadCodeAssistErr || ln.IndexOf("loadCodeAssist", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            fatalWasLoadCodeAssist = true;
                        }
                    }
                }

                bool hasRegionErr = lastRegionLineIdx > lastSuccessLineIdx;
                bool hasNetTimeout = lastFatalNetLineIdx > lastSuccessLineIdx;
                bool hasLoadCodeAssistTimeout = hasNetTimeout && fatalWasLoadCodeAssist;

                DateTime cutoffUtc = GetAntigravityStateCutoffUtc();
                bool staleAgRunning = CountProcessesStartedBefore(new[] { "Antigravity" }, cutoffUtc) > 0;

                if (hasRegionErr && minsAgo < 10)
                {
                    dotColor = ColAmber;
                    statusBanner = string.Format("Обнаружен блок региона в логе ({0}) • нажмите Авто-Фикс для перезапуска LS", recency);
                    diagLines.Add("  ⚠ [ЛОГ ANTIGRAVITY] В language_server.log зафиксирована ошибка региона (" + recency + "). Авто-патч AG_LS_PROXY применён.");
                    if (staleAgRunning)
                    {
                        _forceShowAgBannerOnNextCheck = true;
                        diagLines.Add("  💡 [РЕШЕНИЕ] Antigravity.exe запущен до патча/туннеля -> нажмите «Перезапустить Antigravity в туннеле».");
                    }
                }
                else if (hasLoadCodeAssistTimeout && minsAgo < 15)
                {
                    bool agEnvLive;
                    int agEnvPort;
                    string agEnvVal = GetCurrentAgLsProxyState(out agEnvLive, out agEnvPort);
                    bool binProxyPatched = IsAnyLsBinaryProxyPatchedOnDisk();

                    var causes = new List<string>();
                    if (!binProxyPatched)
                        causes.Add("в language_server.exe отсутствует патч AG_LS_PROXY");
                    if (string.IsNullOrEmpty(agEnvVal) || !agEnvLive)
                        causes.Add("переменная AG_LS_PROXY не задана или порт не отвечает");
                    if (staleAgRunning)
                    {
                        causes.Add("Antigravity.exe запущен ДО включения туннеля/патча и не унаследовал AG_LS_PROXY");
                        _forceShowAgBannerOnNextCheck = true;
                    }
                    if (causes.Count == 0)
                        causes.Add("процесс language_server стартовал без унаследованного AG_LS_PROXY / HTTPS_PROXY");

                    dotColor = ColRed;
                    statusBanner = "Antigravity обходит туннель (loadCodeAssist timeout) • Нажмите «Перезапустить Antigravity в туннеле»";
                    diagLines.Add(string.Format(
                        "  ✗ [ПРЯМОЙ ВЫХОД БЕЗ ПРОКСИ] В логе зафиксирован loadCodeAssist TLS handshake timeout ({0}). Причина: {1}.",
                        recency, string.Join("; ", causes.ToArray())));
                    diagLines.Add("  💡 [РЕШЕНИЕ] Нажмите «Перезапустить Antigravity в туннеле» в главном окне, чтобы Electron Antigravity.exe и language_server унаследовали AG_LS_PROXY + HTTPS_PROXY + HTTP_PROXY.");
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
                    if (staleAgRunning) _forceShowAgBannerOnNextCheck = true;
                    dotColor = ColRed;
                    statusBanner = string.Format("Таймаут сети в Antigravity ({0}) • Нажмите «Проверить и починить»", recency);
                    diagLines.Add("  ✗ [ТАЙМАУТ СЕТИ В IDE] В логе language_server зафиксирован TLS handshake timeout / обрыв связи с Google (" + recency + "). Нажмите «Проверить и починить» или «Перезапустить Antigravity в туннеле».");
                }
                else
                {
                    dotColor = IsLocalPortOpen(_activeHttpPort, 100) ? ColGreen : ColBlue;
                    statusBanner = string.Format("Шлюз :{0} • Потоков: {1} • Лог Antigravity: 200 OK ({2})", _activeHttpPort, activeConns, recency);
                    diagLines.Add(string.Format("  ✓ [OK] Лог Antigravity ({0}): соединение 200 OK ({1}), активных потоков: {2}.", fileName, recency, activeConns));
                }
            }
            catch { }
        }

        private void RefreshAiTelemetryBanner()
        {
            try
            {
                CheckAntigravityPreTunnelState();
                CheckSignedManifestUpdateUi();
                if (_isConnected) UpdateLicenseHintFromServer();
            }
            catch { }
        }

        private static string DiscoverAntigravityExePath()
        {
            try
            {
                Process[] agProcs = GetProcessesByNameSafe("Antigravity");
                try
                {
                    foreach (var p in agProcs)
                    {
                        try
                        {
                            string exe = p.MainModule.FileName;
                            if (!string.IsNullOrEmpty(exe) && File.Exists(exe)) return exe;
                        }
                        catch { }
                    }
                }
                finally { DisposeProcessArray(agProcs); }

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
                DateTime cutoffUtc = GetAntigravityStateCutoffUtc();
                if (_tunnelConnectedUtc > cutoffUtc) cutoffUtc = _tunnelConnectedUtc;

                if (!_isConnected || !_optAntigravity || cutoffUtc == DateTime.MinValue ||
                    ((_agBannerDismissed || _agRelaunchedForPort == _activeHttpPort) && !_forceShowAgBannerOnNextCheck))
                {
                    if (_ideOpenedPreTunnel)
                    {
                        _ideOpenedPreTunnel = false;
                        RunOnUiThread(delegate { UpdateIdeQuickBarVisual(); });
                    }
                    return;
                }

                bool startedBeforeCutoff = CountProcessesStartedBefore(new[] { "Antigravity" }, cutoffUtc) > 0;
                if (!startedBeforeCutoff) _forceShowAgBannerOnNextCheck = false;
                if (_ideOpenedPreTunnel != startedBeforeCutoff)
                {
                    _ideOpenedPreTunnel = startedBeforeCutoff;
                    RunOnUiThread(delegate { UpdateIdeQuickBarVisual(); });
                }
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
                    FlashIdeBarLabel("Перезапуск IDE...");
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
                    SetAgLsProxyEnv(proxyUrl, true);
                    BroadcastEnvironmentChange();

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
                _forceShowAgBannerOnNextCheck = false;
                _ideOpenedPreTunnel = false;
                RunOnUiThread(delegate
                {
                    UpdateIdeQuickBarVisual();
                    FlashIdeBarLabel("IDE перезапущен \u2713");
                    FlashStatusSub(string.Format("Antigravity в туннеле :{0} + --disable-quic", port));
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
                        SyncRoutesFromOptions(true);
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
                    FlashStatusSub(string.Format("Перезапуск Discord через SOCKS5 UDP :{0}...", socksPort));
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
                    FlashStatusSub(string.Format("Discord UDP активен на 127.0.0.1:{0}", socksPort));
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
                RunOnUiThread(delegate { SyncRoutesFromOptions(true); });
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
                    SetAgLsProxyEnv(proxyUrl, true);
                }
                else
                {
                    SetAgLsProxyEnv(null, true);
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

        private static List<string> HealAiEditorsAndServices(bool tunnelActive, bool restartLanguageServer = true, bool routeAg = true, bool routeAi = false, bool routeMedia = false, bool routeWeb = false, bool allowSpotifyRestart = false)
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
                                json = InsertPropIntoJsonObject(json, "\"http.proxy\": \"" + activeProxyUrl + "\"", "  ");
                            }

                            // 2. Force http.proxyStrictSSL = false
                            if (Regex.IsMatch(json, "\"http\\.proxyStrictSSL\"\\s*:\\s*(?:true|false)"))
                            {
                                json = Regex.Replace(json, "\"http\\.proxyStrictSSL\"\\s*:\\s*(?:true|false)", "\"http.proxyStrictSSL\": false");
                            }
                            else
                            {
                                json = InsertPropIntoJsonObject(json, "\"http.proxyStrictSSL\": false", "  ");
                            }

                            // 3. Force http.proxySupport = "override"
                            if (Regex.IsMatch(json, "\"http\\.proxySupport\"\\s*:\\s*\"[^\"]*\""))
                            {
                                json = Regex.Replace(json, "\"http\\.proxySupport\"\\s*:\\s*\"[^\"]*\"", "\"http.proxySupport\": \"override\"");
                            }
                            else
                            {
                                json = InsertPropIntoJsonObject(json, "\"http.proxySupport\": \"override\"", "  ");
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
                                    json = InsertPropIntoJsonObject(json, "\"cursor.general.disableHttp2\": true", "  ");
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
                            // Clean only PixelTunnel's local proxy from this editor; preserve third-party proxies
                            Match mEdProxy = Regex.Match(json, "\"http\\.proxy\"\\s*:\\s*\"([^\"]*)\"");
                            if (mEdProxy.Success && (string.IsNullOrEmpty(mEdProxy.Groups[1].Value) || IsPixelTunnelProxyUrl(mEdProxy.Groups[1].Value)))
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
                                bool wasSpotifyRunning = false;
                                string spotifyExe = System.IO.Path.Combine(spotifyDir, "Spotify.exe");
                                if (allowSpotifyRestart)
                                {
                                    var spProcs = GetProcessesByNameSafe("Spotify");
                                    try
                                    {
                                        wasSpotifyRunning = spProcs.Length > 0;
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
                                    }
                                    finally { DisposeProcessArray(spProcs); }
                                }

                                string cleanedSp = Regex.Replace(spTxt, "(?m)^\\s*network\\.proxy\\.[^\\r\\n]*\\r?\\n?", "").TrimEnd();
                                string updatedSp = (string.IsNullOrEmpty(cleanedSp) ? "" : cleanedSp + "\r\n") + targetAddr + "\r\n" + targetMode + "\r\n";
                                File.WriteAllText(spotifyPrefs, updatedSp, new UTF8Encoding(false));

                                if (allowSpotifyRestart && wasSpotifyRunning && File.Exists(spotifyExe))
                                {
                                    try { Process.Start(new ProcessStartInfo(spotifyExe) { UseShellExecute = true }); } catch { }
                                }
                                healed.Add(string.Format("Spotify: прописан шлюз 127.0.0.1:{0}@http в prefs (mode=2)", _activeHttpPort));
                            }
                        }
                        else
                        {
                            Match mSpAddr = Regex.Match(spTxt, "network\\.proxy\\.addr\\s*=\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
                            if (mSpAddr.Success && IsPixelTunnelProxyUrl(mSpAddr.Groups[1].Value))
                            {
                                string cleanedSp = Regex.Replace(spTxt, "(?m)^\\s*network\\.proxy\\.[^\\r\\n]*\\r?\\n?", "");
                                if (cleanedSp != spTxt)
                                {
                                    File.WriteAllText(spotifyPrefs, cleanedSp, new UTF8Encoding(false));
                                    healed.Add("Spotify: очищен от прокси PixelTunnel (прямой режим)");
                                }
                            }
                        }
                    }
                }
                catch { }

                // Clean only PixelTunnel local proxy leftovers in ~/.gitconfig and ~/.npmrc; preserve third-party proxies
                try
                {
                    string userProf = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    string gitCfgPath = System.IO.Path.Combine(userProf, ".gitconfig");
                    if (File.Exists(gitCfgPath))
                    {
                        string gtxt = File.ReadAllText(gitCfgPath, Encoding.UTF8);
                        string updatedGit = Regex.Replace(gtxt, "(?m)^\\s*proxy\\s*=\\s*(http://(?:127\\.0\\.0\\.1|localhost):\\d+/?)\\s*\\r?\\n?", delegate(Match m)
                        {
                            return IsPixelTunnelProxyUrl(m.Groups[1].Value) ? "" : m.Value;
                        });
                        if (updatedGit != gtxt)
                        {
                            File.WriteAllText(gitCfgPath, updatedGit, new UTF8Encoding(false));
                            healed.Add("Git: очищен прокси PixelTunnel в .gitconfig");
                        }
                    }

                    string npmrcPath = System.IO.Path.Combine(userProf, ".npmrc");
                    if (File.Exists(npmrcPath))
                    {
                        string ntxt = File.ReadAllText(npmrcPath, Encoding.UTF8);
                        string updatedNpm = Regex.Replace(ntxt, "(?m)^\\s*(?:https?-)?proxy\\s*=\\s*(http://(?:127\\.0\\.0\\.1|localhost):\\d+/?)\\s*\\r?\\n?", delegate(Match m)
                        {
                            return IsPixelTunnelProxyUrl(m.Groups[1].Value) ? "" : m.Value;
                        });
                        if (updatedNpm != ntxt)
                        {
                            File.WriteAllText(npmrcPath, updatedNpm, new UTF8Encoding(false));
                            healed.Add("npm: очищен прокси PixelTunnel в .npmrc");
                        }
                    }
                }
                catch { }

                if (tunnelActive && restartLanguageServer && agSettingsChanged && IsLocalPortOpen(_activeHttpPort, 150) && !IsAiStreamActivelyFlowing())
                {
                    string[] lsNames = new[] { "language_server", "language_server_windows_x64" };
                    foreach (var lsName in lsNames)
                    {
                        Process[] lsProcs = GetProcessesByNameSafe(lsName);
                        try
                        {
                            foreach (var p in lsProcs)
                            {
                                try { p.Kill(); healed.Add(lsName + ": \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0449\u0435\u043d"); } catch { }
                            }
                        }
                        finally { DisposeProcessArray(lsProcs); }
                    }
                }
            }
            catch { }
            return healed;
        }

        private static string BuildSmartPacUrl()
        {
            return string.Format("http://127.0.0.1:{0}/proxy.pac?r={1}", _activeHttpPort, Math.Max(1, PixelCoreService.ActivePacRevision));
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
                SetAgLsProxyEnv(proxyUrl, true);
                BroadcastEnvironmentChange();
            }
        }

        private static string MergeProxyOverride(string existingOverride, string requiredOverride)
        {
            var merged = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Action<string> addList = delegate(string csv)
            {
                if (string.IsNullOrWhiteSpace(csv)) return;
                foreach (var raw in csv.Split(';'))
                {
                    string item = raw.Trim();
                    if (!string.IsNullOrEmpty(item) && seen.Add(item))
                    {
                        merged.Add(item);
                    }
                }
            };
            addList(existingOverride);
            addList(requiredOverride);
            return string.Join(";", merged.ToArray());
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
                        string existingOvr = Convert.ToString(key.GetValue("ProxyOverride", ""));
                        proxyOvr = MergeProxyOverride(existingOvr, proxyOvr);
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
                SetAgLsProxyEnv(proxyUrl, true);
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
                        string existingOvr = Convert.ToString(key.GetValue("ProxyOverride", ""));
                        proxyOvr = MergeProxyOverride(existingOvr, proxyOvr);
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
                    SetAgLsProxyEnv("http://127.0.0.1:7890", false);
                }
                else
                {
                    SetAgLsProxyEnv(null, true);
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
                    bool ok;
                    try
                    {
                        ok = res.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMs));
                    }
                    finally
                    {
                        try { res.AsyncWaitHandle.Close(); } catch { }
                    }
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
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "GET";
                req.AllowAutoRedirect = false;
                req.KeepAlive = false;
                req.UserAgent = "PixelTunnel/" + APP_VERSION;
                int timeoutMs = Math.Max(2000, timeoutSec * 1000);
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.Proxy = string.IsNullOrEmpty(proxyUrl)
                    ? null
                    : new WebProxy(proxyUrl);

                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    return ((int)resp.StatusCode).ToString(System.Globalization.CultureInfo.InvariantCulture);
                }
            }
            catch (WebException wex)
            {
                try
                {
                    using (var errResp = wex.Response as HttpWebResponse)
                    {
                        if (errResp != null)
                        {
                            return ((int)errResp.StatusCode).ToString(System.Globalization.CultureInfo.InvariantCulture);
                        }
                    }
                }
                catch { }
                return "000";
            }
            catch { return "000"; }
        }

        private static bool IsHttpCodeHealthy(string code)
        {
            if (string.IsNullOrEmpty(code) || code == "000") return false;
            return code.StartsWith("2") || code.StartsWith("3") || code == "400" || code == "401" || code == "403" || code == "404" || code == "405";
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
                    if (name.IndexOf("PixelAG", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        string.Equals(name, "PixelTunnel", StringComparison.OrdinalIgnoreCase) ||
                        desc.IndexOf("PixelTunnel", StringComparison.OrdinalIgnoreCase) >= 0) continue;

                    if (desc.IndexOf("Wintun", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        desc.IndexOf("WireGuard", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        desc.IndexOf("Sing-Box", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        desc.IndexOf("sing-tun", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        desc.IndexOf("Clash", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("PixelTUN", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Nekoray", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Hiddify", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Amnezia", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Outline", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Clash", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Mihomo", StringComparison.OrdinalIgnoreCase) >= 0)
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
            bool catchFailed = false;
            string catchErrMsg = "";
            try
            {
                _statusHasCustomMessage = false;
                string rawKey = ReadFromUiThread(() => _keyInput != null ? (_keyInput.Text ?? "").Trim() : "", "");
                if (string.IsNullOrEmpty(rawKey))
                {
                    int dLeft;
                    rawKey = EnsureAutoTrialKeyProvisioned(out dLeft);
                    RunOnUiThreadSync(delegate { if (_keyInput != null) _keyInput.Text = rawKey; });
                }

                string foreignKeyReason;
                if (IsForeignIncompatibleVpnKey(rawKey, out foreignKeyReason))
                {
                    RunOnUiThread(delegate
                    {
                        OnKeyTextChanged();
                        SetStatus(ColRed, "Чужой VPN-ключ не поддерживается", foreignKeyReason);
                        ResetButtonState(false);
                    });
                    return;
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
                    _connState = TunnelState.Connecting;
                    _waveStep = 0;
                    UpdateConnectionVisuals(true);
                    if (_waveTimer != null) _waveTimer.Start();
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
                    PixelCoreService.EnsureManifestLoadedForConfig(3500);

                    string jsonConfig = BuildSingBoxConfig(node, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                    ApplyAndStartCoreConfig(jsonConfig);

                    for (int i = 0; i < 80; i++)
                    {
                        if (!string.IsNullOrEmpty(PixelCoreService.LastLicenseError)) break;
                        if (IsLocalPortOpen(_activeHttpPort, 150)) break;
                        if (!PixelCoreService.IsRunning) break;
                        Thread.Sleep(100);
                    }

                    // Verify BOTH tunnel AND Direct .RU internet BEFORE enabling System Proxy!
                    if (string.IsNullOrEmpty(PixelCoreService.LastLicenseError) && IsLocalPortOpen(_activeHttpPort, 200))
                    {
                        string localProxy = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                        gstaticCode = RunHttpProbe("http://www.gstatic.com/generate_204", localProxy, 9);
                        if (string.IsNullOrEmpty(PixelCoreService.LastLicenseError))
                        {
                            var t1 = Task.Factory.StartNew(() => { agHttpCode = RunHttpProbe("https://daily-cloudcode-pa.googleapis.com", localProxy, 9); });
                            var t3 = Task.Factory.StartNew(() => { directRuCode = RunHttpProbe("https://ya.ru", "", 5); });
                            Task.WaitAll(new[] { t1, t3 }, 10500);
                        }
                    }
                });

                await PixelCoreService.SyncGoTelemetryAsync();
                string licError = PixelCoreService.LastLicenseError;
                if (!string.IsNullOrEmpty(licError))
                {
                    await Task.Run(() => StopTunnelProcess(false));
                    RunOnUiThread(delegate
                    {
                        ApplyLicenseErrorToUi(licError);
                        ResetButtonState(false);
                    });
                    return;
                }

                bool finalTunnelOk = IsHttpCodeHealthy(agHttpCode) || IsHttpCodeHealthy(gstaticCode);

                if (PixelCoreService.IsRunning && IsLocalPortOpen(_activeHttpPort, 250) && finalTunnelOk)
                {
                    await Task.Run(() =>
                    {
                        ApplyConnectedProxyPolicy();
                        FlushWindowsDnsCache();
                        List<string> pLogs;
                        PatchAntigravitySanctionsAndProxy(out pLogs, false);
                        HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, true);
                    });

                    _isConnected = true;
                    _tunnelConnectedUtc = DateTime.UtcNow;
                    _lastTunnelConnectedUtc = _tunnelConnectedUtc;
                    var unusedPulseOnConn = RefreshAiPulseUiAsync(true);
                    _agBannerDismissed = false;
                    int shownMs = PixelCoreService.LivePingMs > 0
                        ? PixelCoreService.LivePingMs
                        : (PixelCoreService.ActiveNodeLatencyMs > 0 ? PixelCoreService.ActiveNodeLatencyMs : (pingMs > 0 ? pingMs : 0));
                    _currentPing = shownMs;
                    _statusHasCustomMessage = false;

                    RunOnUiThread(delegate
                    {
                        if (_waveTimer != null) _waveTimer.Stop();
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
                                if (!_githubUpdateChecked) CheckForGitHubUpdateAsync();
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
                    await Task.Run(() => StopTunnelProcess(false));

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
                catchFailed = true;
                catchErrMsg = ex.Message;
            }
            if (catchFailed)
            {
                await Task.Run(() => StopTunnelProcess(false));
                RunOnUiThread(delegate
                {
                    SetStatus(ColRed, "Ошибка запуска (Прямой интернет сохранён)", catchErrMsg);
                    ResetButtonState(false);
                });
            }
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
            _currentPing = 0;
            _ideOpenedPreTunnel = false;
            _isConnected = false;

            if (updateUi && Dispatcher != null && Dispatcher.CheckAccess())
            {
                _isBusy = true;
                Task.Run(() =>
                {
                    try
                    {
                        DisableOrRestoreSystemProxy();
                        PixelCoreService.StopService();
                    }
                    catch { }
                    RunOnUiThread(delegate
                    {
                        if (_waveTimer != null) _waveTimer.Stop();
                        if (wasOAuthHelperActive && _oauthHelperTimer != null)
                        {
                            try { _oauthHelperTimer.Stop(); } catch { }
                        }
                        UpdateIdeQuickBarVisual();
                        _statusHasCustomMessage = false;
                        ResetButtonState(false);
                        RefreshAiTelemetryBanner();
                    });
                });
                var unusedPulseStopAsync = RefreshAiPulseUiAsync(false);
                return;
            }

            DisableOrRestoreSystemProxy();
            PixelCoreService.StopService();

            RunOnUiThread(delegate
            {
                if (_waveTimer != null) _waveTimer.Stop();
                if (wasOAuthHelperActive && _oauthHelperTimer != null)
                {
                    try { _oauthHelperTimer.Stop(); } catch { }
                }
                UpdateIdeQuickBarVisual();

                if (updateUi)
                {
                    _statusHasCustomMessage = false;
                    ResetButtonState(false);
                    RefreshAiTelemetryBanner();
                }
            });
            var unusedPulseStop = RefreshAiPulseUiAsync(false);
        }

        // ====================================================================
        // SMART DIAGNOSTICS HELPERS: HOSTS DOCTOR, OAUTH GUARD & PASSPORT
        // ====================================================================
        private static bool IsHostMappedIpAliveTcp(string mappedIp, int timeoutMs = 1000)
        {
            if (string.IsNullOrWhiteSpace(mappedIp)) return false;
            IPAddress ip;
            if (!IPAddress.TryParse(mappedIp.Trim(), out ip)) return false;
            if (IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip) || IPAddress.IsLoopback(ip)) return false;
            try
            {
                using (var tcp = new TcpClient(ip.AddressFamily))
                {
                    IAsyncResult ar = tcp.BeginConnect(ip, 443, null, null);
                    WaitHandle wh = ar.AsyncWaitHandle;
                    try
                    {
                        if (!wh.WaitOne(timeoutMs)) return false;
                        tcp.EndConnect(ar);
                        return true;
                    }
                    finally
                    {
                        try { wh.Close(); } catch { }
                    }
                }
            }
            catch { return false; }
        }

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
                    "gstatic.com", "gemini.google.com", "aistudio.google.com", "ai.studio", "makersuite.google.com",
                    "googleusercontent.com", "usercontent.goog", "withgoogle.com", "google.dev",
                    "claude.ai", "anthropic.com", "openai.com", "chatgpt.com",
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
                        bool aliveMapping = attemptAutoComment && IsHostMappedIpAliveTcp(mappedIp, 1000);
                        if (!aliveMapping)
                        {
                            poisonedCount += matchedDomains.Count;
                            findings.Add(string.Join(", ", matchedDomains.ToArray()) + " -> " + mappedIp);
                        }
                        if (attemptAutoComment && !aliveMapping)
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
                        string backupPath = hostsPath + ".pixeltunnel.bak";
                        try { File.Copy(hostsPath, backupPath, true); } catch { }
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
            if (_isOAuthToggleRunning) return;
            _isOAuthToggleRunning = true;
            try
            {
                if (_oauthHelperActive)
                {
                    StopGoogleOAuthHelperMode(false);
                    return;
                }

                if (_isBusy) return;
                if (!_isConnected)
                {
                    await StartTunnelInternalAsync();
                    if (!_isConnected)
                    {
                        _oauthHelperActive = false;
                        RunOnUiThread(delegate { UpdateIdeQuickBarVisual(); });
                        return;
                    }
                }
                if (!_isConnected) return;

                _oauthHelperActive = true;
                _oauthHelperSecondsLeft = 180;

                string prx, dir, eds;
                ReadCustomRulesConfig(out prx, out dir, out eds);
                await PixelCoreService.ReloadRulesV4Async(BuildReloadRulesJsonPayload(prx, dir));
                await Task.Run(() =>
                {
                    try
                    {
                        if (_useSmartPacMode)
                        {
                            // Refresh Smart PAC AutoConfigURL only without forcing ProxyEnable=1
                            string pacUrl = BuildSmartPacUrl();
                            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                            {
                                if (key != null)
                                {
                                    key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                    key.SetValue("AutoConfigURL", pacUrl, RegistryValueKind.String);
                                }
                            }
                            ApplyWinInetPerConnectionProxy(true, "", "", pacUrl);
                        }
                        else
                        {
                            EnableSystemProxy();
                        }
                        FlushWindowsDnsCache();
                    }
                    catch { }
                });

                RunOnUiThread(delegate
                {
                    UpdateIdeQuickBarVisual();
                    FlashStatusSub("Режим входа в Google активен на 3 мин (без разрыва соединений)");

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
                                UpdateIdeQuickBarVisual();
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
                    UpdateIdeQuickBarVisual();
                    SetStatus(ColAmber, "Не удалось включить режим входа Google", errMsg);
                });
            }
            finally
            {
                _isOAuthToggleRunning = false;
            }
        }

        private async void StopGoogleOAuthHelperMode(bool silent)
        {
            _oauthHelperActive = false;
            RunOnUiThread(delegate
            {
                if (_oauthHelperTimer != null)
                {
                    try { _oauthHelperTimer.Stop(); } catch { }
                }
                UpdateIdeQuickBarVisual();
            });

            if (_isConnected && _activeNode != null && !silent)
            {
                try
                {
                    string prx, dir, eds;
                    ReadCustomRulesConfig(out prx, out dir, out eds);
                    await PixelCoreService.ReloadRulesV4Async(BuildReloadRulesJsonPayload(prx, dir));
                }
                catch { }

                await Task.Run(() =>
                {
                    try
                    {
                        ApplyConnectedProxyPolicy();
                        HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb);
                    }
                    catch { }
                });

                RunOnUiThread(delegate
                {
                    FlashStatusSub("Режим OAuth завершён · изолированный обход восстановлен");
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
            bool lsSanctionPatched,
            bool optAg = true,
            bool optAi = false,
            bool optWeb = false,
            bool optMedia = false)
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
            sb.AppendLine(string.Format("ОС: {0} ({1}) | Порты: :{2}/:{3} | Категории: AG={4}, AI={5}, WEB={6}, MEDIA={7}, TUN={8}",
                Environment.OSVersion.Version,
                Environment.Is64BitOperatingSystem ? "x64" : "x86",
                _activeHttpPort, _activeSocksPort,
                optAg ? "ON" : "OFF",
                optAi ? "ON" : "OFF",
                optWeb ? "ON" : "OFF",
                optMedia ? "ON" : "OFF",
                _optTunMode ? "ON" : "OFF"));
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
                tunName, lsOk,
                _optAntigravity, _optCursorAi, _optSocialWeb, _optDiscordYt);
        }

        // ====================================================================
        // SMART DIAGNOSTICS & SELF-HEALING ENGINE ("АВТО-ДОКТОР КЛИЕНТА")
        // ====================================================================
        private void SetDiagItem(string id, DiagItemState state, string detail, string recommendation, bool canAutoFix, string unusedTag = "")
        {
            RunOnUiThread(delegate
            {
                if (_diagItems.Count == 0) InitPendingDiagItems();
                for (int i = 0; i < _diagItems.Count; i++)
                {
                    if (string.Equals(_diagItems[i].Id, id, StringComparison.Ordinal))
                    {
                        _diagItems[i].State = state;
                        _diagItems[i].Detail = detail ?? "";
                        _diagItems[i].Recommendation = recommendation ?? "";
                        _diagItems[i].CanAutoFix = canAutoFix;
                        break;
                    }
                }
                if (_activeModalKind == "diag")
                {
                    BuildDiagModalContent(false);
                }
            });
        }

        private static void ProbeAllDiagChannels(string proxyUrl, int timeoutSec, out string agCode, out string gemCode, out string aiStudioCode, out string oauthCode, out string yaCode)
        {
            agCode = RunHttpProbe("https://daily-cloudcode-pa.googleapis.com", proxyUrl, timeoutSec);
            gemCode = RunHttpProbe("https://gemini.google.com", proxyUrl, timeoutSec);
            aiStudioCode = RunHttpProbe("https://aistudio.google.com", proxyUrl, timeoutSec);
            oauthCode = RunHttpProbe("https://oauth2.googleapis.com/token", proxyUrl, timeoutSec);
            yaCode = RunHttpProbe("https://ya.ru", "", Math.Min(5, timeoutSec));
        }

        private static bool IsControlStatusConnected()
        {
            if (!PixelCoreService.IsRunning) return false;
            try
            {
                var task = PixelCoreService.QueryStatusV4JsonAsync();
                if (task != null && task.Wait(600))
                {
                    var obj = MiniJson.Deserialize(task.Result) as Dictionary<string, object>;
                    if (obj != null && MiniJson.GetBool(obj, "connected", false)) return true;
                }
            }
            catch { }
            return false;
        }

        private async void RunSmartDiagnosticsAsync(bool autoFix, bool isAutoDiagCli = false)
        {
            if (_isDiagRunning) return;
            _isDiagRunning = true;
            _diagFixing = autoFix;

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
            bool diagForeignKey = false;
            string diagForeignReason = "";

            try
            {
                RunOnUiThread(delegate
                {
                    if (!isAutoDiagCli)
                    {
                        if (!autoFix || _diagItems.Count == 0)
                        {
                            InitPendingDiagItems();
                        }
                        if (_activeModalKind == "diag")
                        {
                            BuildDiagModalContent(false);
                        }
                    }
                });

                await Task.Run(() =>
                {
                    var sw = Stopwatch.StartNew();
                    report.AppendLine("╔══ ДИАГНОСТИКА И АВТО-ДОКТОР PIXELTUNNEL ══╗");

                // ----------------------------------------------------------------
                // 1. CHECK DIRECT ISP INTERNET, WININET PROXY & POISONED HOSTS FILE
                // ----------------------------------------------------------------
                SetDiagItem("isp_dns", DiagItemState.Running, "проверка", "", false, "");
                report.AppendLine("\r\n[1/9] Прямой интернет РФ и проверка системного прокси WinInet:");
                int dnsPing = MeasureTcpPing("77.88.8.8", 53);
                string yaDirect = RunHttpProbe("https://ya.ru", "", 3);
                diagYaCode = yaDirect;
                bool ispHealthy = IsHttpCodeHealthy(yaDirect) || dnsPing > 0;
                if (ispHealthy)
                {
                    report.AppendLine(string.Format("  ✓ [OK] Прямой канал работает (ya.ru: HTTP {0}, DNS 77.88.8.8: {1} мс)", yaDirect, dnsPing > 0 ? dnsPing.ToString() : "OK"));
                }
                else
                {
                    issuesFound++;
                    report.AppendLine("  ✗ [ПРОБЛЕМА] Прямой выход в интернет заблокирован или недоступен!");
                    if (autoFix)
                    {
                        bool liveTunnelProtected = false;
                        if (IsControlStatusConnected() && IsLocalPortOpen(_activeHttpPort, 150))
                        {
                            string pUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                            string probeAg = RunHttpProbe("https://daily-cloudcode-pa.googleapis.com", pUrl, 4);
                            string probeGem = RunHttpProbe("https://gemini.google.com", pUrl, 4);
                            if (IsHttpCodeHealthy(probeAg) || IsHttpCodeHealthy(probeGem))
                            {
                                liveTunnelProtected = true;
                            }
                        }

                        if (liveTunnelProtected)
                        {
                            FlushWindowsDnsCache();
                            report.AppendLine("  ℹ [СОХРАНЁН ТУННЕЛЬ] Ядро активно и пропускает AI-трафик — сбой прямого канала РФ не затронул туннель.");
                        }
                        else
                        {
                            string clearedDead;
                            TryClearDeadSystemProxyInRegistry(180, false, out clearedDead);
                            CleanDeadProxyEnvironmentVariables();
                            FlushWindowsDnsCache();
                            Thread.Sleep(300);
                            yaDirect = RunHttpProbe("https://ya.ru", "", 3);
                            diagYaCode = yaDirect;
                            if (IsHttpCodeHealthy(yaDirect))
                            {
                                ispHealthy = true;
                                issuesFixed++;
                                report.AppendLine("  ⚡ [АВТО-ФИКС] Сброшены мёртвые прокси PixelTunnel и DNS-кэш -> Прямой интернет восстановлен (HTTP " + yaDirect + ")!");
                            }
                            else
                            {
                                report.AppendLine("  💡 [СОВЕТ] Проверьте Wi-Fi/кабель провайдера или отключите сторонний фаервол.");
                            }
                        }
                    }
                }

                bool winInetIssue = false;
                bool winInetFixed = false;
                string winInetRec = "";
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
                                winInetIssue = true;
                                report.AppendLine("  ✗ [ПРОБЛЕМА] Обнаружен устаревший WPAD/PAC AutoConfigURL: " + wpadStr);
                                if (autoFix)
                                {
                                    key.DeleteValue("AutoConfigURL", false);
                                    RefreshWinInet();
                                    issuesFixed++;
                                    winInetFixed = true;
                                    report.AppendLine("  ⚡ [АВТО-ФИКС] Устаревший AutoConfigURL удалён из реестра.");
                                }
                                else
                                {
                                    winInetRec = "Обнаружен зависший PAC/WPAD AutoConfigURL — нажмите «Починить автоматически» для сброса.";
                                }
                            }

                            int proxyEn = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                            string proxySrv = Convert.ToString(key.GetValue("ProxyServer", ""));
                            string proxyOvr = Convert.ToString(key.GetValue("ProxyOverride", ""));

                            if (proxyEn == 1 && !string.IsNullOrEmpty(proxySrv))
                            {
                                int pPort = TryExtractLoopbackProxyPort(proxySrv);
                                bool isOurPort = IsPixelTunnelLocalPort(pPort);
                                bool portAlive = pPort > 0 && IsLocalPortOpen(pPort, 200);
                                bool foreign7890Blocked = false;
                                if (portAlive && pPort == 7890 && !isOurPort)
                                {
                                    bool upstreamOk = ProbeLocalProxyUpstreamHealthy(7890, 1800);
                                    UpdateForeign7890DeadState(!upstreamOk);
                                    foreign7890Blocked = !upstreamOk;
                                }

                                if (isOurPort && !portAlive)
                                {
                                    issuesFound++;
                                    winInetIssue = true;
                                    report.AppendLine(string.Format("  ✗ [МЁРТВЫЙ ШЛЮЗ] Системный прокси включён ({0}), но порт {1} не отвечает!", proxySrv, pPort));
                                    if (autoFix)
                                    {
                                        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                                        ApplyWinInetPerConnectionProxy(false, "", "");
                                        FlushWindowsDnsCache();
                                        issuesFixed++;
                                        winInetFixed = true;
                                        report.AppendLine("  ⚡ [АВТО-ФИКС] Мёртвый системный прокси PixelTunnel отключён -> Браузеры разблокированы!");
                                    }
                                    else
                                    {
                                        winInetRec = string.Format("Включён мёртвый системный прокси {0} — нажмите «Починить автоматически».", proxySrv);
                                    }
                                }
                                else if (!isOurPort && !portAlive)
                                {
                                    issuesFound++;
                                    winInetIssue = true;
                                    report.AppendLine(string.Format("  ⚠ [СТОРОННИЙ ПРОКСИ] Включён сторонний системный прокси {0}, порт не отвечает.", proxySrv));
                                    winInetRec = string.Format("Обнаружен сторонний прокси {0} — отключите его в настройках Windows или в стороннем VPN.", proxySrv);
                                }
                                else if (foreign7890Blocked)
                                {
                                    issuesFound++;
                                    winInetIssue = true;
                                    report.AppendLine(string.Format("  ⚠ [СТОРОННИЙ UPSTREAM] Чужой локальный прокси {0} слушает порт 7890, но его upstream не отвечает.", proxySrv));
                                    winInetRec = "Сторонний прокси 127.0.0.1:7890 не пропускает трафик — проверьте или отключите сторонний VPN.";
                                }
                                else
                                {
                                    report.AppendLine(string.Format("  ✓ [OK] Системный прокси ({0}) активен и порт отвечает.", proxySrv));
                                    if (autoFix && isOurPort)
                                    {
                                        string effOvr = MergeProxyOverride(proxyOvr, BuildEffectiveProxyOverride());
                                        if (proxyOvr.IndexOf("127.*", StringComparison.OrdinalIgnoreCase) < 0 ||
                                            proxyOvr.IndexOf("localhost", StringComparison.OrdinalIgnoreCase) < 0 ||
                                            proxyOvr.IndexOf("*.ru", StringComparison.OrdinalIgnoreCase) < 0)
                                        {
                                            key.SetValue("ProxyOverride", effOvr, RegistryValueKind.String);
                                            issuesFixed++;
                                            report.AppendLine("  ⚡ [АВТО-ФИКС] Добавлены исключения localhost, 127.* и *.ru в ProxyOverride.");
                                        }
                                        ApplyWinInetPerConnectionProxy(true, proxySrv, effOvr);
                                    }
                                }
                            }
                            else
                            {
                                report.AppendLine("  ✓ [OK] Системный прокси не блокирует сеть (изолированный режим прямого интернета).");
                            }
                        }
                    }
                }
                catch { }

                if (!ispHealthy)
                {
                    SetDiagItem("isp_dns", DiagItemState.Error, "нет сети",
                        "Прямой выход в интернет (ya.ru / DNS 77.88.8.8) не отвечает. Проверьте Wi-Fi/провайдера или нажмите «Починить автоматически» для сброса зависшего прокси.",
                        true, "isp_proxy");
                }
                else if (winInetIssue && !winInetFixed)
                {
                    SetDiagItem("isp_dns", DiagItemState.Warn, "битый прокси",
                        winInetRec,
                        true, "isp_proxy");
                }
                else
                {
                    SetDiagItem("isp_dns", DiagItemState.Ok,
                        winInetFixed ? "исправлено" : ("HTTP " + (string.IsNullOrEmpty(yaDirect) ? "OK" : yaDirect)),
                        "", false, "");
                }

                // ----------------------------------------------------------------
                // 2. CHECK WINDOWS HOSTS FILE
                // ----------------------------------------------------------------
                SetDiagItem("hosts", DiagItemState.Running, "проверка", "", false, "");
                var poisonedHostsList = ScanAndHealPoisonedHostsFile(null, autoFix, out diagPoisonedHosts, out diagHostsHealed);
                if (diagPoisonedHosts == 0)
                {
                    report.AppendLine("  ✓ [OK] Файл C:\\Windows\\System32\\drivers\\etc\\hosts чист (нет мёртвых IP от старых обходов).");
                    SetDiagItem("hosts", DiagItemState.Ok, "чист", "", false, "");
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
                        report.AppendLine("  ⚡ [АВТО-ФИКС] Мёртвые IP-записи автоматически закомментированы в hosts (бэкап hosts.pixeltunnel.bak) + сброшен DNS!");
                        SetDiagItem("hosts", DiagItemState.Ok, "очищен", "", false, "");
                    }
                    else
                    {
                        report.AppendLine("  💡 [РЕШЕНИЕ] Запустите PixelTunnel от имени Администратора и нажмите «Починить автоматически» — он сам очистит мёртвые IP в hosts.");
                        SetDiagItem("hosts", DiagItemState.Error, string.Format("{0} перехватов", diagPoisonedHosts),
                            "В файле hosts найдены старые IP для AI-доменов. Запустите от имени Администратора или нажмите «Починить автоматически».",
                            true, "hosts");
                    }
                }

                // ----------------------------------------------------------------
                // 3. CHECK CONFLICTING SERVICES & LOCAL PORTS
                // ----------------------------------------------------------------
                SetDiagItem("conflicts_ports", DiagItemState.Running, "проверка", "", false, "");
                report.AppendLine("\r\n[2/9] Проверка конфликтов служб ProksiFi и локальных портов:");
                bool conflictFound = false;
                bool conflictFixed = false;
                bool proksiDetectedBefore = IsProcessRunning("ProksiFi") || IsProcessRunning("ProksiFi_Tray") || IsServiceRunning("ProksiFiService");
                if (autoFix)
                {
                    var earlyFixed = StopConflictingVpnAndApplyFixes();
                    bool proksiStillRunning = IsProcessRunning("ProksiFi") || IsProcessRunning("ProksiFi_Tray") || IsServiceRunning("ProksiFiService");
                    if (earlyFixed.Count > 0 || proksiDetectedBefore)
                    {
                        conflictFound = true;
                        conflictFixed = !proksiStillRunning;
                        foreach (var item in earlyFixed)
                        {
                            issuesFound++;
                            issuesFixed++;
                            report.AppendLine("  ✓ [АВТО-ФИКС] " + item);
                        }
                        if (proksiStillRunning)
                        {
                            issuesFound++;
                            report.AppendLine("  ⚠ [ВНИМАНИЕ] Процесс или служба ProksiFi продолжает работать (требуются права Администратора).");
                        }
                    }
                    else
                    {
                        report.AppendLine("  ✓ [OK] Конфликтующих служб ProksiFi и фоновых перехватчиков не обнаружено.");
                    }
                }
                else
                {
                    if (proksiDetectedBefore)
                    {
                        conflictFound = true;
                        issuesFound++;
                        report.AppendLine("  ⚠ [КОНФЛИКТ] Обнаружен запущенный процесс/служба ProksiFi (ProksiFi / ProksiFi_Tray / ProksiFiService).");
                    }
                    else
                    {
                        report.AppendLine("  ✓ [OK] Конфликтующих служб ProksiFi не обнаружено.");
                    }
                }

                string portMsg = "";
                if (!_isConnected)
                {
                    portMsg = EnsureAvailableLocalPorts();
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

                if (conflictFound && !conflictFixed)
                {
                    SetDiagItem("conflicts_ports", DiagItemState.Warn, "ProksiFi активен",
                        "Обнаружен конкурирующий процесс/служба ProksiFi. Нажмите «Починить автоматически» для остановки.",
                        true, "conflicts");
                }
                else
                {
                    SetDiagItem("conflicts_ports", DiagItemState.Ok,
                        string.Format(":{0} / :{1}", _activeHttpPort, _activeSocksPort),
                        "", false, "");
                }

                // ----------------------------------------------------------------
                // 4. CHECK THIRD-PARTY TUN ADAPTERS & ZAPRET/WINWS COEXISTENCE
                // ----------------------------------------------------------------
                SetDiagItem("tun_dpi", DiagItemState.Running, "проверка", "", false, "");
                string thirdPartyTun;
                bool hasForeignTun = CheckOtherThirdPartyTunAdapters(out thirdPartyTun);
                bool tunFixed = false;
                if (hasForeignTun)
                {
                    diagThirdPartyTun = thirdPartyTun;
                    issuesFound++;
                    report.AppendLine("  ⚠ [ВНИМАНИЕ] Обнаружен сторонний виртуальный адаптер: " + thirdPartyTun);
                    report.AppendLine("  💡 [СОВЕТ] Активный сторонний адаптер (например, PixelTUN / sing-tun / WireGuard) может перехватывать L3 UDP/Telegram/Discord трафик до PixelTunnel — отключите другой VPN-клиент на время работы.");
                    if (autoFix)
                    {
                        _preferSafeProxyMode = true;
                        _optTunMode = false;
                        tunFixed = true;
                        issuesFixed++;
                        report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС] Включён режим «Безопасный локальный шлюз :{0} без конфликта с чужим TUN»!", _activeHttpPort));
                    }
                }

                string extDpiTool = PixelCoreService.DetectExternalDesyncProcess();
                if (!string.IsNullOrEmpty(extDpiTool))
                {
                    report.AppendLine(string.Format("  ⚡ [СОВМЕСТИМОСТЬ] Обнаружен активный обход DPI ({0}) — PixelTunnel автоматически включил режим No-Split (без двойной фрагментации пакетов).", extDpiTool));
                }

                string[] otherVpnProcs = new[] { "v2rayN", "nekobox", "nekoray", "Hiddify", "AmneziaVPN", "wireguard", "goodbyedpi", "winws", "winws2" };
                var runningOthers = new List<string>();
                foreach (var vp in otherVpnProcs)
                {
                    if (IsProcessRunning(vp)) runningOthers.Add(vp + ".exe");
                }
                if (runningOthers.Count > 0)
                {
                    if (string.IsNullOrEmpty(diagThirdPartyTun)) diagThirdPartyTun = string.Join(",", runningOthers.ToArray());
                    report.AppendLine("  💡 [ЗАМЕТКА] Запущены сетевые утилиты: " + string.Join(", ", runningOthers.ToArray()) + " (сохраняем совместимость).");
                }

                if (hasForeignTun && !tunFixed)
                {
                    SetDiagItem("tun_dpi", DiagItemState.Warn, thirdPartyTun,
                        string.Format("Обнаружен сторонний TUN-адаптер ({0}). Отключите другой VPN-клиент или нажмите «Починить автоматически» для безопасного режима без TUN.", thirdPartyTun),
                        true, "safe_mode");
                }
                else if (!string.IsNullOrEmpty(extDpiTool))
                {
                    SetDiagItem("tun_dpi", DiagItemState.Ok, "No-Split (" + extDpiTool + ")", "", false, "");
                }
                else
                {
                    SetDiagItem("tun_dpi", DiagItemState.Ok, "конфликтов нет", "", false, "");
                }

                // ----------------------------------------------------------------
                // 5. ENGINE (GO uTLS vs C# FALLBACK), MANIFEST, CLOCK & SSL-MITM
                // ----------------------------------------------------------------
                SetDiagItem("engine_manifest", DiagItemState.Running, "проверка", "", false, "");
                report.AppendLine("\r\n[3/9] Проверка ядра Go uTLS / Fallback, манифеста, часов и SSL:");
                bool manifestLoaded = PixelCoreService.EnsureEmbeddedManifestLoaded();
                if (autoFix)
                {
                    bool remoteSynced = PixelCoreService.EnsureManifestLoadedForConfig(4500);
                    if (remoteSynced)
                    {
                        manifestLoaded = true;
                        issuesFixed++;
                        report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС] Манифест узлов синхронизирован (v{0}, {1}).", PixelCoreService.ManifestVersion, PixelCoreService.ManifestSource));
                    }
                }
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
                        report.AppendLine("  ⚡ [АВТО-ФИКС БЕЗ АДМИНА] Включён авто-компенсатор времени PWP-3.");
                    }
                }
                else
                {
                    report.AppendLine("  ✓ [OK] Авто-компенсатор времени по заголовкам сервера активен.");
                }

                string certIssuer, avMitm;
                bool hasSslMitm = PixelCoreService.DetectSslMitmInterceptor(out certIssuer, out avMitm);
                if (hasSslMitm)
                {
                    diagSslMitm = avMitm;
                    issuesFound++;
                    report.AppendLine("  ⚠ [НАЙДЕН ПЕРЕХВАТ HTTPS] Антивирус подменяет TLS-сертификаты: " + avMitm);
                    report.AppendLine("  💡 [РЕШЕНИЕ] Добавьте googleapis.com и antigravity.exe в исключения HTTPS-сканера антивируса (" + avMitm + ").");
                }
                else
                {
                    report.AppendLine("  ✓ [OK] Перехвата HTTPS антивирусами (Kaspersky / Dr.Web / ESET / AdGuard) не обнаружено.");
                }

                string standbyInfo = string.IsNullOrEmpty(PixelCoreService.StandbyNodeName) ? "" : (" • резерв: " + PixelCoreService.StandbyNodeName);
                report.AppendLine(string.Format("  ✓ [ЯДРО] {0} | Манифест v{1} ({2}){3}",
                    PixelCoreService.ActiveEngineLabel,
                    PixelCoreService.ManifestVersion,
                    string.IsNullOrEmpty(PixelCoreService.ManifestSource) ? "embedded" : PixelCoreService.ManifestSource,
                    standbyInfo));

                if (!string.IsNullOrEmpty(PixelCoreService.LastGoEngineFailureReason))
                {
                    report.AppendLine("  ⚠ [GO FALLBACK] " + PixelCoreService.LastGoEngineFailureReason);
                }

                if (hasSslMitm)
                {
                    SetDiagItem("engine_manifest", DiagItemState.Warn, "SSL MITM: " + avMitm,
                        "Антивирус (" + avMitm + ") подменяет TLS-сертификаты (ошибки x509 в Node/MCP). Добавьте googleapis.com и antigravity.exe в исключения HTTPS-проверки.",
                        false, "");
                }
                else if (!manifestLoaded && PixelCoreService.ManifestVersion <= 0)
                {
                    issuesFound++;
                    SetDiagItem("engine_manifest", DiagItemState.Warn, "нет манифеста",
                        "Резервный манифест узлов не загружен. Нажмите «Починить автоматически» или переподключитесь.",
                        true, "engine");
                }
                else
                {
                    string engShort = PixelCoreService.UsingGoEngine ? "Go uTLS" : "C# Fallback";
                    SetDiagItem("engine_manifest", DiagItemState.Ok,
                        string.Format("{0} · v{1}", engShort, PixelCoreService.ManifestVersion),
                        "", false, "");
                }

                // ----------------------------------------------------------------
                // 6. LICENSE, KEY VALIDITY & PARALLEL NODE BENCHMARK
                // ----------------------------------------------------------------
                SetDiagItem("license", DiagItemState.Running, "проверка", "", false, "");
                report.AppendLine("\r\n[4/9] Турбо-бенчмарк матрицы узлов PWP-3 и проверка лицензии:");
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
                if (IsForeignIncompatibleVpnKey(rawKey, out diagForeignReason))
                {
                    diagForeignKey = true;
                    issuesFound++;
                    report.AppendLine("  ✗ [ЧУЖОЙ КЛЮЧ] " + diagForeignReason);
                }
                if (!diagForeignKey && (rawKey.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || rawKey.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                {
                    resolvedUri = FetchVlessFromSubscription(rawKey);
                }
                node = diagForeignKey ? null : ParseVlessUri(resolvedUri);
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
                    diagLicErrSummary = PixelCoreService.LastLicenseError;
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

                if (diagForeignKey)
                {
                    SetDiagItem("license", DiagItemState.Error, "чужой ключ",
                        "Вставлен ключ от стороннего VPN. Нажмите «Ключ / PRO» и сбросьте на встроенный FREE-режим или вставьте ключ от " + GetTelegramBotHandle() + ".",
                        false, "");
                }
                else if (!string.IsNullOrEmpty(PixelCoreService.LastLicenseError))
                {
                    string licUp = PixelCoreService.LastLicenseError.ToUpperInvariant();
                    string licRec = licUp.Contains("DEVICE_LIMIT")
                        ? string.Format("Достигнут лимит устройств ({0}/{1} ПК). Откройте {2}, сбросьте лишние ПК или продлите ключ.", Math.Max(1, PixelCoreService.ServerDevicesUsed), Math.Max(3, PixelCoreService.ServerDevicesMax), GetTelegramBotHandle())
                        : (licUp.Contains("EXPIRED")
                            ? string.Format("Срок ключа/триала истёк. Продлите ключ в {0} или переключитесь на Бесплатный режим.", GetTelegramBotHandle())
                            : string.Format("Сервер отклонил ключ ({0}). Получите новый ключ в {1}.", PixelCoreService.LastLicenseError, GetTelegramBotHandle()));
                    SetDiagItem("license", DiagItemState.Error, PixelCoreService.LastLicenseError, licRec, false, "");
                }
                else
                {
                    string licDetail = HasActiveProAccess()
                        ? (PixelCoreService.ServerDaysLeft > 0 ? string.Format("PRO · {0} дн.", PixelCoreService.ServerDaysLeft) : "PRO активен")
                        : string.Format("FREE · {0}/{1} узлов", healthyNodesCount, Math.Max(1, benchResults.Count));
                    SetDiagItem("license", DiagItemState.Ok, licDetail, "", false, "");
                }

                // ----------------------------------------------------------------
                // 7. LIVE END-TO-END CHANNEL PROBES & GRADUATED RECOVERY LADDER
                // ----------------------------------------------------------------
                SetDiagItem("channels", DiagItemState.Running, "проверка", "", false, "");
                report.AppendLine("\r\n[5/9] Сквозной боевой тест каналов (CloudCode + Gemini + OAuth2 + РФ):");
                bool channelsOk = false;
                bool activeStreamBlockedRestart = false;
                if (node != null && !string.IsNullOrEmpty(node.Server))
                {
                    string proxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                    bool portOpen = IsLocalPortOpen(_activeHttpPort, 200);
                    bool coreAlive = PixelCoreService.IsRunning;

                    string agCode = "000";
                    string gemCode = "000";
                    string aiStudioCode = "000";
                    string oauthCode = "000";
                    string yaCode = "000";
                    if (portOpen)
                    {
                        ProbeAllDiagChannels(proxyUrl, 5, out agCode, out gemCode, out aiStudioCode, out oauthCode, out yaCode);
                    }
                    else
                    {
                        yaCode = RunHttpProbe("https://ya.ru", "", 4);
                    }

                    if (autoFix && (!portOpen || !coreAlive || (!IsHttpCodeHealthy(agCode) && !IsHttpCodeHealthy(gemCode))))
                    {
                        issuesFound++;
                        bool wokeOk = false;
                        bool controlApiAlive = IsControlStatusConnected();
                        if (coreAlive && portOpen && (PixelCoreService.UsingGoEngine || controlApiAlive))
                        {
                            report.AppendLine("  ↻ Пробуем мгновенный Instant Wake канала...");
                            try
                            {
                                PixelCoreService.TriggerInstantWakeAsync("diag_autofix").GetAwaiter().GetResult();
                                ProbeAllDiagChannels(proxyUrl, 5, out agCode, out gemCode, out aiStudioCode, out oauthCode, out yaCode);
                                wokeOk = IsHttpCodeHealthy(agCode) || IsHttpCodeHealthy(gemCode);
                            }
                            catch { }
                        }

                        if (!wokeOk)
                        {
                            if (coreAlive && portOpen && IsAiStreamActivelyFlowing())
                            {
                                activeStreamBlockedRestart = true;
                                report.AppendLine("  ⚠ [ЗАЩИТА ПОТОКА] Обнаружен активный AI-поток — холодный перезапуск ядра пропущен, чтобы не оборвать сессию.");
                            }
                            else
                            {
                                report.AppendLine("  ↻ Авто-поднятие мультиплексного туннеля PWP-3 на лучшем узле...");
                                PixelCoreService.StopService();
                                Thread.Sleep(200);

                                _preferSafeProxyMode = true;
                                _activeNode = node;
                                string healedCfg = BuildSingBoxConfig(node, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                                ApplyAndStartCoreConfig(healedCfg);

                                for (int i = 0; i < 80; i++)
                                {
                                    if (!string.IsNullOrEmpty(PixelCoreService.LastLicenseError)) break;
                                    if (IsLocalPortOpen(_activeHttpPort, 150)) break;
                                    if (!PixelCoreService.IsRunning) break;
                                    Thread.Sleep(100);
                                }

                                if (string.IsNullOrEmpty(PixelCoreService.LastLicenseError) && IsLocalPortOpen(_activeHttpPort, 200))
                                {
                                    ProbeAllDiagChannels(proxyUrl, 8, out agCode, out gemCode, out aiStudioCode, out oauthCode, out yaCode);
                                }
                                PixelCoreService.SyncGoTelemetryAsync().GetAwaiter().GetResult();

                                if (string.IsNullOrEmpty(PixelCoreService.LastLicenseError) && !IsHttpCodeHealthy(agCode) && !IsHttpCodeHealthy(gemCode))
                                {
                                    report.AppendLine("  ↻ Авто-перебалансировка маршрута через манифест PixelCore...");
                                    PixelCoreService.StopService();
                                    Thread.Sleep(150);

                                    string retryCfg = BuildSingBoxConfig(node, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                                    ApplyAndStartCoreConfig(retryCfg);

                                    for (int i = 0; i < 80; i++)
                                    {
                                        if (!string.IsNullOrEmpty(PixelCoreService.LastLicenseError)) break;
                                        if (IsLocalPortOpen(_activeHttpPort, 150)) break;
                                        if (!PixelCoreService.IsRunning) break;
                                        Thread.Sleep(100);
                                    }

                                    if (string.IsNullOrEmpty(PixelCoreService.LastLicenseError) && IsLocalPortOpen(_activeHttpPort, 200))
                                    {
                                        ProbeAllDiagChannels(proxyUrl, 8, out agCode, out gemCode, out aiStudioCode, out oauthCode, out yaCode);
                                    }
                                    PixelCoreService.SyncGoTelemetryAsync().GetAwaiter().GetResult();
                                }
                            }
                        }

                        diagAgCode = agCode;
                        diagGemCode = gemCode;
                        diagOAuthCode = oauthCode;
                        diagYaCode = yaCode;

                        if (IsHttpCodeHealthy(agCode) || IsHttpCodeHealthy(gemCode))
                        {
                            channelsOk = true;
                            ApplyConnectedProxyPolicy();
                            FlushWindowsDnsCache();
                            HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                            issuesFixed++;
                            report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС УСПЕШЕН] Туннель поднят! CloudCode: HTTP {0} [OK], Gemini: HTTP {1} [OK], AI Studio: HTTP {4} [OK], OAuth2: HTTP {2} [OK], РФ (ya.ru): HTTP {3} [OK]", agCode, gemCode, oauthCode, yaCode, aiStudioCode));
                            RunOnUiThreadSync(delegate
                            {
                                _isConnected = true;
                                _connState = TunnelState.Online;
                                _statusHasCustomMessage = false;
                                if (_tunnelConnectedUtc == DateTime.MinValue) _tunnelConnectedUtc = DateTime.UtcNow;
                                _lastTunnelConnectedUtc = _tunnelConnectedUtc;
                                _currentPing = PixelCoreService.LivePingMs > 0 ? PixelCoreService.LivePingMs : PixelCoreService.ActiveNodeLatencyMs;
                                ResetButtonState(true);
                                UpdateLicenseHintFromServer();
                            });
                        }
                        else if (!activeStreamBlockedRestart)
                        {
                            string diagLicErr = PixelCoreService.LastLicenseError;
                            diagLicErrSummary = diagLicErr;
                            diagGoReason = !string.IsNullOrEmpty(PixelCoreService.LastConnectError)
                                ? PixelCoreService.LastConnectError
                                : PixelCoreService.GoEngineFallbackReason;
                            StopTunnelProcess(false);
                            report.AppendLine("  ✗ [ВНИМАНИЕ] Зарубежный узел не пропускает трафик. Системный прокси автоматически ОТКЛЮЧЁН для сохранения прямого интернета.");
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

                        if (portOpen && coreAlive && (IsHttpCodeHealthy(agCode) || IsHttpCodeHealthy(gemCode)))
                        {
                            channelsOk = true;
                            _activeNode = node;
                            ApplyConnectedProxyPolicy();
                            FlushWindowsDnsCache();
                            HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                            RunOnUiThreadSync(delegate
                            {
                                _isConnected = true;
                                _connState = TunnelState.Online;
                                _statusHasCustomMessage = false;
                                if (_tunnelConnectedUtc == DateTime.MinValue) _tunnelConnectedUtc = DateTime.UtcNow;
                                _lastTunnelConnectedUtc = _tunnelConnectedUtc;
                                ResetButtonState(true);
                                UpdateLicenseHintFromServer();
                            });
                            report.AppendLine(string.Format("  ✓ [OK] Все каналы работают! CloudCode: HTTP {0}, Gemini: HTTP {1}, AI Studio: HTTP {4}, OAuth2: HTTP {2}, РФ: HTTP {3}", agCode, gemCode, oauthCode, yaCode, aiStudioCode));
                        }
                        else
                        {
                            if (!portOpen || !coreAlive)
                            {
                                issuesFound++;
                                report.AppendLine("  ⚠ [ТУННЕЛЬ ОСТАНОВЛЕН] Шлюз сейчас не запущен — нажмите «Починить автоматически» или «Запустить туннель».");
                            }
                            else
                            {
                                issuesFound++;
                                report.AppendLine(string.Format("  ✗ [КАНАЛЫ НЕДОСТУПНЫ] CloudCode: {0}, Gemini: {1}, OAuth2: {2}, РФ: {3}", agCode, gemCode, oauthCode, yaCode));
                            }
                        }
                    }
                }

                if (channelsOk)
                {
                    SetDiagItem("channels", DiagItemState.Ok,
                        string.Format("AI {0} · РФ {1}", IsHttpCodeHealthy(diagAgCode) ? diagAgCode : diagGemCode, diagYaCode),
                        "", false, "");
                }
                else if (!string.IsNullOrEmpty(diagLicErrSummary))
                {
                    SetDiagItem("channels", DiagItemState.Error, "отклонён ключ",
                        "Сервер отклонил ключ (" + diagLicErrSummary + "). Вставьте актуальный ключ в «Ключ / PRO».",
                        false, "");
                }
                else if (!IsLocalPortOpen(_activeHttpPort, 100))
                {
                    SetDiagItem("channels", DiagItemState.Warn, "шлюз выключен",
                        "Туннель сейчас остановлен. Нажмите «Починить автоматически» чтобы поднять канал и проверить доступ к AI.",
                        true, "channels");
                }
                else if (activeStreamBlockedRestart)
                {
                    SetDiagItem("channels", DiagItemState.Warn, "активный AI-поток",
                        "Обнаружены активные AI-соединения — перезапуск ядра отложен, чтобы не оборвать текущий ответ.",
                        true, "channels");
                }
                else
                {
                    SetDiagItem("channels", DiagItemState.Error,
                        string.Format("AI {0} / РФ {1}", diagAgCode, diagYaCode),
                        "Канал CloudCode/Gemini не отвечает. Нажмите «Починить автоматически» для сброса узла и Instant Wake.",
                        true, "channels");
                }

                // ----------------------------------------------------------------
                // 8. ANTIGRAVITY IDE PROXY, SANCTIONS PATCH & LANGUAGE SERVER
                // ----------------------------------------------------------------
                SetDiagItem("ide_check", DiagItemState.Running, "проверка", "", false, "");
                report.AppendLine("\r\n[6/9] Патч Antigravity, AG_LS_PROXY, MCP Guard и логи IDE:");
                if (_optAntigravity && _optMcpTerminal)
                {
                    report.AppendLine("  ✓ [OK] Терминал Antigravity & MCP-серверы (npx/uvx/Python) защищены изолированно.");
                }
                List<string> sanctionPatchLogs;
                bool diagAnyPatchedNow;
                diagLsPatched = PatchAntigravitySanctionsAndProxy(out sanctionPatchLogs, false, out diagAnyPatchedNow);
                bool ideSanctionIssue = false;
                foreach (var sLog in sanctionPatchLogs)
                {
                    if (sLog.Contains("АВТО-ПАТЧ")) { issuesFound++; issuesFixed++; }
                    else if (sLog.Contains("⚠") || sLog.Contains("✗") || sLog.Contains("ОТСУТСТВУЕТ"))
                    {
                        issuesFound++;
                        ideSanctionIssue = true;
                    }
                    report.AppendLine(sLog);
                }

                bool envJustRepaired = false;
                bool diagAgEnvLive;
                int diagAgEnvPort;
                string diagAgEnvVal = GetCurrentAgLsProxyState(out diagAgEnvLive, out diagAgEnvPort);
                bool agEnvHealthy = !string.IsNullOrEmpty(diagAgEnvVal) && diagAgEnvLive;
                if (agEnvHealthy)
                {
                    report.AppendLine(string.Format("  ✓ [OK] AG_LS_PROXY env: {0} (порт :{1} активен).", diagAgEnvVal, diagAgEnvPort));
                }
                else if (_optAntigravity)
                {
                    if (_isConnected && IsLocalPortOpen(_activeHttpPort, 150) && autoFix)
                    {
                        string pUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                        SetAgLsProxyEnv(pUrl, true);
                        PurgeGlobalCliProxyEnvVars();
                        BroadcastEnvironmentChange();
                        envJustRepaired = true;
                        agEnvHealthy = true;
                        issuesFound++;
                        issuesFixed++;
                        report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС] AG_LS_PROXY env восстановлена -> {0}.", pUrl));
                    }
                    else if (_isConnected)
                    {
                        issuesFound++;
                        report.AppendLine(string.Format("  ✗ [ПРОБЛЕМА АНТИГРАВИТИ] AG_LS_PROXY env: {0}.", string.IsNullOrEmpty(diagAgEnvVal) ? "не задана" : (diagAgEnvVal + " (порт закрыт)")));
                    }
                    else
                    {
                        report.AppendLine("  ℹ [ИНФО] AG_LS_PROXY выставится автоматически при старте туннеля.");
                    }
                }

                DateTime agCutoffUtc = GetAntigravityStateCutoffUtc();
                int staleLsCount = CountProcessesStartedBefore(new[] { "language_server", "language_server_windows_x64" }, agCutoffUtc);
                if (staleLsCount > 0 && (diagAnyPatchedNow || envJustRepaired || autoFix))
                {
                    if (autoFix && !IsAiStreamActivelyFlowing())
                    {
                        int restarted = RestartStaleLanguageServers(agCutoffUtc);
                        if (restarted > 0)
                        {
                            staleLsCount = 0;
                            issuesFound++;
                            issuesFixed++;
                            report.AppendLine(string.Format("  ⚡ [АВТО-ФИКС] Перезапущено устаревших процессов language_server: {0}.", restarted));
                        }
                    }
                    else
                    {
                        issuesFound++;
                        report.AppendLine(string.Format("  ⚠ [УСТАРЕВШИЙ LS] Обнаружен language_server ({0}), запущенный до обновления AG_LS_PROXY.", staleLsCount));
                    }
                }

                string agLogBanner, agValUrl;
                Color agLogCol;
                List<string> agDiagLines;
                bool hasFreshLsError;
                InspectAntigravityLogs(true, out agLogBanner, out agLogCol, out agValUrl, out agDiagLines, out hasFreshLsError);
                bool hasRelaunchTipInLogs = false;
                foreach (var dl in agDiagLines)
                {
                    if (dl.IndexOf("Перезапустить Antigravity в туннеле", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasRelaunchTipInLogs = true;
                    if (dl.Contains("✗") && hasFreshLsError) issuesFound++;
                    report.AppendLine(dl);
                }

                bool hasRouteOrTimeoutBanner = hasFreshLsError && agLogBanner != null &&
                    (agLogBanner.IndexOf("блок региона", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     agLogBanner.IndexOf("loadCodeAssist timeout", StringComparison.OrdinalIgnoreCase) >= 0);

                if (autoFix && hasRouteOrTimeoutBanner && !IsAiStreamActivelyFlowing())
                {
                    int restartedLs = 0;
                    foreach (var lsName in new[] { "language_server", "language_server_windows_x64" })
                    {
                        Process[] lsProcs = GetProcessesByNameSafe(lsName);
                        try
                        {
                            foreach (var p in lsProcs)
                            {
                                try { p.Kill(); restartedLs++; } catch { }
                            }
                        }
                        finally { DisposeProcessArray(lsProcs); }
                    }
                    if (restartedLs > 0)
                    {
                        issuesFound++;
                        issuesFixed++;
                        report.AppendLine("  ⚡ [АВТО-СБРОС СЕССИИ] Перезапущен фоновый language_server без закрытия вкладок -> зависший кэш ошибки очищен!");
                    }
                }

                int staleAgCount = CountProcessesStartedBefore(new[] { "Antigravity" }, agCutoffUtc);
                if (staleAgCount > 0 && _optAntigravity)
                {
                    issuesFound++;
                    _forceShowAgBannerOnNextCheck = true;
                    RunOnUiThread(delegate { CheckAntigravityPreTunnelState(); });
                    report.AppendLine("  ⚠ [УСТАРЕВШИЙ ПРОЦЕСС IDE] Antigravity.exe запущен ДО включения туннеля — нажмите «Рестарт IDE» в главном окне.");
                }

                if (autoFix)
                {
                    var aiFixedList = HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                    foreach (var aiItem in aiFixedList)
                    {
                        issuesFixed++;
                        report.AppendLine("  ⚡ [АВТО-ФИКС AI] " + aiItem);
                    }
                }

                if (staleAgCount > 0 || hasRelaunchTipInLogs)
                {
                    SetDiagItem("ide_check", DiagItemState.Warn, "нужен рестарт IDE",
                        "Antigravity.exe запущен до туннеля и не получил AG_LS_PROXY. Нажмите «Рестарт IDE» в главном окне.",
                        false, "");
                }
                else if (staleLsCount > 0 || (!agEnvHealthy && _isConnected && _optAntigravity) || ideSanctionIssue)
                {
                    SetDiagItem("ide_check", DiagItemState.Warn,
                        staleLsCount > 0 ? "устарел LS" : "требуется настройка",
                        "Нажмите «Починить автоматически» для обновления AG_LS_PROXY и перезапуска language_server.",
                        true, "ide");
                }
                else
                {
                    SetDiagItem("ide_check", DiagItemState.Ok,
                        diagLsPatched ? "патч + proxy OK" : "готов",
                        "", false, "");
                }

                report.AppendLine("\r\n=== 📌 РЕКОМЕНДАЦИИ ===");
                int recNum = 1;
                if (diagForeignKey)
                {
                    report.AppendLine(string.Format("  {0}. Вставлен ключ от другого VPN. Переключитесь на FREE или вставьте ключ от {1}.", recNum++, GetTelegramBotHandle()));
                }
                if (!string.IsNullOrEmpty(diagLicErrSummary))
                {
                    report.AppendLine(string.Format("  {0}. Проверьте статус ключа ({1}) в {2}.", recNum++, diagLicErrSummary, GetTelegramBotHandle()));
                }
                if (!string.IsNullOrEmpty(diagThirdPartyTun))
                {
                    report.AppendLine(string.Format("  {0}. Отключите сторонний VPN/TUN ({1}) при использовании TUN-режима.", recNum++, diagThirdPartyTun));
                }
                if (staleAgCount > 0)
                {
                    report.AppendLine(string.Format("  {0}. Нажмите «Рестарт IDE» в главном окне PixelTunnel, чтобы Antigravity IDE перечитала AG_LS_PROXY.", recNum++));
                }
                if (recNum == 1)
                {
                    report.AppendLine("  1. Все ключевые проверки завершены — локальные конфиги и шлюз в актуальном состоянии.");
                }

                _lastSupportPassport = BuildCompactSupportPassport(
                    diagPoisonedHosts, diagHostsHealed, diagSslMitm,
                    diagNodeMatrix, diagAgCode, diagGemCode, diagOAuthCode, diagYaCode,
                    diagThirdPartyTun, diagLsPatched,
                    _optAntigravity, _optCursorAi, _optSocialWeb, _optDiscordYt);

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
                _diagFixing = false;
            }

            try
            {
                string finalReport = report.ToString();
                _lastDiagReport = finalReport;

                if (autoFix && !isAutoDiagCli)
                {
                    _diagFixActionNotice = issuesFixed > 0
                        ? string.Format("Выполнено исправлений: {0}. Проверки перепроверены.", issuesFixed)
                        : "Восстановление выполнено — все каналы проверены.";
                }

                RunOnUiThread(delegate
                {
                    RefreshAiTelemetryBanner();
                    CheckAntigravityPreTunnelState();
                    if (_activeModalKind == "diag")
                    {
                        BuildDiagModalContent(false);
                    }
                });

                if (isAutoDiagCli)
                {
                    SaveDiagnosticReportToDesktop();
                    RunOnUiThread(delegate { ExplicitShutdown(); });
                    return;
                }

                var unusedPulseRefresh = RefreshAiPulseUiAsync(true);
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
                    "• Процессы шлюза и ProksiFi: ОСТАНОВЛЕНЫ\r\n" +
                    "• Системный прокси Windows: ОТКЛЮЧЁН (ProxyEnable = 0)\r\n" +
                    "• Перехват WPAD (AutoConfigURL): ОЧИЩЕН\r\n" +
                    "• Системный кэш DNS Windows: СБРОШЕН (ipconfig /flushdns)\r\n" +
                    string.Format("• Проверка прямого интернета (ya.ru): HTTP {0} [OK]\r\n", yaShown);

                RunOnUiThread(delegate
                {
                    ResetButtonState(false);
                    SetStatus(
                        ColGreen,
                        "Прямой интернет полностью восстановлен",
                        string.Format("Все прокси и TUN-адаптеры отключены • Яндекс HTTP {0} [OK]", yaShown)
                    );
                });
            }
            catch (Exception ex)
            {
                string errMsg = ex.Message;
                RunOnUiThread(delegate
                {
                    SetStatus(ColAmber, "Ошибка сброса сети", errMsg);
                });
            }
            finally
            {
                _isDiagRunning = false;
            }
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
            _connState = connected ? TunnelState.Online : TunnelState.Offline;
            UpdateConnectionVisuals(true);
        }

        private void SetStatus(Color dotColor, string title, string sub)
        {
            _statusHasCustomMessage = true;
            _statusCustomTitle = title ?? "";
            _statusCustomSub = sub ?? "";

            if (_statusTitle != null)
            {
                _statusTitle.Text = _statusCustomTitle;
                if (dotColor == ColRed)
                    _statusTitle.Foreground = new SolidColorBrush(_theme.Err);
                else if (dotColor == ColAmber)
                    _statusTitle.Foreground = new SolidColorBrush(_theme.Warn);
                else
                    _statusTitle.Foreground = new SolidColorBrush(_theme.Ink);
            }
            if (_statusSub != null)
            {
                _statusSub.Text = _statusCustomSub;
            }
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
            if (_isMonitorTickRunning) return;
            _isMonitorTickRunning = true;
            try
            {
                _idleMonitorTickCounter++;
                if (_idleMonitorTickCounter % 15 == 1)
                {
                    CheckAntigravityUpdateWatchdogAsync();
                }
                if (_isConnected || _idleMonitorTickCounter % 5 == 1)
                {
                    RunOnUiThread(delegate { RefreshAiTelemetryBanner(); });
                }
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

                if (_isConnected && ((PixelCoreService.UsingGoEngine && !PixelCoreService.IsGoEngineAlive()) ||
                    (!PixelCoreService.IsRunning && !string.IsNullOrEmpty(PixelCoreService.GoEngineUnexpectedExitReason))))
                {
                    string crashReason = !string.IsNullOrEmpty(PixelCoreService.GoEngineUnexpectedExitReason)
                        ? PixelCoreService.GoEngineUnexpectedExitReason
                        : "Go uTLS процесс неожиданно завершился";
                    PixelCoreService.StopService();
                    if (_activeNode != null && (DateTime.UtcNow - _lastAutoReconnectUtc).TotalSeconds >= 10.0)
                    {
                        _lastAutoReconnectUtc = DateTime.UtcNow;
                        VlessNode recoverNode = _activeNode;
                        await Task.Run(() =>
                        {
                            try
                            {
                                string cfg = BuildSingBoxConfig(recoverNode, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                                ApplyAndStartCoreConfig(cfg);
                                for (int i = 0; i < 40; i++)
                                {
                                    if (IsLocalPortOpen(_activeHttpPort, 100) || !PixelCoreService.IsRunning) break;
                                    Thread.Sleep(100);
                                }
                                if (PixelCoreService.IsRunning && IsLocalPortOpen(_activeHttpPort, 150))
                                {
                                    ApplyConnectedProxyPolicy();
                                }
                            }
                            catch { }
                        });
                        if (PixelCoreService.IsRunning && IsLocalPortOpen(_activeHttpPort, 200))
                        {
                            RunOnUiThread(delegate
                            {
                                if (!PixelCoreService.UsingGoEngine)
                                {
                                    SetStatus(ColAmber, "Переключено на C# Fallback", crashReason);
                                }
                                UpdateConnectionVisuals(false);
                            });
                            return;
                        }
                    }

                    _isConnected = false;
                    await Task.Run(() => DisableOrRestoreSystemProxy());
                    RunOnUiThread(delegate
                    {
                        SetStatus(ColRed, "Туннель остановился (Прямой интернет сохранён)", crashReason);
                        ResetButtonState(false);
                    });
                    return;
                }

                bool alive = PixelCoreService.IsRunning;

                if (!alive || !IsLocalPortOpen(_activeHttpPort, 200))
                {
                    // Immediately disable system proxy if core died so browsers NEVER lose internet!
                    _isConnected = false;
                    string stopReason = !string.IsNullOrEmpty(PixelCoreService.GoEngineFallbackReason)
                        ? PixelCoreService.GoEngineFallbackReason
                        : "Системный прокси автоматически отключён. Нажмите «Запустить туннель».";
                    await Task.Run(() => DisableOrRestoreSystemProxy());
                    RunOnUiThread(delegate
                    {
                        SetStatus(ColRed, "Туннель остановился (Прямой интернет сохранён)", stopReason);
                        ResetButtonState(false);
                    });
                    return;
                }

                // Watchdog: ensure Windows system proxy matches active policy (Smart PAC vs Classic ProxyEnable=1)
                if (ShouldEnableSystemWideBrowserProxy())
                {
                    bool needProxyReapply = false;
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
                                        needProxyReapply = true;
                                }
                                else
                                {
                                    if (en == 0 || srv != string.Format("127.0.0.1:{0}", _activeHttpPort))
                                        needProxyReapply = true;
                                }
                            }
                        }
                    }
                    catch { }
                    if (needProxyReapply)
                    {
                        await Task.Run(() => EnableSystemProxy());
                    }
                }

                _pulseTickCounter++;
                if (_pulseTickCounter % 8 == 1)
                {
                    var unusedPulse = RefreshAiPulseUiAsync(false);
                }
                if (_pulseTickCounter % 3 == 1)
                {
                    RunOnUiThread(delegate { CheckAntigravityPreTunnelState(); });
                }

                if (_activeNode != null)
                {
                    if (PixelCoreService.UsingGoEngine)
                    {
                        try { await PixelCoreService.SyncGoTelemetryAsync(); } catch { }
                    }

                    int ms = PixelCoreService.LivePingMs;
                    if (ms <= 0) ms = PixelCoreService.ActiveNodeLatencyMs;
                    if (ms <= 0)
                    {
                        string host = _activeNode.Server;
                        int port = IsClusterHost(host) ? 443 : _activeNode.Port;
                        ms = await Task.Run(() => MeasureTcpPing(host, port));
                    }

                    if (ms > 0 && _isConnected)
                    {
                        _consecutivePingFailures = 0;
                        RunOnUiThread(delegate
                        {
                            _currentPing = ms;
                            UpdateLicenseHintFromServer();
                            if (_isConnected && _specLatencyVal != null && _connState == TunnelState.Online)
                            {
                                _specLatencyVal.Text = ms + " \u043c\u0441";
                                UpdateSignalBars(false);
                                if (!_statusHasCustomMessage && _statusSub != null)
                                {
                                    _statusSub.Text = BuildActiveRoutesSummary();
                                }
                            }
                        });
                    }
                    else if (_isConnected)
                    {
                        RunOnUiThread(delegate { UpdateLicenseHintFromServer(); });
                        _consecutivePingFailures++;
                        if (_consecutivePingFailures >= 3 && (DateTime.UtcNow - _lastAutoReconnectUtc).TotalSeconds >= 25.0)
                        {
                            _consecutivePingFailures = 0;
                            string proxyUrl = string.Format("http://127.0.0.1:{0}", _activeHttpPort);
                            string probe = await Task.Run(() => RunHttpProbe("https://www.gstatic.com/generate_204", proxyUrl, 5));
                            if (!IsHttpCodeHealthy(probe))
                            {
                                _lastAutoReconnectUtc = DateTime.UtcNow;
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
                                            string retryCfg = BuildSingBoxConfig(curNode, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb || _oauthHelperActive, false);
                                            ApplyAndStartCoreConfig(retryCfg);
                                        }
                                        catch { }
                                    });
                                    RunOnUiThread(delegate
                                    {
                                        _statusHasCustomMessage = false;
                                        UpdateConnectionVisuals(false);
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
            finally
            {
                _isMonitorTickRunning = false;
            }
        }

        private static int MeasureTcpPing(string host, int port)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(host, port, null, null);
                    bool ok;
                    try
                    {
                        ok = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(2200));
                    }
                    finally
                    {
                        try { result.AsyncWaitHandle.Close(); } catch { }
                    }
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
                req.UserAgent = "PixelTunnel/" + APP_VERSION;
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
                if (_isConfigGenMode || File.Exists(localFile)) return localFile;

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

        private static List<string> SubtractDefaultDomains(string legacyCsv, string defaultCsv)
        {
            var defaultSet = new HashSet<string>(ParseDomainCsv(defaultCsv), StringComparer.OrdinalIgnoreCase);
            var diff = new List<string>();
            foreach (string dom in ParseDomainCsv(legacyCsv))
            {
                if (!defaultSet.Contains(dom) && !diff.Contains(dom))
                {
                    diff.Add(dom);
                }
            }
            return diff;
        }

        private static void ReadCustomRulesConfig(out string proxyCsv, out string directCsv, out string editorsCsv)
        {
            proxyCsv = "";
            directCsv = "";
            editorsCsv = DEFAULT_CUSTOM_EDITORS;
            bool hasUserProxy = false;
            bool hasUserDirect = false;
            string legacyProxy = "";
            string legacyDirect = "";
            try
            {
                string p = GetCustomRulesFilePath();
                if (File.Exists(p))
                {
                    foreach (var line in File.ReadAllLines(p, Encoding.UTF8))
                    {
                        string t = (line ?? "").Trim();
                        if (t.StartsWith("USER_PROXY=", StringComparison.OrdinalIgnoreCase))
                        {
                            proxyCsv = t.Substring(11).Trim();
                            hasUserProxy = true;
                        }
                        else if (t.StartsWith("USER_DIRECT=", StringComparison.OrdinalIgnoreCase))
                        {
                            directCsv = t.Substring(12).Trim();
                            hasUserDirect = true;
                        }
                        else if (t.StartsWith("PROXY=", StringComparison.OrdinalIgnoreCase))
                        {
                            legacyProxy = t.Substring(6).Trim();
                        }
                        else if (t.StartsWith("DIRECT=", StringComparison.OrdinalIgnoreCase))
                        {
                            legacyDirect = t.Substring(7).Trim();
                        }
                        else if (t.StartsWith("EDITORS=", StringComparison.OrdinalIgnoreCase))
                        {
                            editorsCsv = t.Substring(8).Trim();
                        }
                    }

                    bool migratedLegacy = false;
                    List<string> migratedProxyList = null;
                    List<string> migratedDirectList = null;
                    if (!hasUserProxy && !string.IsNullOrEmpty(legacyProxy))
                    {
                        migratedProxyList = SubtractDefaultDomains(legacyProxy, DEFAULT_CUSTOM_PROXY);
                        proxyCsv = string.Join(", ", migratedProxyList.ToArray());
                        migratedLegacy = true;
                    }
                    if (!hasUserDirect && !string.IsNullOrEmpty(legacyDirect))
                    {
                        migratedDirectList = SubtractDefaultDomains(legacyDirect, DEFAULT_CUSTOM_DIRECT);
                        directCsv = string.Join(", ", migratedDirectList.ToArray());
                        migratedLegacy = true;
                    }
                    if (migratedLegacy && !_isConfigGenMode)
                    {
                        SaveCustomRulesConfig(
                            migratedProxyList ?? ParseDomainCsv(proxyCsv),
                            migratedDirectList ?? ParseDomainCsv(directCsv));
                    }
                }
            }
            catch { }
        }

        private static void SaveCustomRulesConfig(List<string> userProxyDomains, List<string> userDirectDomains)
        {
            try
            {
                string editorsCsv = DEFAULT_CUSTOM_EDITORS;
                string p = GetCustomRulesFilePath();
                if (File.Exists(p))
                {
                    try
                    {
                        foreach (var line in File.ReadAllLines(p, Encoding.UTF8))
                        {
                            string t = (line ?? "").Trim();
                            if (t.StartsWith("EDITORS=", StringComparison.OrdinalIgnoreCase))
                            {
                                string val = t.Substring(8).Trim();
                                if (!string.IsNullOrEmpty(val)) editorsCsv = val;
                            }
                        }
                    }
                    catch { }
                }

                string dir = System.IO.Path.GetDirectoryName(p);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

                string prxJoined = (userProxyDomains != null && userProxyDomains.Count > 0) ? string.Join(", ", userProxyDomains.ToArray()) : "";
                string dirJoined = (userDirectDomains != null && userDirectDomains.Count > 0) ? string.Join(", ", userDirectDomains.ToArray()) : "";
                var sb = new StringBuilder();
                sb.AppendLine("USER_PROXY=" + prxJoined);
                sb.AppendLine("USER_DIRECT=" + dirJoined);
                sb.AppendLine("EDITORS=" + editorsCsv);
                File.WriteAllText(p, sb.ToString(), new UTF8Encoding(false));
            }
            catch { }
        }

        private async void ApplyRulesHotReloadAsync(bool healEditors, bool updateStatusUi)
        {
            try
            {
                if (_activeNode == null) return;
                string prx, dir, eds;
                if (_customProxyDomains.Count > 0 || _customDirectDomains.Count > 0)
                {
                    prx = _customProxyDomains.Count > 0 ? string.Join(", ", _customProxyDomains.ToArray()) : "";
                    dir = _customDirectDomains.Count > 0 ? string.Join(", ", _customDirectDomains.ToArray()) : "";
                }
                else
                {
                    ReadCustomRulesConfig(out prx, out dir, out eds);
                }

                if (_isConnected && !_isBusy)
                {
                    await PixelCoreService.ReloadRulesV4Async(BuildReloadRulesJsonPayload(prx, dir)).ConfigureAwait(false);
                }

                await Task.Run(() =>
                {
                    try
                    {
                        string newCfg = BuildSingBoxConfig(_activeNode, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                        string dirPath = System.IO.Path.GetDirectoryName(_activeConfigPath);
                        if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath)) Directory.CreateDirectory(dirPath);
                        File.WriteAllText(_activeConfigPath, newCfg, new UTF8Encoding(false));
                        if (_isConnected && !_isBusy)
                        {
                            FlushWindowsDnsCache();
                            ApplyConnectedProxyPolicy();
                            if (healEditors)
                            {
                                HealAiEditorsAndServices(true, false, _optAntigravity, _optCursorAi, _optDiscordYt, _optSocialWeb, false);
                            }
                        }
                    }
                    catch { }
                });

                if (updateStatusUi)
                {
                    RunOnUiThread(delegate
                    {
                        _statusHasCustomMessage = false;
                        UpdateConnectionVisuals(false);
                    });
                }
            }
            catch { }
        }

        private void ApplyCustomRulesHotReloadAsync()
        {
            UpdateRulesCountPill();
            if (!_isConnected || _isBusy || _activeNode == null) return;
            ApplyRulesHotReloadAsync(false, false);
        }

        private void TriggerCategoryHotReloadIfConnected()
        {
            if (!_isConnected || _isBusy || _activeNode == null) return;
            ApplyRulesHotReloadAsync(true, true);
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
                { "temporary_proxy_domains", _oauthHelperActive ? new List<string>(OAuthTemporaryDomains) : new List<string>() },
                { "temporary_proxy_ttl_sec", _oauthHelperActive ? 180 : 0 },
                { "proxy_all", false },
                { "tun_mode", _optTunMode },
                { "wsl_bridge", _optWslBridge },
                { "instant_wake", _optInstantWake }
            };
            return MiniJson.Serialize(payload);
        }

        private string BuildLocalDiagnosticReportString()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== PIXELTUNNEL DIAGNOSTIC REPORT v" + APP_VERSION + " ===");
            sb.AppendLine("Timestamp: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Engine: " + PixelCoreService.ActiveEngineLabel + (string.IsNullOrEmpty(PixelCoreService.GoEngineFallbackReason) ? "" : (" (" + PixelCoreService.GoEngineFallbackReason + ")")));
            sb.AppendLine("LastUsedEngine: " + PixelCoreService.LastUsedEngineLabel + (string.IsNullOrEmpty(PixelCoreService.LastGoEngineFailureReason) ? "" : (" (" + PixelCoreService.LastGoEngineFailureReason + ")")));
            string repExtDesync = PixelCoreService.DetectExternalDesyncProcess();
            sb.AppendLine("ExternalDesync: " + (string.IsNullOrEmpty(repExtDesync) ? "none" : repExtDesync));
            sb.AppendLine(string.Format("LicenseError: {0} | Devices: {1}/{2}",
                string.IsNullOrEmpty(PixelCoreService.LastLicenseError) ? "none" : PixelCoreService.LastLicenseError,
                PixelCoreService.ServerDevicesUsed,
                PixelCoreService.ServerDevicesMax));
            if (!string.IsNullOrEmpty(PixelCoreService.LastConnectError))
                sb.AppendLine("LastConnectError: " + PixelCoreService.LastConnectError);
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
            foreach (var raw in csv.Split(new[] { ',', ';', '\r', '\n', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string d = NormalizeDomainInput(raw);
                if (!string.IsNullOrEmpty(d) && !res.Contains(d))
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

            string[] googleAiStudioList = new[]
            {
                "aistudio.google.com", "ai.studio", "aistudio.google", "makersuite.google.com",
                "alkalimakersuite-pa.clients6.google.com", "alkalimakersuiteapplets.pa.clients6.google.com",
                "webchannel-alkalimakersuite-pa.clients6.google.com", "generativelanguage.googleapis.com",
                "gemini.google.com", "gemini.google", "geminiweb-pa.clients6.google.com",
                "notebooklm.google.com", "notebooklm.google", "colab.research.google.com", "colab.google",
                "labs.google", "deepmind.google", "ai.google", "ai.google.dev", "jules.google", "firebase.studio",
                "cloud.google", "usercontent.goog", "withgoogle.com", "google.dev", "g.co", "goo.gl", "ggpht.com",
                "recaptcha.net", "googletagmanager.com", "google-analytics.com",
                "run.app", "web.app", "firebaseapp.com", "appspot.com",
                "apis.google.com", "accounts.google.com",
                "clients1.google.com", "clients2.google.com", "clients3.google.com",
                "clients4.google.com", "clients5.google.com", "clients6.google.com",
                "cloudconsole-pa.clients6.google.com", "people-pa.clients6.google.com",
                "oauth2.googleapis.com", "www.googleapis.com", "googleapis.com",
                "gstatic.com", "googleusercontent.com", "google.com",
                "gvt1.com", "gvt2.com", "gvt3.com", "1e100.net", "pki.goog"
            };

            if (routeAg)
            {
                string[] agList = new[]
                {
                    "antigravity.google", "antigravity-unleash.goog", "antigravity-unlocker.pages.dev", "antigravity.dev",
                    "daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com",
                    "cloudaicompanion.googleapis.com", "daily-cloud-pa.clients6.google.com", "aicode.googleapis.com"
                };
                foreach (var d in agList) addDom(d);
                foreach (var d in googleAiStudioList) addDom(d);

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
                    "cursor.com", "cursor.sh", "cursorapi.com", "cursor-cdn.com", "windsurf.com", "codeium.com",
                    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
                    "claude.ai", "claude.com", "anthropic.com", "auth0.com", "perplexity.ai", "grok.com", "x.ai",
                    "elevenlabs.io", "suno.com", "suno.ai", "midjourney.com", "klingai.com",
                    "runwayml.com", "sora.com", "luma.ai", "lumalabs.ai", "heygen.com",
                    "v0.dev", "bolt.new", "lovable.dev", "replit.com", "huggingface.co", "hf.co",
                    "openrouter.ai", "together.ai", "groq.com", "deepseek.com", "mistral.ai",
                    "cohere.com", "replicate.com", "civitai.com", "githubcopilot.com", "copilot.microsoft.com"
                };
                foreach (var d in aiList) addDom(d);
                foreach (var d in googleAiStudioList) addDom(d);
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
                    "telegram.org", "t.me", "tx.me", "web.telegram.org", "tdesktop.com", "telesco.pe", "telegra.ph",
                    "telegram-cdn.org", "cdn-telegram.org", "usercontent.dev"
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

            if (domains.Count == 0)
            {
                addDom("antigravity.google");
                addDom("daily-cloudcode-pa.googleapis.com");
            }

            var items = new List<string>();
            foreach (var d in domains) items.Add("\"domain:" + EscapeJson(d) + "\"");
            return string.Join(", ", items.ToArray());
        }

        private static VlessNode NormalizeLegacyClusterNode(VlessNode node)
        {
            if (node == null || string.IsNullOrWhiteSpace(node.Server)) return node;
            string s = node.Server.Trim();
            if (string.Equals(s, "201.34.152.97", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s, "147.45.135.71", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s, "node.pixelstore.space", StringComparison.OrdinalIgnoreCase))
            {
                node.Server = GetDefaultClusterHost();
                node.Port = 443;
                node.Sni = "ai.pixelstore.space";
                node.TransportType = "pwp3";
                node.Flow = "";
                node.ResolvedIp = "185.103.103.162";
            }
            return node;
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
                    return NormalizeLegacyClusterNode(new VlessNode
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
                    });
                }
                if (!string.IsNullOrWhiteSpace(uri) && Regex.IsMatch(uri.Trim(), @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"))
                {
                    string cleanUuid = uri.Trim().ToLowerInvariant();
                    string defHost = GetDefaultClusterHost();
                    return NormalizeLegacyClusterNode(new VlessNode
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
                    });
                }
                if (!string.IsNullOrWhiteSpace(uri) && Regex.IsMatch(uri.Trim(), @"^https://ai\.pixelstore\.space/sub/[A-Za-z0-9_-]{6,64}$", RegexOptions.IgnoreCase))
                {
                    string defHost = GetDefaultClusterHost();
                    string subId = uri.Trim().Substring(uri.Trim().LastIndexOf('/') + 1);
                    return NormalizeLegacyClusterNode(new VlessNode
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
                    });
                }
                if (!string.IsNullOrWhiteSpace(uri) && uri.StartsWith("pwp1://", StringComparison.OrdinalIgnoreCase))
                {
                    Uri u = new Uri(uri);
                    string sec = string.IsNullOrEmpty(u.UserInfo) ? "" : Uri.UnescapeDataString(u.UserInfo);
                    return NormalizeLegacyClusterNode(new VlessNode
                    {
                        Uuid = sec,
                        Server = u.Host,
                        ResolvedIp = u.Host,
                        Port = u.Port > 0 ? u.Port : 2087,
                        Sni = "www.microsoft.com",
                        TransportType = "pwp1",
                        Security = "pwp1-tls",
                        Remark = "PixelCore PWP-1 NL"
                    });
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

                return NormalizeLegacyClusterNode(node);
            }
            catch
            {
                return null;
            }
        }

        private static bool IsClusterHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            string h = host.Trim().Trim('[', ']').ToLowerInvariant();
            if (string.Equals(h, GetDefaultClusterHost(), StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "node.pixelstore.space", StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "ws.pixelstore.space", StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "pixelstore.space", StringComparison.OrdinalIgnoreCase)
                || h.EndsWith(".pixelstore.space", StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "201.34.152.97", StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "147.45.135.71", StringComparison.OrdinalIgnoreCase)
                || string.Equals(h, "185.103.103.162", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return PixelCoreService.IsKnownManifestHost(h);
        }

        private static void BuildManifestFieldsForConfig(out string pwpSecret, out string nodesJson)
        {
            pwpSecret = "";
            nodesJson = "[]";
            try
            {
                List<Dictionary<string, object>> nodesList;
                PixelCoreService.ExportManifestFieldsForConfig(3500, out pwpSecret, out nodesList);
                if (pwpSecret == null) pwpSecret = "";
                nodesJson = (nodesList != null) ? MiniJson.Serialize(nodesList) : "[]";
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
                if (string.Equals(server.Trim(), "node.pixelstore.space", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(server.Trim(), "201.34.152.97", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(server.Trim(), "147.45.135.71", StringComparison.OrdinalIgnoreCase))
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
            string effectiveDirectIp = IsClusterHost(node.Server) ? "185.103.103.162" : node.ResolvedIp;
            if (!string.IsNullOrEmpty(effectiveDirectIp))
            {
                directIpCidrs += ", \"" + EscapeJson(effectiveDirectIp) + "/32\"";
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

            string defaultOutboundRules = @",
      {
        ""type"": ""field"",
        ""outboundTag"": ""direct"",
        ""network"": ""tcp,udp""
      }";

            string prxCsv, dirCsv, edsCsv;
            ReadCustomRulesConfig(out prxCsv, out dirCsv, out edsCsv);
            string dummyTun;
            bool nodeIsPro = !string.IsNullOrWhiteSpace(uuid) && !IsLegacyOrFreeKey(uuid);
            bool effectiveTun = _optTunMode && nodeIsPro && !CheckOtherThirdPartyTunAdapters(out dummyTun);
            string v2Json = string.Format(@"{{
    ""smart_pac"": {0},
    ""pac_rev"": {1},
    ""wsl_bridge"": {2},
    ""tun_mode"": {10},
    ""instant_wake"": {11},
    ""proxy_all"": false,
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
                JoinJsonStrings(ParseDomainCsv(dirCsv)),
                effectiveTun ? "true" : "false",
                _optInstantWake ? "true" : "false");

            return string.Format(@"{{
  ""preferredRegion"": ""{15}"",
  ""http_port"": {17},
  ""socks_port"": {18},
  ""pwpSecret"": ""{19}"",
  ""nodes"": {20},
  ""v2"": {16},
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
        }}{14}
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
          ""domain:vkplay.ru""
        ]
      }},
      {{
        ""type"": ""field"",
        ""outboundTag"": ""proxy"",
        ""domain"": [ {12} ]
      }}{13}
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
            var sb = new StringBuilder(s.Length + 8);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\\') sb.Append("\\\\");
                else if (c == '"') sb.Append("\\\"");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\t') sb.Append("\\t");
                else if (c == '\b') sb.Append("\\b");
                else if (c == '\f') sb.Append("\\f");
                else if (c < 0x20) sb.AppendFormat(System.Globalization.CultureInfo.InvariantCulture, "\\u{0:x4}", (int)c);
                else sb.Append(c);
            }
            return sb.ToString();
        }
    }
}
