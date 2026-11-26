using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PixelTunnel
{
    /// <summary>
    /// Pre-baked grayscale monospace glyph atlas for fast CPU WriteableBitmap blitting
    /// without per-frame GDI+/WPF text shaping allocations.
    /// </summary>
    internal sealed class AsciiGlyphAtlas
    {
        public const string BodyRamp = " .,:;~-+*rvcxznuwqpbd0OQWD8%$#@";
        public static readonly char[] SparkGlyphs = new char[] { '\u00B7', ':', ';', '+', '*', '\u00B0', '^', '~' };
        private const string ExtraChars = "\u00B7\u00B0\u2502\u25B8\u2500!\u2588\u2593\u2592\u2591ISPNETW4AD";

        public readonly int CellW;
        public readonly int CellH;
        private readonly Dictionary<char, byte[]> _glyphs = new Dictionary<char, byte[]>();

        public AsciiGlyphAtlas(int cellW, int cellH, float fontPt)
        {
            CellW = cellW;
            CellH = cellH;

            string allChars = BodyRamp + ExtraChars;
            var seen = new HashSet<char>();
            foreach (char ch in allChars)
            {
                if (!seen.Add(ch)) continue;
                _glyphs[ch] = RasterizeGlyph(ch, fontPt);
            }
        }

        private byte[] RasterizeGlyph(char ch, float fontPt)
        {
            var alpha = new byte[CellW * CellH];
            if (ch == ' ') return alpha;

            using (var bmp = new Bitmap(CellW, CellH, System.Drawing.Imaging.PixelFormat.Format32bppArgb))
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(System.Drawing.Color.Black);
                g.SmoothingMode = SmoothingMode.HighQuality;
                g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;

                using (var font = CreateMonoFont(fontPt))
                using (var sf = new StringFormat(StringFormat.GenericTypographic))
                using (var brush = new SolidBrush(System.Drawing.Color.White))
                {
                    sf.Alignment = StringAlignment.Center;
                    sf.LineAlignment = StringAlignment.Center;
                    sf.FormatFlags |= StringFormatFlags.NoWrap;
                    g.DrawString(ch.ToString(), font, brush, new RectangleF(-1f, 0f, CellW + 2f, CellH + 0.5f), sf);
                }

                for (int y = 0; y < CellH; y++)
                {
                    for (int x = 0; x < CellW; x++)
                    {
                        var px = bmp.GetPixel(x, y);
                        int lum = (px.R * 30 + px.G * 59 + px.B * 11) / 100;
                        alpha[y * CellW + x] = (byte)Math.Min(255, lum);
                    }
                }
            }
            return alpha;
        }

        private static System.Drawing.Font CreateMonoFont(float pt)
        {
            string[] candidates = new string[] { "Cascadia Mono", "Consolas", "Courier New" };
            foreach (string name in candidates)
            {
                try
                {
                    var f = new System.Drawing.Font(name, pt, System.Drawing.FontStyle.Bold, GraphicsUnit.Point);
                    if (string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase) || name == "Courier New")
                    {
                        return f;
                    }
                    f.Dispose();
                }
                catch { }
            }
            return new System.Drawing.Font(System.Drawing.FontFamily.GenericMonospace, pt, System.Drawing.FontStyle.Bold, GraphicsUnit.Point);
        }

        public static void FillRect(int[] buf, int bgR, int bgG, int bgB)
        {
            int packed = unchecked((int)(0xFF000000u | ((uint)bgR << 16) | ((uint)bgG << 8) | (uint)bgB));
            for (int i = 0; i < buf.Length; i++) buf[i] = packed;
        }

        public void BlitGlyph(int[] buf, int stridePx, int col, int row, char ch, int fgR, int fgG, int fgB, int bgR, int bgG, int bgB)
        {
            byte[] mask;
            if (!_glyphs.TryGetValue(ch, out mask)) return;

            int ox = col * CellW;
            int oy = row * CellH;
            int totalRows = buf.Length / stridePx;
            if (ox < 0 || oy < 0 || ox + CellW > stridePx || oy + CellH > totalRows) return;

            for (int y = 0; y < CellH; y++)
            {
                int dstRow = (oy + y) * stridePx + ox;
                int srcRow = y * CellW;
                for (int x = 0; x < CellW; x++)
                {
                    int a = mask[srcRow + x];
                    if (a == 0) continue;
                    int inv = 255 - a;
                    int r = (fgR * a + bgR * inv) / 255;
                    int g = (fgG * a + bgG * inv) / 255;
                    int b = (fgB * a + bgB * inv) / 255;
                    buf[dstRow + x] = unchecked((int)(0xFF000000u | ((uint)r << 16) | ((uint)g << 8) | (uint)b));
                }
            }
        }

        public void BlitTextCentered(int[] buf, int stridePx, double centerXNorm, int totalCols, int row, string text, int fgR, int fgG, int fgB, int bgR, int bgG, int bgB)
        {
            if (string.IsNullOrEmpty(text)) return;
            int startCol = (int)Math.Round(centerXNorm * totalCols - text.Length * 0.5);
            for (int i = 0; i < text.Length; i++)
            {
                int c = startCol + i;
                if (c >= 0 && c < totalCols)
                {
                    BlitGlyph(buf, stridePx, c, row, text[i], fgR, fgG, fgB, bgR, bgG, bgB);
                }
            }
        }

        public static void SampleRamp(byte[,] stops, double t, out int r, out int g, out int b)
        {
            t = t - Math.Floor(t);
            int count = stops.GetLength(0);
            double u = t * (count - 1);
            int idx = (int)Math.Floor(u);
            double f = u - idx;
            int next = Math.Min(count - 1, idx + 1);
            r = (int)Math.Round(stops[idx, 0] + (stops[next, 0] - stops[idx, 0]) * f);
            g = (int)Math.Round(stops[idx, 1] + (stops[next, 1] - stops[idx, 1]) * f);
            b = (int)Math.Round(stops[idx, 2] + (stops[next, 2] - stops[idx, 2]) * f);
        }

        public static double Hash2(int ix, int iy)
        {
            unchecked
            {
                int n = ix * 374761393 + iy * 668265263;
                n = (n ^ (n >> 13)) * 1274126177;
                uint u = (uint)(n ^ (n >> 16));
                return u / 4294967295.0;
            }
        }

        public static double Noise2(double x, double y)
        {
            int ix = (int)Math.Floor(x);
            int iy = (int)Math.Floor(y);
            double fx = x - ix;
            double fy = y - iy;
            double ux = fx * fx * (3.0 - 2.0 * fx);
            double uy = fy * fy * (3.0 - 2.0 * fy);
            double a = Hash2(ix, iy);
            double b = Hash2(ix + 1, iy);
            double c = Hash2(ix, iy + 1);
            double d = Hash2(ix + 1, iy + 1);
            return a + (b - a) * ux + (c - a) * uy + (a - b - c + d) * ux * uy;
        }
    }

    /// <summary>
    /// Shimmering PRISM ASCII renderer for the official Google Antigravity emblem inside the Status Card.
    /// Adapts automatically to Light (#FAFBFD) and Dark (#08090D) themes and always shimmers in color.
    /// </summary>
    internal sealed class AsciiAntigravityPrismEngine
    {
        private const string AntigravitySvgPath =
            "M21.751 22.607c1.34 1.005 3.35.335 1.508-1.508C17.73 15.74 18.904 1 12.037 1 5.17 1 6.342 15.74.815 21.1c-2.01 2.009.167 2.511 1.507 1.506 5.192-3.517 4.857-9.714 9.715-9.714 4.857 0 4.522 6.197 9.714 9.715z";

        private static readonly byte[,] PrismDarkStops = new byte[,]
        {
            { 49, 134, 255 }, { 116, 155, 255 }, { 0, 185, 92 }, { 251, 188, 4 }, { 252, 65, 61 }, { 116, 155, 255 }
        };

        private static readonly byte[,] PrismLightStops = new byte[,]
        {
            { 29, 78, 216 }, { 2, 132, 199 }, { 4, 120, 87 }, { 217, 119, 6 }, { 220, 38, 38 }, { 29, 78, 216 }
        };

        private const int Cols = 45;
        private const int Rows = 13;
        private readonly AsciiGlyphAtlas _atlas;
        private readonly int _widthPx;
        private readonly int _heightPx;
        private readonly int[] _frameBuf;
        private readonly float[] _insideMask;
        private readonly float[] _edgeMask;

        public WriteableBitmap Bitmap { get; private set; }

        public AsciiAntigravityPrismEngine()
        {
            _atlas = new AsciiGlyphAtlas(9, 14, 9.2f);
            _widthPx = Cols * _atlas.CellW;
            _heightPx = Rows * _atlas.CellH;
            _frameBuf = new int[_widthPx * _heightPx];
            _insideMask = new float[Cols * Rows];
            _edgeMask = new float[Cols * Rows];
            Bitmap = new WriteableBitmap(_widthPx, _heightPx, 96, 96, PixelFormats.Bgra32, null);

            BuildMasks();
        }

        private void BuildMasks()
        {
            var geom = Geometry.Parse(AntigravitySvgPath);
            double fitSize = Math.Min(_widthPx * 0.66, _heightPx * 0.72);
            double scale = fitSize / 24.0;
            double offX = (_widthPx - 24.0 * scale) * 0.5;
            double offY = (_heightPx - 24.0 * scale) * 0.22;

            for (int r = 0; r < Rows; r++)
            {
                for (int c = 0; c < Cols; c++)
                {
                    float sum = 0f;
                    int samples = 0;
                    for (int sy = 0; sy < 2; sy++)
                    {
                        double py = r * _atlas.CellH + (sy + 0.5) * (_atlas.CellH * 0.5);
                        double svgY = (py - offY) / scale;
                        for (int sx = 0; sx < 2; sx++)
                        {
                            double px = c * _atlas.CellW + (sx + 0.5) * (_atlas.CellW * 0.5);
                            double svgX = (px - offX) / scale;
                            if (geom.FillContains(new System.Windows.Point(svgX, svgY)))
                            {
                                sum += 1f;
                            }
                            samples++;
                        }
                    }
                    _insideMask[r * Cols + c] = sum / samples;
                }
            }

            for (int r = 0; r < Rows; r++)
            {
                for (int c = 0; c < Cols; c++)
                {
                    if (_insideMask[r * Cols + c] > 0.12f) continue;
                    float best = 0f;
                    for (int dr = -2; dr <= 2; dr++)
                    {
                        for (int dc = -3; dc <= 3; dc++)
                        {
                            int nr = r + dr;
                            int nc = c + dc;
                            if (nr >= 0 && nr < Rows && nc >= 0 && nc < Cols)
                            {
                                float cov = _insideMask[nr * Cols + nc];
                                if (cov > 0.2f)
                                {
                                    double d = Math.Sqrt(dc * dc * 0.56 + dr * dr * 1.32);
                                    float fall = (float)(Math.Max(0.0, 1.0 - d / 3.2) * cov);
                                    if (fall > best) best = fall;
                                }
                            }
                        }
                    }
                    _edgeMask[r * Cols + c] = best;
                }
            }
        }

        public void Render(double t, TunnelState connState, bool isDark, bool pointerActive, double pointerNormX, double pointerNormY)
        {
            int bgR = isDark ? 8 : 250;
            int bgG = isDark ? 9 : 251;
            int bgB = isDark ? 13 : 253;
            int specR = isDark ? 244 : 17;
            int specG = isDark ? 248 : 17;
            int specB = isDark ? 250 : 19;
            int auraR = isDark ? 75 : 148;
            int auraG = isDark ? 85 : 163;
            int auraB = isDark ? 99 : 184;
            byte[,] stops = isDark ? PrismDarkStops : PrismLightStops;

            AsciiGlyphAtlas.FillRect(_frameBuf, bgR, bgG, bgB);

            double tiltX = pointerActive ? (pointerNormX - 0.5) * 1.4 : 0.0;
            double tiltY = pointerActive ? (pointerNormY - 0.5) * 1.4 : 0.0;
            int rampLen = AsciiGlyphAtlas.BodyRamp.Length;

            for (int r = 0; r < Rows; r++)
            {
                double ny = r / (double)(Rows - 1);
                for (int c = 0; c < Cols; c++)
                {
                    double nx = c / (double)(Cols - 1);
                    int idx = r * Cols + c;
                    float cov = _insideMask[idx];
                    float aura = _edgeMask[idx];

                    if (cov > 0.08f)
                    {
                        double flowN = AsciiGlyphAtlas.Noise2(c * 0.24 - t * 0.65, r * 0.34 + t * 0.9);
                        double wave = Math.Sin((nx * 4.4 + ny * 2.8 + tiltX + tiltY) * 1.6 - t * 2.1 + flowN * 1.4);
                        double crest = Math.Pow(Math.Max(0.0, wave), 3.0);

                        if (connState == TunnelState.Offline)
                        {
                            double idleLum = Math.Max(0.28, Math.Min(0.76, cov * (0.42 + flowN * 0.24 + crest * 0.22)));
                            char ch = AsciiGlyphAtlas.BodyRamp[(int)(idleLum * (rampLen - 1))];
                            if (ch != ' ')
                            {
                                double phase = nx * 0.8 + ny * 0.4 + tiltX * 0.2 - t * 0.16 + flowN * 0.2;
                                int fr, fg, fb;
                                AsciiGlyphAtlas.SampleRamp(stops, phase, out fr, out fg, out fb);
                                _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, ch, fr, fg, fb, bgR, bgG, bgB);
                            }
                            continue;
                        }

                        if (connState == TunnelState.Connecting)
                        {
                            double scanY = 1.0 - ((t * 0.95) % 1.25);
                            double scanBand = Math.Max(0.0, 1.0 - Math.Abs(ny - scanY) * 5.2);
                            double lum = Math.Min(1.0, cov * (0.35 + scanBand * 0.65 + flowN * 0.15));
                            char ch = AsciiGlyphAtlas.BodyRamp[Math.Min(rampLen - 1, (int)(lum * (rampLen - 1)))];
                            if (ch != ' ')
                            {
                                int fr, fg, fb;
                                if (scanBand > 0.55) { fr = specR; fg = specG; fb = specB; }
                                else AsciiGlyphAtlas.SampleRamp(stops, nx + ny + t * 0.6, out fr, out fg, out fb);
                                _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, ch, fr, fg, fb, bgR, bgG, bgB);
                            }
                            continue;
                        }

                        // Online: full vibrant PRISM iridescent shimmer
                        double oLum = Math.Min(1.0, cov * (0.50 + flowN * 0.28 + crest * 0.34));
                        int rIdx = Math.Min(rampLen - 1, Math.Max(2, (int)(oLum * (rampLen - 1))));
                        char oCh = AsciiGlyphAtlas.BodyRamp[rIdx];
                        if (oCh != ' ')
                        {
                            int fr, fg, fb;
                            if (crest > 0.72 && cov > 0.75f)
                            {
                                fr = specR; fg = specG; fb = specB;
                            }
                            else
                            {
                                double phase = nx * 0.85 + ny * 0.45 + tiltX * 0.25 - t * 0.28 + flowN * 0.22;
                                AsciiGlyphAtlas.SampleRamp(stops, phase, out fr, out fg, out fb);
                            }
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, oCh, fr, fg, fb, bgR, bgG, bgB);
                        }
                    }
                    else if (connState != TunnelState.Offline)
                    {
                        int driftR = r + (int)Math.Floor(t * 2.2);
                        double spark = AsciiGlyphAtlas.Hash2(c, driftR);
                        if (aura > 0.15f)
                        {
                            if (spark > 0.84)
                            {
                                char sCh = AsciiGlyphAtlas.SparkGlyphs[((c + driftR) % 5 + 5) % 5];
                                int fr, fg, fb;
                                AsciiGlyphAtlas.SampleRamp(stops, nx + ny - t * 0.25, out fr, out fg, out fb);
                                _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, sCh, fr, fg, fb, bgR, bgG, bgB);
                            }
                            else if (aura > 0.45f && spark > 0.52)
                            {
                                _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, '\u00B7', auraR, auraG, auraB, bgR, bgG, bgB);
                            }
                        }
                        else if (connState == TunnelState.Online && spark > 0.978)
                        {
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, (c % 2 == 0 ? '\u00B7' : '+'), auraR, auraG, auraB, bgR, bgG, bgB);
                        }
                    }
                }
            }

            Bitmap.WritePixels(new Int32Rect(0, 0, _widthPx, _heightPx), _frameBuf, _widthPx * 4, 0);
        }
    }

    /// <summary>
    /// 3D-shaded tilted ASCII capsule renderer for the Blue (Pixel VPN) and Red (Aether VPN) pills.
    /// </summary>
    internal sealed class AsciiVpnPillEngine
    {
        private static readonly byte[,] BlueDarkStops = new byte[,]
        {
            { 30, 58, 138 }, { 29, 78, 216 }, { 59, 130, 246 }, { 96, 165, 250 }, { 186, 230, 253 }
        };
        private static readonly byte[,] BlueLightStops = new byte[,]
        {
            { 30, 58, 138 }, { 29, 78, 216 }, { 37, 99, 235 }, { 2, 132, 199 }, { 14, 116, 144 }
        };
        private static readonly byte[,] RedDarkStops = new byte[,]
        {
            { 69, 10, 10 }, { 153, 27, 27 }, { 220, 38, 38 }, { 248, 113, 113 }, { 254, 205, 211 }
        };
        private static readonly byte[,] RedLightStops = new byte[,]
        {
            { 127, 29, 29 }, { 153, 27, 27 }, { 185, 28, 28 }, { 220, 38, 38 }, { 234, 88, 12 }
        };

        private const int Cols = 40;
        private const int Rows = 9;
        private readonly AsciiGlyphAtlas _atlas;
        private readonly int _widthPx;
        private readonly int _heightPx;
        private readonly int[] _frameBuf;

        public WriteableBitmap Bitmap { get; private set; }

        public AsciiVpnPillEngine()
        {
            _atlas = new AsciiGlyphAtlas(8, 12, 8.2f);
            _widthPx = Cols * _atlas.CellW;
            _heightPx = Rows * _atlas.CellH;
            _frameBuf = new int[_widthPx * _heightPx];
            Bitmap = new WriteableBitmap(_widthPx, _heightPx, 96, 96, PixelFormats.Bgra32, null);
        }

        public void Render(double baseTime, bool isRed, bool isDark, bool isHovered)
        {
            int bgR = isDark ? 8 : 250;
            int bgG = isDark ? 9 : 251;
            int bgB = isDark ? 13 : 253;
            int specR = isDark ? 248 : 9;
            int specG = isDark ? 250 : 9;
            int specB = isDark ? 252 : 11;
            int auraR = isDark ? 75 : 148;
            int auraG = isDark ? 85 : 163;
            int auraB = isDark ? 99 : 184;
            byte[,] stops = isRed
                ? (isDark ? RedDarkStops : RedLightStops)
                : (isDark ? BlueDarkStops : BlueLightStops);

            AsciiGlyphAtlas.FillRect(_frameBuf, bgR, bgG, bgB);

            double t = baseTime * (isHovered ? 1.55 : 1.0);
            double cx = _widthPx * 0.5;
            double cy = _heightPx * 0.5;
            const double angle = -0.36;
            double cosA = Math.Cos(angle);
            double sinA = Math.Sin(angle);
            double halfLen = Math.Min(_widthPx * 0.16, 44.0);
            double rad = Math.Min(_heightPx * 0.24, 22.0);
            int rampLen = AsciiGlyphAtlas.BodyRamp.Length;

            for (int r = 0; r < Rows; r++)
            {
                double py = (r + 0.5) * _atlas.CellH;
                for (int c = 0; c < Cols; c++)
                {
                    double px = (c + 0.5) * _atlas.CellW;
                    double dx = px - cx;
                    double dy = py - cy;
                    double rx = dx * cosA + dy * sinA;
                    double ry = -dx * sinA + dy * cosA;

                    double clx = Math.Max(-halfLen, Math.Min(halfLen, rx));
                    double sd = Math.Sqrt((rx - clx) * (rx - clx) + ry * ry) - rad;
                    double flowN = AsciiGlyphAtlas.Noise2(c * 0.3 - t * 0.7, r * 0.4 + t * 0.5);

                    if (sd <= 1.2)
                    {
                        double normY = Math.Max(-1.0, Math.Min(1.0, ry / rad));
                        double nz = Math.Sqrt(Math.Max(0.05, 1.0 - normY * normY));
                        double topLight = Math.Max(0.0, -normY * 0.65 + nz * 0.55);
                        bool isSeam = Math.Abs(rx) < 3.0;
                        double rightHalf = rx >= 0 ? 0.14 : 0.0;

                        double sweep = Math.Sin(rx * 0.08 - t * 2.4 + ry * 0.06 + flowN * 1.1);
                        double gleam = Math.Pow(Math.Max(0.0, sweep), 3.2);
                        double lum = Math.Min(1.0, Math.Max(0.0, 0.34 + topLight * 0.48 + rightHalf + gleam * 0.38 - (isSeam ? 0.22 : 0.0)));

                        int rIdx = Math.Min(rampLen - 1, Math.Max(2, (int)(lum * (rampLen - 1))));
                        char ch = isSeam ? '\u2502' : AsciiGlyphAtlas.BodyRamp[rIdx];
                        if (ch != ' ')
                        {
                            int fr, fg, fb;
                            if (gleam > 0.78 && topLight > 0.45 && !isSeam)
                            {
                                fr = specR; fg = specG; fb = specB;
                            }
                            else
                            {
                                AsciiGlyphAtlas.SampleRamp(stops, lum * 0.92, out fr, out fg, out fb);
                            }
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, ch, fr, fg, fb, bgR, bgG, bgB);
                        }
                    }
                    else if (sd < 18.0)
                    {
                        int driftR = r + (int)Math.Floor(t * 2.2);
                        double sp = AsciiGlyphAtlas.Hash2(c + (isRed ? 53 : 11), driftR);
                        if (sp > 0.89)
                        {
                            char sCh = AsciiGlyphAtlas.SparkGlyphs[((c + driftR) % 5 + 5) % 5];
                            int fr, fg, fb;
                            AsciiGlyphAtlas.SampleRamp(stops, 0.72, out fr, out fg, out fb);
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, sCh, fr, fg, fb, bgR, bgG, bgB);
                        }
                        else if (sp > 0.78 && sd < 9.0)
                        {
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, '\u00B7', auraR, auraG, auraB, bgR, bgG, bgB);
                        }
                    }
                }
            }

            Bitmap.WritePixels(new Int32Rect(0, 0, _widthPx, _heightPx), _frameBuf, _widthPx * 4, 0);
        }
    }

    /// <summary>
    /// Live 5-node ASCII signal topology and scan-wave visualizer for Smart Diagnostics.
    /// Node states: 0=Pending, 1=Running, 2=Ok, 3=Warn, 4=Error.
    /// </summary>
    internal sealed class AsciiDiagScannerEngine
    {
        private static readonly byte[,] CobaltStops = new byte[,]
        {
            { 30, 58, 138 }, { 29, 78, 216 }, { 59, 130, 246 }, { 96, 165, 250 }, { 186, 230, 253 }
        };
        private static readonly byte[,] EmeraldDarkStops = new byte[,]
        {
            { 6, 78, 59 }, { 4, 120, 87 }, { 16, 185, 129 }, { 52, 211, 153 }, { 209, 250, 229 }
        };
        private static readonly byte[,] EmeraldLightStops = new byte[,]
        {
            { 6, 78, 59 }, { 20, 83, 45 }, { 4, 120, 87 }, { 5, 150, 105 }, { 13, 148, 136 }
        };
        private static readonly byte[,] AmberDarkStops = new byte[,]
        {
            { 69, 26, 3 }, { 146, 64, 14 }, { 217, 119, 6 }, { 251, 191, 36 }, { 254, 243, 199 }
        };
        private static readonly byte[,] AmberLightStops = new byte[,]
        {
            { 120, 53, 15 }, { 146, 64, 14 }, { 180, 83, 9 }, { 217, 119, 6 }, { 234, 88, 12 }
        };

        private static readonly double[] NodeX = new double[] { 0.10, 0.30, 0.50, 0.70, 0.90 };
        private static readonly string[] NodeLabels = new string[] { "ISP", "NET", "PWP4", "AI", "IDE" };

        private const int Cols = 72;
        private const int Rows = 10;
        private readonly AsciiGlyphAtlas _atlas;
        private readonly int _widthPx;
        private readonly int _heightPx;
        private readonly int[] _frameBuf;

        public WriteableBitmap Bitmap { get; private set; }

        public AsciiDiagScannerEngine()
        {
            _atlas = new AsciiGlyphAtlas(8, 12, 8.2f);
            _widthPx = Cols * _atlas.CellW;
            _heightPx = Rows * _atlas.CellH;
            _frameBuf = new int[_widthPx * _heightPx];
            Bitmap = new WriteableBitmap(_widthPx, _heightPx, 96, 96, PixelFormats.Bgra32, null);
        }

        public void Render(double t, int[] nodeStates, bool isFixing, bool isDark)
        {
            int bgR = isDark ? 8 : 250;
            int bgG = isDark ? 9 : 251;
            int bgB = isDark ? 13 : 253;
            int specR = isDark ? 248 : 9;
            int specG = isDark ? 250 : 9;
            int specB = isDark ? 252 : 11;
            int slateR = isDark ? 75 : 148;
            int slateG = isDark ? 85 : 163;
            int slateB = isDark ? 99 : 184;

            byte[,] emStops = isDark ? EmeraldDarkStops : EmeraldLightStops;
            byte[,] amStops = isDark ? AmberDarkStops : AmberLightStops;

            AsciiGlyphAtlas.FillRect(_frameBuf, bgR, bgG, bgB);

            const double cy = 0.42;
            double aspectScaleX = (_widthPx / (double)_heightPx) * 0.56;
            int rampLen = AsciiGlyphAtlas.BodyRamp.Length;

            for (int r = 0; r < Rows - 1; r++)
            {
                double ny = r / (double)(Rows - 2);
                for (int c = 0; c < Cols; c++)
                {
                    double nx = c / (double)(Cols - 1);
                    double flowN = AsciiGlyphAtlas.Noise2(c * 0.25 - t * 0.9, r * 0.4 + t * 0.4);

                    double bestDist = 99.0;
                    int bestIdx = 0;
                    for (int i = 0; i < 5; i++)
                    {
                        double dx = (nx - NodeX[i]) * aspectScaleX;
                        double dy = ny - cy;
                        double d = Math.Sqrt(dx * dx + dy * dy);
                        if (d < bestDist) { bestDist = d; bestIdx = i; }
                    }

                    if (bestDist < 0.175)
                    {
                        int st = (nodeStates != null && bestIdx < nodeStates.Length) ? nodeStates[bestIdx] : 0;
                        int fr = slateR, fg = slateG, fb = slateB;
                        double lum = 0.34 + flowN * 0.22;

                        if (isFixing && (st == 3 || st == 4 || st == 1))
                        {
                            byte[,] fixStops = ((int)Math.Floor(t * 10) % 2 == 0) ? CobaltStops : emStops;
                            AsciiGlyphAtlas.SampleRamp(fixStops, 0.45 + flowN * 0.5, out fr, out fg, out fb);
                            lum = 0.72 + Math.Sin(t * 8.0) * 0.2;
                        }
                        else if (st == 3 || st == 4)
                        {
                            double pulse = 0.55 + 0.45 * Math.Sin(t * 4.5);
                            AsciiGlyphAtlas.SampleRamp(amStops, 0.35 + pulse * 0.55, out fr, out fg, out fb);
                            lum = 0.55 + pulse * 0.35;
                        }
                        else if (st == 2)
                        {
                            double shimmer = Math.Sin(nx * 14.0 - t * 2.6 + flowN * 2.0) * 0.5 + 0.5;
                            AsciiGlyphAtlas.SampleRamp(emStops, 0.30 + shimmer * 0.65, out fr, out fg, out fb);
                            lum = 0.50 + shimmer * 0.45;
                        }
                        else if (st == 1)
                        {
                            double sweep = Math.Sin((ny - ((t * 1.4) % 1.0)) * 10.0) * 0.5 + 0.5;
                            if (sweep > 0.80) { fr = specR; fg = specG; fb = specB; }
                            else AsciiGlyphAtlas.SampleRamp(CobaltStops, 0.35 + sweep * 0.6, out fr, out fg, out fb);
                            lum = 0.45 + sweep * 0.50;
                        }

                        int idx = Math.Min(rampLen - 1, Math.Max(2, (int)((1.0 - bestDist / 0.175) * lum * (rampLen - 1))));
                        char ch = AsciiGlyphAtlas.BodyRamp[idx];
                        if (ch != ' ') _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, ch, fr, fg, fb, bgR, bgG, bgB);
                        continue;
                    }

                    if (Math.Abs(ny - cy) < 0.095 && nx > NodeX[0] && nx < NodeX[4])
                    {
                        int segIdx = Math.Min(3, Math.Max(0, (int)Math.Floor((nx - 0.10) / 0.20)));
                        int leftSt = (nodeStates != null && segIdx < nodeStates.Length) ? nodeStates[segIdx] : 0;
                        int rightSt = (nodeStates != null && segIdx + 1 < nodeStates.Length) ? nodeStates[segIdx + 1] : 0;
                        bool pkt = ((c - (int)Math.Floor(t * 14.0)) % 5 + 5) % 5 == 0;

                        if (leftSt >= 3 || rightSt >= 3)
                        {
                            int fr, fg, fb;
                            AsciiGlyphAtlas.SampleRamp(amStops, pkt ? 0.85 : 0.45, out fr, out fg, out fb);
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, pkt ? '!' : '~', fr, fg, fb, bgR, bgG, bgB);
                        }
                        else if (leftSt == 2 && rightSt >= 1)
                        {
                            int fr, fg, fb;
                            AsciiGlyphAtlas.SampleRamp(emStops, pkt ? 0.85 : 0.45, out fr, out fg, out fb);
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, pkt ? '\u25B8' : '\u2500', fr, fg, fb, bgR, bgG, bgB);
                        }
                        else
                        {
                            _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, '\u00B7', slateR, slateG, slateB, bgR, bgG, bgB);
                        }
                        continue;
                    }

                    double waveY = cy + Math.Sin(nx * 12.0 - t * 2.2) * 0.26;
                    if (Math.Abs(ny - waveY) < 0.06 && flowN > 0.55)
                    {
                        _atlas.BlitGlyph(_frameBuf, _widthPx, c, r, flowN > 0.72 ? ':' : '\u00B7', slateR, slateG, slateB, bgR, bgG, bgB);
                    }
                }
            }

            // Bottom row: crisp node labels centered under each ASCII node
            for (int i = 0; i < 5; i++)
            {
                int st = (nodeStates != null && i < nodeStates.Length) ? nodeStates[i] : 0;
                int lr = slateR, lg = slateG, lb = slateB;
                if (st == 3 || st == 4) AsciiGlyphAtlas.SampleRamp(amStops, 0.72, out lr, out lg, out lb);
                else if (st == 2) AsciiGlyphAtlas.SampleRamp(emStops, 0.72, out lr, out lg, out lb);
                else if (st == 1) AsciiGlyphAtlas.SampleRamp(CobaltStops, 0.72, out lr, out lg, out lb);

                _atlas.BlitTextCentered(_frameBuf, _widthPx, NodeX[i], Cols, Rows - 1, NodeLabels[i], lr, lg, lb, bgR, bgG, bgB);
            }

            Bitmap.WritePixels(new Int32Rect(0, 0, _widthPx, _heightPx), _frameBuf, _widthPx * 4, 0);
        }
    }
}
