using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace PixelTunnel
{
    /// <summary>
    /// Векторный потоковый шифр для заголовков PWP-3 / PWP-2 и открытого TCP-фоллбэка.
    /// Побайтово совместим с Go-сервером PixelCore v3.0 и Python-сервером v2.0.
    /// </summary>
    internal sealed class PixelStreamCipher
    {
        private readonly byte[] _keyBuffer;
        private uint _counter = 0;
        private byte[] _keystreamPad = new byte[0];
        private int _padIndex = 0;
        private readonly SHA256 _sha = SHA256.Create();

        public const uint HardBlockLimit = 0xE0000000u;
        public uint BlockCounter { get { return _counter; } }

        public PixelStreamCipher(string key, string salt)
        {
            byte[] k = Encoding.UTF8.GetBytes(key);
            byte[] s = Encoding.UTF8.GetBytes(salt);
            _keyBuffer = new byte[k.Length + s.Length];
            Buffer.BlockCopy(k, 0, _keyBuffer, 0, k.Length);
            Buffer.BlockCopy(s, 0, _keyBuffer, k.Length, s.Length);
        }

        public void ProcessBytes(byte[] buf, int offset, int count)
        {
            byte[] blk = null;
            for (int i = 0; i < count; i++)
            {
                if (_padIndex >= _keystreamPad.Length)
                {
                    if (_counter >= HardBlockLimit)
                    {
                        throw new IOException("Mux cipher block limit reached (0xE0000000)");
                    }
                    if (blk == null)
                    {
                        blk = new byte[_keyBuffer.Length + 4];
                        Buffer.BlockCopy(_keyBuffer, 0, blk, 0, _keyBuffer.Length);
                    }
                    blk[_keyBuffer.Length]     = (byte)((_counter >> 24) & 0xFF);
                    blk[_keyBuffer.Length + 1] = (byte)((_counter >> 16) & 0xFF);
                    blk[_keyBuffer.Length + 2] = (byte)((_counter >> 8) & 0xFF);
                    blk[_keyBuffer.Length + 3] = (byte)(_counter & 0xFF);
                    _counter++;
                    _keystreamPad = _sha.ComputeHash(blk);
                    _padIndex = 0;
                }
                buf[offset + i] ^= _keystreamPad[_padIndex++];
            }
        }
    }

    /// <summary>
    /// Anti-DPI Shield v2: адаптивная TCP/TLS-фрагментация пакета ClientHello (под SslStream) без драйверов WinDivert.
    /// Профиль 0 (StandardSplit): быстрый 3-4 сегментный разрез заголовка + середины SNI.
    /// Профиль 1 (SniMicroChunk): микро-нарезка (7..19 байт) вокруг расширения SNI против глубоких ТСПУ-буферов.
    /// Профиль 2 (TlsRecordSplit): пересборка одного TLS Handshake Record (0x16 0x03) в 2 валидных RFC 5246 рекорда прямо по SNI.
    /// После установки TLS 1.3 работает в прозрачном режиме с нулевым оверхедом.
    /// </summary>
    internal sealed class DpiFragmentingStream : Stream
    {
        private readonly NetworkStream _inner;
        private readonly byte[] _sniBytes;
        private bool _clientHelloSplitDone = false;
        public bool FragmentActive = true;
        public int Profile = 0;

        public DpiFragmentingStream(NetworkStream inner, string sni, int profile = 0)
        {
            _inner = inner;
            _sniBytes = string.IsNullOrEmpty(sni) ? null : Encoding.ASCII.GetBytes(sni);
            Profile = profile;
        }

        public override bool CanRead { get { return _inner.CanRead; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return _inner.CanWrite; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override void Flush()
        {
            _inner.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return _inner.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _inner.Read(buffer, offset, count);
        }

        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            return _inner.BeginRead(buffer, offset, count, callback, state);
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            return _inner.EndRead(asyncResult);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _inner.ReadAsync(buffer, offset, count, cancellationToken);
        }

        private int FindSniMidpointOffset(byte[] buf, int offset, int count)
        {
            if (_sniBytes == null || _sniBytes.Length < 4) return -1;
            int end = offset + count - _sniBytes.Length;
            for (int i = offset; i <= end; i++)
            {
                if (buf[i] != _sniBytes[0]) continue;
                bool ok = true;
                for (int j = 1; j < _sniBytes.Length; j++)
                {
                    if (buf[i + j] != _sniBytes[j]) { ok = false; break; }
                }
                if (ok)
                {
                    return (i - offset) + (_sniBytes.Length / 2);
                }
            }
            return -1;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!FragmentActive || count < 28)
            {
                _inner.Write(buffer, offset, count);
                return;
            }

            bool isTlsRecord = (buffer[offset] == 0x16 && buffer[offset + 1] == 0x03);
            bool isClientHello = !_clientHelloSplitDone && isTlsRecord && count >= 40 && buffer[offset + 5] == 0x01;
            int sniMid = isTlsRecord ? FindSniMidpointOffset(buffer, offset, count) : -1;

            // Профиль 2 (TlsRecordSplit): переписываем только открытый ClientHello (0x16 .. 0x01) в 2 независимых TLS-рекорда по границе SNI
            if (Profile == 2 && isClientHello)
            {
                int recLen = (buffer[offset + 3] << 8) | buffer[offset + 4];
                if (5 + recLen == count && recLen > 24)
                {
                    _clientHelloSplitDone = true;
                    int part1Payload = (sniMid > 11 && sniMid < count - 8) ? (sniMid - 5) : (recLen / 2);
                    int part2Payload = recLen - part1Payload;
                    byte verMaj = buffer[offset + 1];
                    byte verMin = buffer[offset + 2];

                    byte[] rec1 = new byte[5 + part1Payload];
                    rec1[0] = 0x16;
                    rec1[1] = verMaj;
                    rec1[2] = verMin;
                    rec1[3] = (byte)((part1Payload >> 8) & 0xFF);
                    rec1[4] = (byte)(part1Payload & 0xFF);
                    Buffer.BlockCopy(buffer, offset + 5, rec1, 5, part1Payload);

                    byte[] rec2 = new byte[5 + part2Payload];
                    rec2[0] = 0x16;
                    rec2[1] = verMaj;
                    rec2[2] = verMin;
                    rec2[3] = (byte)((part2Payload >> 8) & 0xFF);
                    rec2[4] = (byte)(part2Payload & 0xFF);
                    Buffer.BlockCopy(buffer, offset + 5 + part1Payload, rec2, 5, part2Payload);

                    _inner.Write(rec1, 0, 2);
                    _inner.Flush();
                    Thread.Sleep(1);

                    _inner.Write(rec1, 2, rec1.Length - 2);
                    _inner.Flush();
                    Thread.Sleep(1);

                    _inner.Write(rec2, 0, rec2.Length);
                    _inner.Flush();
                    return;
                }
            }

            // Профиль 1 (SniMicroChunk): мелкая TCP-нарезка (7..19 байт) вплоть до конца SNI
            if (Profile == 1)
            {
                int targetEnd = (sniMid > 12) ? Math.Min(count, sniMid + 18) : Math.Min(count, 160);
                int pos = 0;
                _inner.Write(buffer, offset, 2);
                _inner.Flush();
                Thread.Sleep(1);
                pos = 2;

                int stepSeed = buffer[offset + 5];
                while (pos < targetEnd)
                {
                    int slice = 7 + ((stepSeed + pos) % 13);
                    if (sniMid > pos && pos + slice > sniMid)
                    {
                        slice = Math.Max(2, sniMid - pos);
                    }
                    if (pos + slice > targetEnd) slice = targetEnd - pos;
                    _inner.Write(buffer, offset + pos, slice);
                    _inner.Flush();
                    if (Math.Abs(pos - sniMid) <= 16) Thread.Sleep(1);
                    pos += slice;
                }

                if (pos < count)
                {
                    _inner.Write(buffer, offset + pos, count - pos);
                    _inner.Flush();
                }
                return;
            }

            // Профиль 0 (StandardSplit): быстрый разрез на микро-заголовок + середину SNI
            int cut1 = 2;
            int cut2 = (sniMid > cut1 + 4 && sniMid < count - 6)
                ? sniMid
                : Math.Min(count - 6, 19 + (buffer[offset + 5] % 17));
            int cut3 = Math.Min(count - 2, cut2 + 11 + (buffer[offset + 7] % 13));

            _inner.Write(buffer, offset, cut1);
            _inner.Flush();
            Thread.Sleep(1);

            _inner.Write(buffer, offset + cut1, cut2 - cut1);
            _inner.Flush();
            Thread.Sleep(1);

            if (cut3 > cut2 && cut3 < count)
            {
                _inner.Write(buffer, offset + cut2, cut3 - cut2);
                _inner.Flush();
                _inner.Write(buffer, offset + cut3, count - cut3);
            }
            else
            {
                _inner.Write(buffer, offset + cut2, count - cut2);
            }
            _inner.Flush();
        }

        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            if (!FragmentActive || count < 28)
            {
                return _inner.BeginWrite(buffer, offset, count, callback, state);
            }
            Write(buffer, offset, count);
            return _inner.BeginWrite(buffer, offset, 0, callback, state);
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            _inner.EndWrite(asyncResult);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (!FragmentActive)
            {
                return _inner.WriteAsync(buffer, offset, count, cancellationToken);
            }
            Write(buffer, offset, count);
            return Task.FromResult(0);
        }

        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { _inner.Dispose(); } catch { }
            }
            base.Dispose(disposing);
        }
    }

    public sealed class NodeBenchmarkResult
    {
        public string Name;
        public string Region;
        public string Host;
        public int Port;
        public bool UseTls;
        public bool SupportsMuxV3;
        public bool Ok;
        public int HandshakeMs;
        public bool AntiFreezeOk;
        public string EffectiveSni;
        public string DpiProfile;
        public string Error;
        public bool IsBestSelected;
    }

    internal sealed class PixelServerNode
    {
        public string Name;
        public string Region = "nl";
        public string Host;
        public int Port;
        public string Secret;
        public string Sni;
        public string UpgradePath = "/api/v3/telemetry/mux";
        public bool UseTls = true;
        public bool SupportsMuxV3 = true;
        public bool EnableDpiSplit = true;
        public bool IsCloudflareWs = false;
        public bool IsOnline = true;
        public bool ProbeVerified = false;
        public int LatencyMs = 20;
        public int FailCount = 0;
        public DateTime LastHealthMeasuredUtc = DateTime.MinValue;
    }

    internal sealed class PixelWarmTunnel : IDisposable
    {
        public TcpClient Tcp;
        public Stream Transport;
        public PixelStreamCipher Encryptor;
        public PixelStreamCipher Decryptor;
        public bool NativeTlsBulk;
        public PixelServerNode Node;
        public DateTime CreatedUtc;

        public bool IsFreshAndAlive()
        {
            try
            {
                if (Tcp == null || !Tcp.Connected || Tcp.Client == null) return false;
                if ((DateTime.UtcNow - CreatedUtc).TotalSeconds > 48.0) return false;
                if (Tcp.Client.Poll(0, SelectMode.SelectRead) && Tcp.Client.Available == 0) return false;
                return true;
            }
            catch { return false; }
        }

        public void Dispose()
        {
            try { if (Transport != null) Transport.Close(); } catch { }
            try { if (Tcp != null) Tcp.Close(); } catch { }
        }
    }

    internal struct MuxRxChunk
    {
        public byte[] Data;
        public bool IsFin;
        public bool IsRst;
    }

    /// <summary>
    /// Логический мультиплексированный поток PWP-3 с индивидуальным окном Flow Control (256 КБ).
    /// </summary>
    internal sealed class ClientMuxStream : IDisposable
    {
        public const int InitialWindow = 262144;
        public const int WindowUpdateStep = 65536;

        public readonly uint StreamId;
        public readonly Pwp3MuxClient Session;
        public bool IsProbeStream;

        private readonly ConcurrentQueue<MuxRxChunk> _rxQueue = new ConcurrentQueue<MuxRxChunk>();
        private readonly SemaphoreSlim _rxSignal = new SemaphoreSlim(0);

        private readonly object _winLock = new object();
        private readonly SemaphoreSlim _winWake = new SemaphoreSlim(0);
        private long _sendWindow = InitialWindow;
        private long _unackedDrained = 0;
        private volatile bool _closed = false;
        private volatile bool _synAcked = false;

        public bool IsClosed { get { return _closed; } }
        public bool IsSynAcked { get { return _synAcked; } }

        public ClientMuxStream(uint streamId, Pwp3MuxClient session, int initialConsumedBytes)
        {
            StreamId = streamId;
            Session = session;
            if (initialConsumedBytes > 0)
            {
                _sendWindow -= initialConsumedBytes;
            }
        }

        public void MarkSynAcked()
        {
            _synAcked = true;
        }

        public void EnqueueInboundData(byte[] data)
        {
            if (_closed) return;
            _rxQueue.Enqueue(new MuxRxChunk { Data = data });
            try { _rxSignal.Release(); } catch { }
        }

        public void EnqueueInboundFin()
        {
            if (_closed) return;
            _rxQueue.Enqueue(new MuxRxChunk { IsFin = true });
            try { _rxSignal.Release(); } catch { }
        }

        public void EnqueueInboundRst()
        {
            if (_closed) return;
            _closed = true;
            _rxQueue.Enqueue(new MuxRxChunk { IsRst = true });
            try { _rxSignal.Release(); } catch { }
            SignalWindowWake();
        }

        public void AddSendWindow(uint delta)
        {
            if (delta == 0 || _closed) return;
            lock (_winLock)
            {
                _sendWindow += delta;
            }
            SignalWindowWake();
        }

        private void SignalWindowWake()
        {
            try
            {
                if (_winWake.CurrentCount == 0) _winWake.Release();
            }
            catch { }
        }

        public async Task<int> AcquireSendWindowAsync(int desired, CancellationToken token)
        {
            while (!_closed && !Session.IsClosed && !token.IsCancellationRequested)
            {
                lock (_winLock)
                {
                    if (_sendWindow > 0)
                    {
                        int grant = desired;
                        if (grant > _sendWindow) grant = (int)_sendWindow;
                        _sendWindow -= grant;
                        return grant;
                    }
                }
                await _winWake.WaitAsync(250, token).ConfigureAwait(false);
            }
            return 0;
        }

        public async Task<MuxRxChunk> DequeueInboundAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                MuxRxChunk item;
                if (_rxQueue.TryDequeue(out item))
                {
                    return item;
                }
                if (_closed || Session.IsClosed)
                {
                    return new MuxRxChunk { IsRst = true };
                }
                await _rxSignal.WaitAsync(500, token).ConfigureAwait(false);
            }
            return new MuxRxChunk { IsRst = true };
        }

        public void NotifyBytesWrittenToLocal(int count)
        {
            if (count <= 0 || _closed || Session.IsClosed) return;
            uint sendDelta = 0;
            lock (_winLock)
            {
                _unackedDrained += count;
                if (_unackedDrained >= WindowUpdateStep)
                {
                    sendDelta = (uint)_unackedDrained;
                    _unackedDrained = 0;
                }
            }
            if (sendDelta > 0)
            {
                byte[] winPayload = new byte[4];
                winPayload[0] = (byte)((sendDelta >> 24) & 0xFF);
                winPayload[1] = (byte)((sendDelta >> 16) & 0xFF);
                winPayload[2] = (byte)((sendDelta >> 8) & 0xFF);
                winPayload[3] = (byte)(sendDelta & 0xFF);
                try
                {
                    Session.WriteFrame(Pwp3MuxClient.FrameWinUpdate, StreamId, 0, winPayload, 0, 4, 0);
                }
                catch { }
            }
        }

        public void CloseFromSessionShutdown()
        {
            _closed = true;
            _rxQueue.Enqueue(new MuxRxChunk { IsRst = true });
            try { _rxSignal.Release(); } catch { }
            SignalWindowWake();
        }

        public void Dispose()
        {
            _closed = true;
            Session.UnregisterStream(StreamId);
            SignalWindowWake();
        }
    }

    /// <summary>
    /// Мультиплексированная сессия PWP-3 поверх одного постоянного соединения TLS 1.3.
    /// Поддерживает сотни параллельных TCP-потоков (0-RTT SYN_TCP), индивидуальный Flow Control
    /// и туннелирование UDP-дейтаграмм (FRAME_UDP_DATA 0x08).
    /// </summary>
    internal sealed class Pwp3MuxClient : IDisposable
    {
        public const byte FrameSynTcp    = 0x01;
        public const byte FrameData      = 0x02;
        public const byte FrameFin       = 0x03;
        public const byte FrameRst       = 0x04;
        public const byte FrameWinUpdate = 0x05;
        public const byte FramePing      = 0x06;
        public const byte FramePong      = 0x07;
        public const byte FrameUdpData   = 0x08;
        public const byte FrameSynAck    = 0x09;

        public const int MaxChunkSize = 32768;

        public readonly string LaneName;
        public readonly PixelServerNode Node;
        public readonly bool IsBulkLane;

        private readonly TcpClient _tcp;
        private readonly Stream _transport;
        private readonly PixelStreamCipher _encryptor;
        private readonly PixelStreamCipher _decryptor;
        private readonly bool _nativeTlsBulk;
        private readonly object _writeLock = new object();
        private readonly RNGCryptoServiceProvider _rng = new RNGCryptoServiceProvider();

        private readonly ConcurrentDictionary<uint, ClientMuxStream> _streams = new ConcurrentDictionary<uint, ClientMuxStream>();
        private readonly ConcurrentDictionary<uint, Action<byte[], int>> _udpHandlers = new ConcurrentDictionary<uint, Action<byte[], int>>();

        private int _nextStreamId = 1;
        private volatile bool _closed = false;
        private long _lastActivityTicks = DateTime.UtcNow.Ticks;
        private int _lastRttMs;

        public bool IsClosed
        {
            get
            {
                if (_closed) return true;
                try
                {
                    if (_tcp == null || !_tcp.Connected || _tcp.Client == null) return true;
                }
                catch { return true; }
                return false;
            }
        }

        public bool IsCipherLimitNear
        {
            get
            {
                const uint SoftRetireThreshold = 0xD0000000u;
                if (_encryptor != null && _encryptor.BlockCounter >= SoftRetireThreshold) return true;
                if (_decryptor != null && _decryptor.BlockCounter >= SoftRetireThreshold) return true;
                return false;
            }
        }

        public int ActiveStreamCount { get { return _streams.Count; } }
        public int ActiveUdpCount { get { return _udpHandlers.Count; } }
        public int LastRttMs { get { return _lastRttMs; } }
        public DateTime LastActivityUtc { get { return new DateTime(Interlocked.Read(ref _lastActivityTicks), DateTimeKind.Utc); } }

        public Pwp3MuxClient(
            string laneName,
            PixelServerNode node,
            TcpClient tcp,
            Stream transport,
            PixelStreamCipher encryptor,
            PixelStreamCipher decryptor,
            bool nativeTlsBulk)
        {
            LaneName = laneName;
            Node = node;
            IsBulkLane = (laneName != null && laneName.StartsWith("Lane1", StringComparison.OrdinalIgnoreCase));
            _tcp = tcp;
            _transport = transport;
            _encryptor = encryptor;
            _decryptor = decryptor;
            _nativeTlsBulk = nativeTlsBulk;
            _lastRttMs = node.LatencyMs;

            _tcp.ReceiveTimeout = 240000;
            _tcp.SendTimeout = 45000;

            Thread readerThread = new Thread(ReadLoop);
            readerThread.IsBackground = true;
            readerThread.Name = "PWP3-" + laneName + "-" + node.Name;
            readerThread.Start();
        }

        public uint AllocateId()
        {
            int raw = Interlocked.Add(ref _nextStreamId, 2);
            uint id = (uint)(raw & 0x7FFFFFFF);
            if (id == 0) id = 1;
            return id;
        }

        public ClientMuxStream OpenTcpStream(string targetHost, int targetPort, byte[] initialPayload, bool isProbe = false)
        {
            if (IsClosed) throw new IOException("Mux session closed");

            byte[] hostBytes = Encoding.UTF8.GetBytes(targetHost);
            if (hostBytes.Length == 0 || hostBytes.Length > 250)
            {
                throw new ArgumentException("Invalid target host");
            }

            int initLen = (initialPayload != null) ? initialPayload.Length : 0;
            int firstSlice = Math.Min(initLen, 24576);
            int synPayloadLen = 1 + hostBytes.Length + 2 + firstSlice;
            byte[] synPayload = new byte[synPayloadLen];
            synPayload[0] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, synPayload, 1, hostBytes.Length);
            synPayload[1 + hostBytes.Length] = (byte)((targetPort >> 8) & 0xFF);
            synPayload[1 + hostBytes.Length + 1] = (byte)(targetPort & 0xFF);
            if (firstSlice > 0)
            {
                Buffer.BlockCopy(initialPayload, 0, synPayload, 1 + hostBytes.Length + 2, firstSlice);
            }

            uint streamId = AllocateId();
            ClientMuxStream stream = new ClientMuxStream(streamId, this, initLen);
            stream.IsProbeStream = isProbe;
            _streams[streamId] = stream;

            try
            {
                WriteFrame(FrameSynTcp, streamId, 0, synPayload, 0, synPayloadLen, 20);
                if (firstSlice > 0 && !isProbe)
                {
                    PixelCoreService.AddBytesUpInternal(firstSlice);
                }
                if (initLen > firstSlice)
                {
                    int rem = initLen - firstSlice;
                    WriteFrame(FrameData, streamId, 0, initialPayload, firstSlice, rem, 0);
                    if (!isProbe) PixelCoreService.AddBytesUpInternal(rem);
                }
                Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);
                return stream;
            }
            catch
            {
                ClientMuxStream removed;
                _streams.TryRemove(streamId, out removed);
                Shutdown();
                throw;
            }
        }

        public void UnregisterStream(uint streamId)
        {
            ClientMuxStream removed;
            _streams.TryRemove(streamId, out removed);
        }

        public uint RegisterUdpAssociation(Action<byte[], int> inboundCallback)
        {
            uint id = AllocateId();
            _udpHandlers[id] = inboundCallback;
            Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);
            return id;
        }

        public void UnregisterUdpAssociation(uint assocId)
        {
            Action<byte[], int> removed;
            if (_udpHandlers.TryRemove(assocId, out removed))
            {
                try
                {
                    WriteFrame(FrameRst, assocId, 0, new byte[] { 0x00 }, 0, 1, 0);
                }
                catch { }
            }
        }

        public void SendPing()
        {
            if (IsClosed) return;
            long ticks = Stopwatch.GetTimestamp();
            byte[] payload = BitConverter.GetBytes(ticks);
            WriteFrame(FramePing, 0, 0, payload, 0, payload.Length, 16);
        }

        public void WriteFrame(byte frameType, uint streamId, byte flags, byte[] payload, int offset, int count, int randomPadMax)
        {
            if (_closed) throw new ObjectDisposedException("Pwp3MuxClient");
            if (count < 0 || count > 65535) throw new ArgumentOutOfRangeException("count");

            int padLen = 0;
            if (randomPadMax > 0)
            {
                byte[] rb = new byte[1];
                _rng.GetBytes(rb);
                padLen = 8 + (rb[0] % randomPadMax);
                if (padLen > 60) padLen = 60;
            }

            int totalLen = 9 + count + padLen;
            byte[] frame = new byte[totalLen];
            frame[0] = frameType;
            frame[1] = (byte)((streamId >> 24) & 0xFF);
            frame[2] = (byte)((streamId >> 16) & 0xFF);
            frame[3] = (byte)((streamId >> 8) & 0xFF);
            frame[4] = (byte)(streamId & 0xFF);
            frame[5] = (byte)((count >> 8) & 0xFF);
            frame[6] = (byte)(count & 0xFF);
            frame[7] = flags;
            frame[8] = (byte)padLen;

            if (count > 0 && payload != null)
            {
                Buffer.BlockCopy(payload, offset, frame, 9, count);
            }
            if (padLen > 0)
            {
                byte[] pad = new byte[padLen];
                _rng.GetBytes(pad);
                Buffer.BlockCopy(pad, 0, frame, 9 + count, padLen);
            }

            lock (_writeLock)
            {
                if (_closed) throw new ObjectDisposedException("Pwp3MuxClient");
                if (_encryptor != null && _encryptor.BlockCounter >= 0xDFF00000u)
                {
                    Shutdown();
                    throw new IOException("Mux encryptor cipher block threshold reached (0xE0000000)");
                }
                if (_nativeTlsBulk)
                {
                    _encryptor.ProcessBytes(frame, 0, 9);
                }
                else
                {
                    _encryptor.ProcessBytes(frame, 0, totalLen);
                }
                _transport.Write(frame, 0, totalLen);
                _transport.Flush();
            }
        }

        private void ReadLoop()
        {
            byte[] hdr = new byte[9];
            byte[] bodyBuf = new byte[65536 + 64];
            try
            {
                while (!_closed)
                {
                    if (_decryptor != null && _decryptor.BlockCounter >= 0xDFF00000u)
                    {
                        throw new IOException("Mux decryptor cipher block threshold reached (0xE0000000)");
                    }
                    PixelCoreService.ReadExactInternal(_transport, hdr, 0, 9);
                    _decryptor.ProcessBytes(hdr, 0, 9);

                    byte fType = hdr[0];
                    uint streamId = ((uint)hdr[1] << 24) | ((uint)hdr[2] << 16) | ((uint)hdr[3] << 8) | hdr[4];
                    int payloadLen = (hdr[5] << 8) | hdr[6];
                    int padLen = hdr[8];
                    int bodyTotal = payloadLen + padLen;

                    if (bodyTotal > bodyBuf.Length)
                    {
                        bodyBuf = new byte[bodyTotal];
                    }
                    if (bodyTotal > 0)
                    {
                        PixelCoreService.ReadExactInternal(_transport, bodyBuf, 0, bodyTotal);
                        if (!_nativeTlsBulk)
                        {
                            _decryptor.ProcessBytes(bodyBuf, 0, bodyTotal);
                        }
                    }

                    Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);

                    switch (fType)
                    {
                        case FrameData:
                            if (payloadLen > 0)
                            {
                                ClientMuxStream st;
                                if (_streams.TryGetValue(streamId, out st))
                                {
                                    if (!st.IsProbeStream)
                                    {
                                        PixelCoreService.AddLaneBytesDownInternal(payloadLen, IsBulkLane);
                                    }
                                    byte[] copy = new byte[payloadLen];
                                    Buffer.BlockCopy(bodyBuf, 0, copy, 0, payloadLen);
                                    st.EnqueueInboundData(copy);
                                }
                                else
                                {
                                    PixelCoreService.AddLaneBytesDownInternal(payloadLen, IsBulkLane);
                                }
                            }
                            break;

                        case FrameFin:
                            {
                                ClientMuxStream st;
                                if (_streams.TryGetValue(streamId, out st))
                                {
                                    st.EnqueueInboundFin();
                                }
                            }
                            break;

                        case FrameRst:
                            {
                                ClientMuxStream st;
                                if (_streams.TryRemove(streamId, out st))
                                {
                                    st.EnqueueInboundRst();
                                }
                            }
                            break;

                        case FrameWinUpdate:
                            if (payloadLen >= 4)
                            {
                                uint delta = ((uint)bodyBuf[0] << 24) | ((uint)bodyBuf[1] << 16) | ((uint)bodyBuf[2] << 8) | bodyBuf[3];
                                ClientMuxStream st;
                                if (_streams.TryGetValue(streamId, out st))
                                {
                                    st.AddSendWindow(delta);
                                }
                            }
                            break;

                        case FrameSynAck:
                            {
                                ClientMuxStream st;
                                if (_streams.TryGetValue(streamId, out st))
                                {
                                    st.MarkSynAcked();
                                }
                            }
                            break;

                        case FramePing:
                            {
                                byte[] echo = new byte[payloadLen];
                                if (payloadLen > 0) Buffer.BlockCopy(bodyBuf, 0, echo, 0, payloadLen);
                                uint pingId = streamId;
                                ThreadPool.QueueUserWorkItem(delegate
                                {
                                    try { WriteFrame(FramePong, pingId, 0, echo, 0, echo.Length, 16); } catch { }
                                });
                            }
                            break;

                        case FramePong:
                            if (payloadLen >= 8)
                            {
                                long sentTicks = BitConverter.ToInt64(bodyBuf, 0);
                                long elapsedTicks = Stopwatch.GetTimestamp() - sentTicks;
                                if (elapsedTicks >= 0)
                                {
                                    int rtt = (int)Math.Max(1L, (elapsedTicks * 1000L) / Stopwatch.Frequency);
                                    _lastRttMs = rtt;
                                    Node.LatencyMs = rtt;
                                    Node.IsOnline = true;
                                    Node.FailCount = 0;
                                    PixelCoreService.UpdateLiveNodeTelemetryInternal(Node.Name, rtt);
                                }
                            }
                            break;

                        case FrameUdpData:
                            if (payloadLen > 3)
                            {
                                PixelCoreService.AddLaneBytesDownInternal(payloadLen, IsBulkLane);
                                Action<byte[], int> cb;
                                if (_udpHandlers.TryGetValue(streamId, out cb))
                                {
                                    byte[] dgramCopy = new byte[payloadLen];
                                    Buffer.BlockCopy(bodyBuf, 0, dgramCopy, 0, payloadLen);
                                    try { cb(dgramCopy, payloadLen); } catch { }
                                }
                            }
                            break;

                        default:
                            Shutdown();
                            return;
                    }
                }
            }
            catch
            {
            }
            finally
            {
                Shutdown();
            }
        }

        public void Shutdown()
        {
            if (_closed) return;
            _closed = true;
            try { if (_transport != null) _transport.Close(); } catch { }
            try { if (_tcp != null) _tcp.Close(); } catch { }
            try { _rng.Dispose(); } catch { }

            foreach (var kv in _streams)
            {
                kv.Value.CloseFromSessionShutdown();
            }
            _streams.Clear();
            _udpHandlers.Clear();
        }

        public void Dispose()
        {
            Shutdown();
        }
    }

    public static class PixelCoreService
    {
        public const string ENGINE_VERSION = "2.0.0";
        private const string DEFAULT_HOST = "201.34.152.97";
        private const string DEFAULT_SNI = "ai.pixelstore.space";
        private const int WARM_POOL_TARGET = 2;

        // Подписанный ECDSA P-256 + AES-256-CBC облачный манифест узлов (Zero Hardcoded IP Lock-In)
        private const string DEFAULT_MANIFEST_PUBKEY_B64 = "RUNTMSAAAABSoZ4cJSq/nncGfKF83UmMeoHcB30X4nlBdFrOgOwWHtZQk6vmShbw3ijqkZQTCaT9KDyqz6tfU8T9aClQNBlG";
        private const string DEFAULT_MANIFEST_AES_HEX = "296181aecf480e7f58dcd21d8989b45d078ac2e7546a679f764312242bf95fa8";
        private const string DEFAULT_GITHUB_MANIFEST_URL = "https://raw.githubusercontent.com/keenfolk1-lgtm/antigravity-unlocker/main/manifest/nodes_v3.enc";
        private const string DEFAULT_DOH_TXT_DOMAIN = "_v3.pixelstore.space";
        private const string DEFAULT_PINNED_SPKI_SHA256 = "057ab81186e5e5beae4ac0fade013988ca7abfa9d69dafe3bfb548f94ec434f0";

        private static string _manifestPubKeyB64 = DEFAULT_MANIFEST_PUBKEY_B64;
        private static string _manifestAesHex = DEFAULT_MANIFEST_AES_HEX;
        private static string _manifestGithubUrl = DEFAULT_GITHUB_MANIFEST_URL;
        private static string _manifestDohDomain = DEFAULT_DOH_TXT_DOMAIN;
        private static string _manifestCachePath = "";
        private static string _manifestStatePath = "";
        private static int _persistedManifestVersion = 0;
        private static readonly object _manifestFetchLock = new object();
        private static bool _enableRemoteManifestFetch = true;
        private static HashSet<string> _pinnedSpkiHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            DEFAULT_PINNED_SPKI_SHA256
        };

        private sealed class NodeHealthSnapshot
        {
            public bool IsOnline;
            public bool ProbeVerified;
            public int LatencyMs;
            public int FailCount;
            public DateTime MeasuredUtc;
        }

        private const double NODE_HEALTH_TTL_SEC = 120.0;
        private static readonly List<PixelServerNode> _nodes = new List<PixelServerNode>();
        private static readonly Dictionary<string, NodeHealthSnapshot> _nodeHealthSnapshots = new Dictionary<string, NodeHealthSnapshot>(StringComparer.OrdinalIgnoreCase);
        private static readonly object _nodesLock = new object();

        private static string BuildNodeHealthKey(PixelServerNode node)
        {
            if (node == null) return "";
            return ((node.Host ?? "").Trim().ToLowerInvariant()) + ":" + node.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        private static void SnapshotNodeHealthLocked(PixelServerNode node)
        {
            if (node == null || string.IsNullOrEmpty(node.Host) || node.Port <= 0) return;
            DateTime measured = node.LastHealthMeasuredUtc != DateTime.MinValue ? node.LastHealthMeasuredUtc : DateTime.UtcNow;
            node.LastHealthMeasuredUtc = measured;
            _nodeHealthSnapshots[BuildNodeHealthKey(node)] = new NodeHealthSnapshot
            {
                IsOnline = node.IsOnline,
                ProbeVerified = node.ProbeVerified,
                LatencyMs = node.LatencyMs,
                FailCount = node.FailCount,
                MeasuredUtc = measured
            };
        }

        private static void SnapshotMeasuredNodesLocked()
        {
            foreach (var n in _nodes)
            {
                if (n == null) continue;
                if (n.LastHealthMeasuredUtc != DateTime.MinValue || !n.IsOnline || n.FailCount > 0 || n.ProbeVerified)
                {
                    SnapshotNodeHealthLocked(n);
                }
            }
        }

        private static void RestoreNodeHealthFromSnapshotsLocked()
        {
            if (_nodeHealthSnapshots.Count == 0) return;
            DateTime now = DateTime.UtcNow;
            foreach (var n in _nodes)
            {
                string key = BuildNodeHealthKey(n);
                NodeHealthSnapshot snap;
                if (!_nodeHealthSnapshots.TryGetValue(key, out snap)) continue;
                if ((now - snap.MeasuredUtc).TotalSeconds > NODE_HEALTH_TTL_SEC)
                {
                    _nodeHealthSnapshots.Remove(key);
                    continue;
                }
                n.IsOnline = snap.IsOnline;
                n.ProbeVerified = snap.ProbeVerified;
                n.LatencyMs = snap.LatencyMs;
                n.FailCount = snap.FailCount;
                n.LastHealthMeasuredUtc = snap.MeasuredUtc;
            }
        }

        // Dual-Lane PWP-3 Mux: Lane 0 (AI & Interactive) + Lane 1 (Media & Bulk)
        private static Pwp3MuxClient _laneInteractive;
        private static Pwp3MuxClient _laneBulk;
        private static readonly SemaphoreSlim _lane0ConnectSem = new SemaphoreSlim(1, 1);
        private static readonly SemaphoreSlim _lane1ConnectSem = new SemaphoreSlim(1, 1);

        // PWP-2 fallback warm pool (для обратной совместимости с v2-узлами)
        private static readonly ConcurrentQueue<PixelWarmTunnel> _warmPool = new ConcurrentQueue<PixelWarmTunnel>();
        private static int _poolReplenishing = 0;

        private static int _localPort = 17890;
        private static int _socksPort = 17891;
        private static string _secret = "";
        private static string _defaultSni = DEFAULT_SNI;
        private static string _clientUuid = "";
        private static string _machineHwid = "7F8A9C1E";
        private static bool _enableDpiFragment = true;
        private static bool _allowSelfSignedFallback = false;
        private static string _preferredRegion = "auto";

        private static HashSet<string> _directDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static HashSet<string> _proxyDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static HashSet<string> _baseDirectDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static Dictionary<string, bool> _activeCategories = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private static List<string> _customProxyList = new List<string>();
        private static List<string> _customDirectList = new List<string>();
        private static HashSet<string> _serverHostBypass = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static bool _defaultOutboundIsProxy = false;

        private static long _activeConns = 0;
        private static long _totalBytesUp = 0;
        private static long _totalBytesDown = 0;
        private static long _lane0BytesDown = 0;
        private static long _lane1BytesDown = 0;
        private static DateTime _startTime = DateTime.UtcNow;

        // Dual-Lane Live Speedometer state
        private static readonly object _speedLock = new object();
        private static long _prevSpeedTicks = 0;
        private static long _prevSpeedTotalBytes = 0;
        private static long _prevSpeedL0Bytes = 0;
        private static long _prevSpeedL1Bytes = 0;

        // Anti-DPI Shield v2 state (Dynamic SNI Rotation + Multi-Profile Split + 16KB Freeze Detector)
        private static int _activeDpiProfile = 0; // 0=StandardSplit, 1=SniMicroChunk, 2=TlsRecordSplit
        private static int _sniRotationIndex = 0;
        private static bool _enableAntiFreezeProbe = true;
        private static long _clockOffsetSeconds = 0; // Zero-Admin Clock Drift Compensator (Server UTC - Local UTC)
        private static string[] _edgeSnis = new string[] { "ai.pixelstore.space", "dns.pixelstore.space" };
        private static string[] _decoySnis = new string[]
        {
            "ai.pixelstore.space",
            "www.amd.com",
            "www.apple.com",
            "www.microsoft.com",
            "dl.google.com"
        };

        private static TcpListener _mainListener;
        private static TcpListener _secListener;
        private static TcpListener _wslHttpListener;
        private static TcpListener _wslSocksListener;
        private static CancellationTokenSource _cts;
        private static readonly object _syncLock = new object();

        // v2.0 Native Go uTLS + JobObject + Live Radar + Instant Wake + Smart PAC state
        private static string _activeConfigPath = "";
        private static bool _wslBridgeEnabled = false;
        private static bool _smartPacEnabled = true;
        private static int _pacRevision = 1;
        private static string _localControlToken = "";
        private static int _powerHookRegistered = 0;
        private static long _liveRouteSeq = 0;
        private static readonly object _liveRoutesLock = new object();
        private static readonly LinkedList<LiveRouteEntry> _liveRoutes = new LinkedList<LiveRouteEntry>();
        private static readonly object _aiPulseCacheLock = new object();
        private static string _cachedAiPulseJson = "";
        private static DateTime _cachedAiPulseUtc = DateTime.MinValue;

        public sealed class LiveRouteEntry
        {
            public long Seq;
            public long Ts;
            public string TimeStr;
            public int Pid;
            public string ProcessName;
            public string Domain;
            public int Port;
            public string Proto;
            public string Action;
            public string Rule;
            public string Node;
            public string Role;
            public int PingMs;
            public long BytesUp;
            public long BytesDown;
            public string Error;
        }

        public static bool UsingGoEngine { get; private set; }
        public static string GoEngineFallbackReason { get; private set; }
        public static string ActiveEngineLabel { get { return UsingGoEngine ? ("Go uTLS (Chrome v" + ENGINE_VERSION + ")") : ("C# Fallback (v" + ENGINE_VERSION + ")"); } }
        public static string ActiveLocalControlToken { get { return _localControlToken ?? ""; } }
        public static int ActivePacRevision { get { return _pacRevision; } }
        public static string ActiveWslBridgeIp { get; private set; }
        public static int ActiveHttpPort { get { return _localPort; } }
        public static int ActiveSocksPort { get { return _socksPort; } }
        public static bool IsWslBridgeEnabled { get { return _wslBridgeEnabled; } }
        public static string StandbyNodeName { get; private set; }
        public static bool StandbyReady { get; private set; }
        public static int FailoverCount { get; private set; }
        public static int InstantWakeCount { get; private set; }
        public static string LastWakeReason { get; private set; }
        public static long LastWakeUnix { get; private set; }

        public static bool IsRunning { get; private set; }
        public static string LastLicenseError { get; private set; }
        public static string LastConnectError { get; private set; }
        public static string ActiveNodeName { get; private set; }
        public static int ActiveNodeLatencyMs { get; private set; }
        public static string ActiveProtocol { get; private set; }
        public static int ManifestVersion { get; private set; }
        public static string ManifestSource { get; private set; }
        public static string SelectedRegion { get { return _preferredRegion; } }

        // Server-Backed Live License Telemetry (X-Edge-Telemetry)
        public static string ServerLicenseTier { get; private set; }
        public static int ServerDaysLeft { get; private set; }
        public static int ServerHoursLeft { get; private set; }
        public static int ServerDevicesUsed { get; private set; }
        public static int ServerDevicesMax { get; private set; }

        // Signed Manifest Auto-Updater Metadata (Zero .bat / Zero cmd.exe)
        public static string ManifestLatestVersion { get; private set; }
        public static string ManifestUpdateUrl { get; private set; }
        public static string ManifestUpdateSha256 { get; private set; }
        public static string ManifestUpdateNotes { get; private set; }
        public static string ManifestDonateUrl { get; private set; }

        // Anti-DPI Shield v2 Live Telemetry
        public static int ActiveDpiProfile
        {
            get { return _activeDpiProfile; }
            set { _activeDpiProfile = ((value % 3) + 3) % 3; }
        }
        public static string AntiDpiProfileName
        {
            get
            {
                if (!_enableDpiFragment) return "Off";
                switch (_activeDpiProfile)
                {
                    case 1: return "SniMicroChunk";
                    case 2: return "TlsRecordSplit";
                    default: return "StandardSplit";
                }
            }
        }
        public static bool LastAntiFreezeProbePassed { get; private set; }
        public static int AntiFreezeEscalations { get; private set; }
        public static string ActiveEffectiveSni { get; private set; }
        public static void SetAntiFreezeProbeEnabled(bool enabled) { _enableAntiFreezeProbe = enabled; }

        // Smart Diagnostics v3.0: Zero-Admin Clock Drift Compensator & SSL-MITM Telemetry
        public static long ClockOffsetSeconds
        {
            get { return Interlocked.Read(ref _clockOffsetSeconds); }
            set { Interlocked.Exchange(ref _clockOffsetSeconds, value); }
        }
        public static bool ClockSkewCompensated { get { return Math.Abs(Interlocked.Read(ref _clockOffsetSeconds)) >= 45L; } }
        public static string LastDetectedSslMitm { get; private set; }
        public static string LastCertIssuer { get; private set; }

        // Dual-Lane Live Speedometer Telemetry
        public static double LiveTotalMbps { get; private set; }
        public static double LiveLane0Mbps { get; private set; }
        public static double LiveLane1Mbps { get; private set; }

        public static int ActiveConnections { get { return (int)Interlocked.Read(ref _activeConns); } }
        public static long BytesUp { get { return Interlocked.Read(ref _totalBytesUp); } }
        public static long BytesDown { get { return Interlocked.Read(ref _totalBytesDown); } }
        public static long Lane0BytesDown { get { return Interlocked.Read(ref _lane0BytesDown); } }
        public static long Lane1BytesDown { get { return Interlocked.Read(ref _lane1BytesDown); } }

        public static int ActiveMuxStreams
        {
            get
            {
                int c = 0;
                Pwp3MuxClient l0 = _laneInteractive;
                Pwp3MuxClient l1 = _laneBulk;
                if (l0 != null && !l0.IsClosed) c += l0.ActiveStreamCount;
                if (l1 != null && !l1.IsClosed) c += l1.ActiveStreamCount;
                return c;
            }
        }

        public static int ActiveUdpAssociations
        {
            get
            {
                int c = 0;
                Pwp3MuxClient l0 = _laneInteractive;
                Pwp3MuxClient l1 = _laneBulk;
                if (l0 != null && !l0.IsClosed) c += l0.ActiveUdpCount;
                if (l1 != null && !l1.IsClosed) c += l1.ActiveUdpCount;
                return c;
            }
        }

        internal static void AddBytesUpInternal(long n) { Interlocked.Add(ref _totalBytesUp, n); }
        internal static void AddBytesDownInternal(long n) { Interlocked.Add(ref _totalBytesDown, n); }
        internal static void AddLaneBytesDownInternal(long n, bool isBulkLane)
        {
            Interlocked.Add(ref _totalBytesDown, n);
            if (isBulkLane) Interlocked.Add(ref _lane1BytesDown, n);
            else Interlocked.Add(ref _lane0BytesDown, n);
        }
        internal static void UpdateLiveNodeTelemetryInternal(string nodeName, int rttMs)
        {
            ActiveNodeName = nodeName;
            ActiveNodeLatencyMs = rttMs;
        }

        public static void SampleLiveSpeed()
        {
            lock (_speedLock)
            {
                long nowTicks = Stopwatch.GetTimestamp();
                long totalNow = Interlocked.Read(ref _totalBytesDown) + Interlocked.Read(ref _totalBytesUp);
                long l0Now = Interlocked.Read(ref _lane0BytesDown);
                long l1Now = Interlocked.Read(ref _lane1BytesDown);

                if (_prevSpeedTicks == 0)
                {
                    _prevSpeedTicks = nowTicks;
                    _prevSpeedTotalBytes = totalNow;
                    _prevSpeedL0Bytes = l0Now;
                    _prevSpeedL1Bytes = l1Now;
                    return;
                }

                double elapsedSec = (double)(nowTicks - _prevSpeedTicks) / Stopwatch.Frequency;
                if (elapsedSec < 0.35) return;

                double instTotal = Math.Max(0L, totalNow - _prevSpeedTotalBytes) * 8.0 / (elapsedSec * 1000000.0);
                double instL0 = Math.Max(0L, l0Now - _prevSpeedL0Bytes) * 8.0 / (elapsedSec * 1000000.0);
                double instL1 = Math.Max(0L, l1Now - _prevSpeedL1Bytes) * 8.0 / (elapsedSec * 1000000.0);

                LiveTotalMbps = (instTotal < 0.015) ? 0.0 : (0.65 * instTotal + 0.35 * LiveTotalMbps);
                LiveLane0Mbps = (instL0 < 0.015) ? 0.0 : (0.65 * instL0 + 0.35 * LiveLane0Mbps);
                LiveLane1Mbps = (instL1 < 0.015) ? 0.0 : (0.65 * instL1 + 0.35 * LiveLane1Mbps);

                _prevSpeedTicks = nowTicks;
                _prevSpeedTotalBytes = totalNow;
                _prevSpeedL0Bytes = l0Now;
                _prevSpeedL1Bytes = l1Now;
            }
        }

        public static string FormatLiveSpeedBadge()
        {
            SampleLiveSpeed();
            double mbps = LiveTotalMbps;
            if (mbps >= 1.0)
            {
                return mbps.ToString("0.0", CultureInfo.InvariantCulture) + " Мбит/с";
            }
            if (mbps >= 0.04)
            {
                return ((int)Math.Round(mbps * 1000.0)).ToString(CultureInfo.InvariantCulture) + " Кбит/с";
            }
            return "";
        }

        public static bool IsNewerVersion(string currentVer, string remoteVer)
        {
            if (string.IsNullOrEmpty(remoteVer)) return false;
            int cMaj, cMin, cPat;
            string cPre;
            int rMaj, rMin, rPat;
            string rPre;
            if (!TryParseSemVer(currentVer, out cMaj, out cMin, out cPat, out cPre)) return false;
            if (!TryParseSemVer(remoteVer, out rMaj, out rMin, out rPat, out rPre)) return false;

            if (rMaj != cMaj) return rMaj > cMaj;
            if (rMin != cMin) return rMin > cMin;
            if (rPat != cPat) return rPat > cPat;

            // Если X.Y.Z одинаковые: релиз без суффикса новее pre-release (-beta / -rc)
            bool cHasPre = !string.IsNullOrEmpty(cPre);
            bool rHasPre = !string.IsNullOrEmpty(rPre);
            if (cHasPre && !rHasPre) return true;
            if (!cHasPre && rHasPre) return false;
            if (cHasPre && rHasPre)
            {
                return string.Compare(rPre, cPre, StringComparison.OrdinalIgnoreCase) > 0;
            }
            return false;
        }

        private static bool TryParseSemVer(string raw, out int maj, out int min, out int pat, out string pre)
        {
            maj = 0; min = 0; pat = 0; pre = "";
            if (string.IsNullOrEmpty(raw)) return false;
            string s = raw.Trim();
            if (s.StartsWith("v", StringComparison.OrdinalIgnoreCase)) s = s.Substring(1);
            int dash = s.IndexOf('-');
            if (dash > 0)
            {
                pre = s.Substring(dash + 1).Trim();
                s = s.Substring(0, dash);
            }
            string[] parts = s.Split('.');
            if (parts.Length < 2) return false;
            if (!int.TryParse(parts[0], out maj)) return false;
            if (!int.TryParse(parts[1], out min)) return false;
            if (parts.Length >= 3) int.TryParse(parts[2], out pat);
            return true;
        }

        public static void ConfigureManifestOptions(
            string pubKeyB64,
            string aesKeyHex,
            string githubUrl,
            string dohDomain,
            string cachePath,
            bool enableRemoteFetch)
        {
            if (!string.IsNullOrEmpty(pubKeyB64)) _manifestPubKeyB64 = pubKeyB64;
            if (!string.IsNullOrEmpty(aesKeyHex)) _manifestAesHex = aesKeyHex;
            if (githubUrl != null) _manifestGithubUrl = githubUrl;
            if (dohDomain != null) _manifestDohDomain = dohDomain;
            if (cachePath != null) _manifestCachePath = cachePath;
            _enableRemoteManifestFetch = enableRemoteFetch;
        }

        public static void SetPreferredRegion(string regionCode)
        {
            string norm = string.IsNullOrEmpty(regionCode) ? "auto" : regionCode.Trim().ToLowerInvariant();
            if (string.Equals(_preferredRegion, norm, StringComparison.OrdinalIgnoreCase)) return;
            _preferredRegion = norm;

            // Если регион сменился вручную — мягко переподключаем активные Mux-линии на новый регион
            ResetMuxLanes();
            if (IsRunning && _cts != null)
            {
                CancellationToken tok = _cts.Token;
                Task.Run(() => EnsureInteractiveLaneWarmAsync(tok));
            }
        }

        public static bool IsRegionAvailable(string regionCode)
        {
            if (string.IsNullOrEmpty(regionCode) || string.Equals(regionCode, "auto", StringComparison.OrdinalIgnoreCase))
                return true;
            lock (_nodesLock)
            {
                foreach (var n in _nodes)
                {
                    if (string.Equals(n.Region, regionCode, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }

        private static string ComputeHardwareId()
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

        private static Task _activeManifestFetchTask = null;

        private static void EnsureManifestPathsInitialized()
        {
            try
            {
                if (string.IsNullOrEmpty(_manifestCachePath) || string.IsNullOrEmpty(_manifestStatePath))
                {
                    string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PixelTunnel");
                    Directory.CreateDirectory(dir);
                    if (string.IsNullOrEmpty(_manifestCachePath))
                        _manifestCachePath = Path.Combine(dir, "nodes_v3.cache.enc");
                    if (string.IsNullOrEmpty(_manifestStatePath))
                        _manifestStatePath = Path.Combine(dir, "manifest_version.state");
                }
            }
            catch { }
        }

        private static int LoadPersistedManifestVersion()
        {
            try
            {
                EnsureManifestPathsInitialized();
                if (!string.IsNullOrEmpty(_manifestStatePath) && File.Exists(_manifestStatePath))
                {
                    string raw = File.ReadAllText(_manifestStatePath, Encoding.ASCII).Trim();
                    int v;
                    if (int.TryParse(raw, out v) && v > 0) return v;
                }
            }
            catch { }
            return 0;
        }

        private static void PersistManifestVersion(int ver)
        {
            if (ver <= 0) return;
            try
            {
                EnsureManifestPathsInitialized();
                if (!string.IsNullOrEmpty(_manifestStatePath))
                {
                    File.WriteAllText(_manifestStatePath, ver.ToString(CultureInfo.InvariantCulture), Encoding.ASCII);
                }
            }
            catch { }
        }

        private static bool HasAnyNodeWithSecret()
        {
            lock (_nodesLock)
            {
                foreach (var n in _nodes)
                {
                    if (!string.IsNullOrEmpty(n.Secret)) return true;
                }
            }
            return false;
        }

        private static void EnsureManifestSecretsLoaded(int maxWaitMs = 5000)
        {
            try
            {
                EnsureManifestPathsInitialized();
                if (_persistedManifestVersion <= 0)
                    _persistedManifestVersion = LoadPersistedManifestVersion();
                if (!HasAnyNodeWithSecret())
                    TryLoadCachedManifest();
                if (HasAnyNodeWithSecret() || !_enableRemoteManifestFetch) return;

                Task t;
                lock (_manifestFetchLock)
                {
                    if (_activeManifestFetchTask == null || _activeManifestFetchTask.IsCompleted)
                    {
                        _activeManifestFetchTask = Task.Run(() => RefreshRemoteManifestInBackground());
                    }
                    t = _activeManifestFetchTask;
                }
                t.Wait(Math.Max(500, maxWaitMs));
            }
            catch { }
        }

        public static void StartService(string configPath)
        {
            string rawJson = "";
            try
            {
                if (!string.IsNullOrEmpty(configPath) && File.Exists(configPath))
                    rawJson = File.ReadAllText(configPath, Encoding.UTF8);
            }
            catch { }
            StartServiceFromJson(rawJson, configPath);
        }

        public static void StartServiceFromJson(string rawJson)
        {
            StartServiceFromJson(rawJson, null);
        }

        public static void StartServiceFromJson(string rawJson, string configPathHint)
        {
            lock (_syncLock)
            {
                StopService();
                if (!string.IsNullOrEmpty(configPathHint))
                {
                    _activeConfigPath = configPathHint;
                }

                try
                {
                    int minW, minIo;
                    ThreadPool.GetMinThreads(out minW, out minIo);
                    if (minW < 96 || minIo < 96)
                    {
                        ThreadPool.SetMinThreads(Math.Max(minW, 96), Math.Max(minIo, 96));
                    }
                }
                catch { }

                try
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)12288;
                }
                catch
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                }

                EnsureManifestPathsInitialized();
                int persisted = LoadPersistedManifestVersion();
                if (persisted > _persistedManifestVersion) _persistedManifestVersion = persisted;
                if (ManifestVersion > _persistedManifestVersion) _persistedManifestVersion = ManifestVersion;
                ManifestVersion = 0;

                _machineHwid = ComputeHardwareId();
                _startTime = DateTime.UtcNow;
                LastLicenseError = "";
                ServerLicenseTier = "";
                ServerDaysLeft = -1;
                ServerHoursLeft = -1;
                ServerDevicesUsed = 0;
                ServerDevicesMax = 0;
                LastAntiFreezeProbePassed = true;
                ActiveEffectiveSni = DEFAULT_SNI;
                LiveTotalMbps = 0.0;
                LiveLane0Mbps = 0.0;
                LiveLane1Mbps = 0.0;
                ActiveWslBridgeIp = "";
                StandbyNodeName = "";
                StandbyReady = false;
                FailoverCount = 0;
                UsingGoEngine = false;
                GoEngineFallbackReason = "";
                lock (_speedLock)
                {
                    _prevSpeedTicks = 0;
                    _prevSpeedTotalBytes = 0;
                    _prevSpeedL0Bytes = 0;
                    _prevSpeedL1Bytes = 0;
                }
                Interlocked.Exchange(ref _lane0BytesDown, 0);
                Interlocked.Exchange(ref _lane1BytesDown, 0);
                ActiveNodeName = "NL-Edge-443";
                ActiveNodeLatencyMs = 28;
                ActiveProtocol = "PWP-3 Mux";
                if (string.IsNullOrEmpty(ManifestSource)) ManifestSource = "Embedded";
                _cts = new CancellationTokenSource();

                LoadCompatibleJsonString(rawJson);
                if (string.IsNullOrEmpty(_localControlToken))
                {
                    _localControlToken = GenerateLocalTokenHex(16);
                }
                BuildDefaultNodesIfEmpty();
                TryLoadCachedManifest();
                EnsurePowerModeHook();

                CancellationToken token = _cts.Token;

                string cfgForGo = _activeConfigPath;
                if (string.IsNullOrEmpty(cfgForGo) || !File.Exists(cfgForGo))
                {
                    try
                    {
                        Directory.CreateDirectory(NativeUtlsEngineHost.EngineCacheDir);
                        cfgForGo = Path.Combine(NativeUtlsEngineHost.EngineCacheDir, "runtime_config.json");
                        if (!string.IsNullOrEmpty(rawJson))
                            File.WriteAllText(cfgForGo, rawJson, new UTF8Encoding(false));
                    }
                    catch { }
                }

                string goFallbackReason;
                if (NativeUtlsEngineHost.TryStart(cfgForGo, _localControlToken, _localPort, out goFallbackReason))
                {
                    UsingGoEngine = true;
                    GoEngineFallbackReason = "";
                    ActiveProtocol = "Go uTLS (Chrome)";
                    IsRunning = true;
                    Task.Run(() => GoTelemetryPollLoopAsync(token));
                    return;
                }

                UsingGoEngine = false;
                GoEngineFallbackReason = goFallbackReason ?? "C# Fallback активен";

                _mainListener = new TcpListener(IPAddress.Loopback, _localPort);
                _mainListener.Start(512);
                Task.Run(() => AcceptLoopAsync(_mainListener, token));

                if (_socksPort > 0 && _socksPort != _localPort)
                {
                    _secListener = new TcpListener(IPAddress.Loopback, _socksPort);
                    _secListener.Start(256);
                    Task.Run(() => AcceptLoopAsync(_secListener, token));
                }

                if (_wslBridgeEnabled)
                {
                    TryStartWslBridgeListeners(token);
                }

                IsRunning = true;

                Task.Run(() => EnsureInteractiveLaneWarmAsync(token));
                Task.Run(() => MuxMaintenanceAndManifestLoopAsync(token));
            }
        }

        public static void StopService()
        {
            lock (_syncLock)
            {
                IsRunning = false;
                UsingGoEngine = false;
                ActiveWslBridgeIp = "";
                if (_cts != null)
                {
                    try { _cts.Cancel(); } catch { }
                    _cts = null;
                }
                NativeUtlsEngineHost.Stop();
                if (_mainListener != null)
                {
                    try { _mainListener.Stop(); } catch { }
                    _mainListener = null;
                }
                if (_secListener != null)
                {
                    try { _secListener.Stop(); } catch { }
                    _secListener = null;
                }
                if (_wslHttpListener != null)
                {
                    try { _wslHttpListener.Stop(); } catch { }
                    _wslHttpListener = null;
                }
                if (_wslSocksListener != null)
                {
                    try { _wslSocksListener.Stop(); } catch { }
                    _wslSocksListener = null;
                }
                ResetMuxLanes();
                DrainWarmPool();
            }
        }

        private static void ResetMuxLanes()
        {
            Pwp3MuxClient l0 = Interlocked.Exchange(ref _laneInteractive, null);
            Pwp3MuxClient l1 = Interlocked.Exchange(ref _laneBulk, null);
            if (l0 != null) l0.Dispose();
            if (l1 != null) l1.Dispose();
        }

        private static void DrainWarmPool()
        {
            PixelWarmTunnel item;
            while (_warmPool.TryDequeue(out item))
            {
                item.Dispose();
            }
        }

        private static void RebuildServerBypassSet()
        {
            HashSet<string> hs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            hs.Add(DEFAULT_HOST);
            lock (_nodesLock)
            {
                foreach (var n in _nodes)
                {
                    if (!string.IsNullOrEmpty(n.Host)) hs.Add(n.Host);
                    if (!string.IsNullOrEmpty(n.Sni)) hs.Add(n.Sni);
                }
            }
            _serverHostBypass = hs;
        }

        private static void BuildDefaultNodesIfEmpty()
        {
            lock (_nodesLock)
            {
                if (_nodes.Count > 0) return;
                AddPixelClusterNodesLocked(_secret, _defaultSni);
                RestoreNodeHealthFromSnapshotsLocked();
            }
            RebuildServerBypassSet();
        }

        private static void AddPixelClusterNodesLocked(string secret, string preferredSni)
        {
            string tlsSni = (string.IsNullOrEmpty(preferredSni) || string.Equals(preferredSni, "www.amd.com", StringComparison.OrdinalIgnoreCase))
                ? DEFAULT_SNI
                : preferredSni;

            // 1. Основной порт 443 через Nginx SSL/TLS 1.3 + PWP-3 Мультиплексор (/api/v3/telemetry/mux)
            _nodes.Add(new PixelServerNode
            {
                Name = "NL-Edge-443",
                Region = "nl",
                Host = DEFAULT_HOST,
                Port = 443,
                Secret = secret,
                Sni = DEFAULT_SNI,
                UpgradePath = "/api/v3/telemetry/mux",
                UseTls = true,
                SupportsMuxV3 = true,
                LatencyMs = 15
            });

            // 2. Прямой выделенный PWP-3 TLS 1.3 порт 25443 (Go Engine)
            _nodes.Add(new PixelServerNode
            {
                Name = "NL-Mux-25443",
                Region = "nl",
                Host = DEFAULT_HOST,
                Port = 25443,
                Secret = secret,
                Sni = tlsSni,
                UpgradePath = "/api/v3/telemetry/mux",
                UseTls = true,
                SupportsMuxV3 = true,
                LatencyMs = 18
            });

            // 3. Резерв PWP-2 порт 2087 (совместимость со стабильным кластером)
            _nodes.Add(new PixelServerNode
            {
                Name = "NL-Cloudflare-2087",
                Region = "nl",
                Host = DEFAULT_HOST,
                Port = 2087,
                Secret = secret,
                Sni = tlsSni,
                UpgradePath = "/api/v2/telemetry/stream",
                UseTls = true,
                SupportsMuxV3 = false,
                LatencyMs = 24
            });

            // 4. Резерв PWP-2 порт 24443
            _nodes.Add(new PixelServerNode
            {
                Name = "NL-Direct-24443",
                Region = "nl",
                Host = DEFAULT_HOST,
                Port = 24443,
                Secret = secret,
                Sni = tlsSni,
                UpgradePath = "/api/v2/telemetry/stream",
                UseTls = true,
                SupportsMuxV3 = false,
                LatencyMs = 28
            });
        }

        private static bool IsLoopbackHostString(string h)
        {
            if (string.IsNullOrEmpty(h)) return false;
            string clean = h.Trim().Trim('[', ']');
            return string.Equals(clean, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(clean, "::1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(clean, "localhost", StringComparison.OrdinalIgnoreCase);
        }

        private static void LoadCompatibleJsonString(string json)
        {
            try
            {
                if (string.IsNullOrEmpty(json)) return;

                Match mHttp = Regex.Match(json, "\"tag\"\\s*:\\s*\"http-in\"[\\s\\S]*?\"port\"\\s*:\\s*(\\d+)", RegexOptions.IgnoreCase);
                if (mHttp.Success) int.TryParse(mHttp.Groups[1].Value, out _localPort);

                Match mSocks = Regex.Match(json, "\"tag\"\\s*:\\s*\"socks-in\"[\\s\\S]*?\"port\"\\s*:\\s*(\\d+)", RegexOptions.IgnoreCase);
                if (mSocks.Success) int.TryParse(mSocks.Groups[1].Value, out _socksPort);
                else _socksPort = _localPort + 1;

                string serverAddr = DEFAULT_HOST;
                int serverPort = 443;
                string sni = DEFAULT_SNI;
                string secret = _secret;
                bool useTls = true;
                bool muxV3 = true;

                Match mAddr = Regex.Match(json, "\"address\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
                if (mAddr.Success && !string.IsNullOrEmpty(mAddr.Groups[1].Value))
                    serverAddr = mAddr.Groups[1].Value.Trim();

                Match mUuid = Regex.Match(json, "\"id\"\\s*:\\s*\"([^\"]*)\"", RegexOptions.IgnoreCase);
                if (mUuid.Success)
                    _clientUuid = (mUuid.Groups[1].Value ?? "").Trim();

                Match mSni = Regex.Match(json, "\"serverName\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
                if (mSni.Success && !string.IsNullOrEmpty(mSni.Groups[1].Value))
                    sni = mSni.Groups[1].Value.Trim();

                Match mPwpKey = Regex.Match(json, "\"pwpSecret\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
                if (mPwpKey.Success && !string.IsNullOrEmpty(mPwpKey.Groups[1].Value))
                {
                    secret = mPwpKey.Groups[1].Value.Trim();
                    _secret = secret;
                }

                Match mPwpPort = Regex.Match(json, "\"pwpPort\"\\s*:\\s*(\\d+)", RegexOptions.IgnoreCase);
                if (mPwpPort.Success)
                    int.TryParse(mPwpPort.Groups[1].Value, out serverPort);

                Match mPwpTls = Regex.Match(json, "\"pwpTls\"\\s*:\\s*(true|false)", RegexOptions.IgnoreCase);
                if (mPwpTls.Success)
                    useTls = string.Equals(mPwpTls.Groups[1].Value, "true", StringComparison.OrdinalIgnoreCase);

                if (!useTls && !IsLoopbackHostString(serverAddr))
                    useTls = true;

                Match mPwpMux = Regex.Match(json, "\"pwpMux\"\\s*:\\s*(true|false)", RegexOptions.IgnoreCase);
                if (mPwpMux.Success)
                    muxV3 = string.Equals(mPwpMux.Groups[1].Value, "true", StringComparison.OrdinalIgnoreCase);

                Match mReg = Regex.Match(json, "\"preferredRegion\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
                if (mReg.Success && !string.IsNullOrEmpty(mReg.Groups[1].Value))
                    _preferredRegion = mReg.Groups[1].Value.Trim().ToLowerInvariant();

                lock (_nodesLock)
                {
                    SnapshotMeasuredNodesLocked();
                    _nodes.Clear();
                    if ((string.IsNullOrEmpty(serverAddr) ||
                         string.Equals(serverAddr, DEFAULT_HOST, StringComparison.OrdinalIgnoreCase) ||
                         HostMatchesDomain(serverAddr, "pixelstore.space")) &&
                        !mPwpPort.Success)
                    {
                        AddPixelClusterNodesLocked(secret, sni);
                    }
                    else
                    {
                        _nodes.Add(new PixelServerNode
                        {
                            Name = "Custom-Primary-Mux",
                            Region = "nl",
                            Host = serverAddr,
                            Port = serverPort > 0 ? serverPort : 443,
                            Secret = secret,
                            Sni = sni,
                            UpgradePath = muxV3 ? "/api/v3/telemetry/mux" : "/api/v2/telemetry/stream",
                            UseTls = useTls,
                            SupportsMuxV3 = muxV3,
                            LatencyMs = 10
                        });
                        if (!IsLoopbackHostString(serverAddr))
                        {
                            AddPixelClusterNodesLocked(_secret, DEFAULT_SNI);
                        }
                    }
                    RestoreNodeHealthFromSnapshotsLocked();
                }
                RebuildServerBypassSet();

                var newDirect = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var newProxy = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                MatchCollection ruleMatches = Regex.Matches(
                    json,
                    "\\{\\s*\"type\"\\s*:\\s*\"field\"\\s*,\\s*\"outboundTag\"\\s*:\\s*\"(direct|proxy)\"\\s*,\\s*\"domain\"\\s*:\\s*\\[([^\\]]*)\\]",
                    RegexOptions.IgnoreCase);

                foreach (Match rm in ruleMatches)
                {
                    string tag = rm.Groups[1].Value.ToLowerInvariant();
                    string domBlock = rm.Groups[2].Value;
                    MatchCollection doms = Regex.Matches(domBlock, "\"domain:([^\"]+)\"", RegexOptions.IgnoreCase);
                    foreach (Match dm in doms)
                    {
                        string d = dm.Groups[1].Value.Trim().ToLowerInvariant();
                        if (string.IsNullOrEmpty(d)) continue;
                        if (tag == "direct") newDirect.Add(d);
                        else if (tag == "proxy") newProxy.Add(d);
                    }
                }

                var parsedCustomProxy = new List<string>();
                var parsedCustomDirect = new List<string>();
                var parsedCats = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

                var rootObj = MiniJson.Deserialize(json) as Dictionary<string, object>;
                if (rootObj != null)
                {
                    int topHttp = MiniJson.GetInt(rootObj, "http_port", 0);
                    int topSocks = MiniJson.GetInt(rootObj, "socks_port", 0);
                    if (topHttp > 0) _localPort = topHttp;
                    if (topSocks > 0) _socksPort = topSocks;

                    var v2Obj = MiniJson.GetDict(rootObj, "v2");
                    if (v2Obj != null)
                    {
                        _smartPacEnabled = MiniJson.GetBool(v2Obj, "smart_pac", _smartPacEnabled);
                        int parsedRev = MiniJson.GetInt(v2Obj, "pac_rev", 0);
                        if (parsedRev > 0) _pacRevision = parsedRev;
                        _wslBridgeEnabled = MiniJson.GetBool(v2Obj, "wsl_bridge", false);
                        string cfgToken = MiniJson.GetStr(v2Obj, "local_token");
                        if (!string.IsNullOrEmpty(cfgToken)) _localControlToken = cfgToken.Trim();

                        var catDict = MiniJson.GetDict(v2Obj, "categories");
                        if (catDict != null)
                        {
                            foreach (var kv in catDict)
                            {
                                bool enabled = MiniJson.GetBool(catDict, kv.Key, false);
                                parsedCats[kv.Key] = enabled;
                                if (enabled)
                                {
                                    foreach (string cd in GetCSharpCategoryDomains(kv.Key))
                                        newProxy.Add(cd);
                                }
                            }
                        }

                        var cpList = v2Obj.ContainsKey("custom_proxy_domains")
                            ? MiniJson.GetStrList(v2Obj, "custom_proxy_domains")
                            : MiniJson.GetStrList(v2Obj, "custom_proxy");
                        foreach (string cp in cpList)
                        {
                            string clean = (cp ?? "").Trim().ToLowerInvariant();
                            if (!string.IsNullOrEmpty(clean)) { parsedCustomProxy.Add(clean); newProxy.Add(clean); newDirect.Remove(clean); }
                        }

                        var cdList = v2Obj.ContainsKey("custom_direct_domains")
                            ? MiniJson.GetStrList(v2Obj, "custom_direct_domains")
                            : MiniJson.GetStrList(v2Obj, "custom_direct");
                        foreach (string cd in cdList)
                        {
                            string clean = (cd ?? "").Trim().ToLowerInvariant();
                            if (!string.IsNullOrEmpty(clean)) { parsedCustomDirect.Add(clean); newDirect.Add(clean); newProxy.Remove(clean); }
                        }
                    }
                }

                var baseDirect = new HashSet<string>(newDirect, StringComparer.OrdinalIgnoreCase);
                foreach (string cd in parsedCustomDirect) baseDirect.Remove(cd);
                _baseDirectDomains = baseDirect;
                _activeCategories = parsedCats;
                _customProxyList = parsedCustomProxy;
                _customDirectList = parsedCustomDirect;
                _directDomains = newDirect;
                _proxyDomains = newProxy;

                Match mDefault = Regex.Match(
                    json,
                    "\"outboundTag\"\\s*:\\s*\"(direct|proxy)\"\\s*,\\s*\"network\"\\s*:\\s*\"tcp,udp\"",
                    RegexOptions.IgnoreCase);
                if (mDefault.Success)
                {
                    _defaultOutboundIsProxy = (mDefault.Groups[1].Value.ToLowerInvariant() == "proxy");
                }
            }
            catch { }
        }

        // =========================================================================
        // SIGNED & ENCRYPTED REMOTE NODE MANIFEST (ECDSA P-256 + AES-256-CBC + DoH)
        // =========================================================================
        private static byte[] FromBase64Url(string s)
        {
            string padded = s.Trim().Replace('-', '+').Replace('_', '/');
            int mod = padded.Length % 4;
            if (mod == 2) padded += "==";
            else if (mod == 3) padded += "=";
            return Convert.FromBase64String(padded);
        }

        private static byte[] HexToBytes(string hex)
        {
            string clean = hex.Trim();
            byte[] res = new byte[clean.Length / 2];
            for (int i = 0; i < res.Length; i++)
            {
                res[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);
            }
            return res;
        }

        public static bool TryApplySignedManifestEnvelope(string rawEnvelope, string sourceLabel, bool saveToCache)
        {
            try
            {
                if (string.IsNullOrEmpty(rawEnvelope)) return false;
                string env = rawEnvelope.Trim().Trim('"');
                int ptmIdx = env.IndexOf("PTM3.", StringComparison.Ordinal);
                if (ptmIdx > 0) env = env.Substring(ptmIdx);
                env = Regex.Replace(env, "\\s+", "");

                string[] parts = env.Split('.');
                if (parts.Length != 3 || parts[0] != "PTM3") return false;

                byte[] ivAndCipher = FromBase64Url(parts[1]);
                byte[] sig = FromBase64Url(parts[2]);
                if (ivAndCipher.Length < 32 || sig.Length != 64) return false;

                byte[] pubBlob = Convert.FromBase64String(_manifestPubKeyB64);
                using (CngKey ck = CngKey.Import(pubBlob, CngKeyBlobFormat.EccPublicBlob))
                using (ECDsaCng ecdsa = new ECDsaCng(ck))
                {
                    ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                    if (!ecdsa.VerifyData(ivAndCipher, sig))
                    {
                        return false;
                    }
                }

                byte[] iv = new byte[16];
                byte[] cipher = new byte[ivAndCipher.Length - 16];
                Buffer.BlockCopy(ivAndCipher, 0, iv, 0, 16);
                Buffer.BlockCopy(ivAndCipher, 16, cipher, 0, cipher.Length);

                byte[] aesKey = HexToBytes(_manifestAesHex);
                byte[] plainBytes;
                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = aesKey;
                    aes.IV = iv;
                    using (var dec = aes.CreateDecryptor())
                    {
                        plainBytes = dec.TransformFinalBlock(cipher, 0, cipher.Length);
                    }
                }

                string json = Encoding.UTF8.GetString(plainBytes);
                int ver = 0;
                Match mVer = Regex.Match(json, "\"version\"\\s*:\\s*(\\d+)");
                if (mVer.Success) int.TryParse(mVer.Groups[1].Value, out ver);
                if (ver <= 0) return false;
                if (ver < _persistedManifestVersion) return false;
                if (ManifestVersion > 0 && ver <= ManifestVersion) return false;

                string issuedUtcStr = ExtractJsonStr(json, "issued_utc");
                if (!string.IsNullOrEmpty(issuedUtcStr))
                {
                    DateTimeOffset issuedDto;
                    if (!DateTimeOffset.TryParse(
                        issuedUtcStr,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out issuedDto))
                    {
                        return false;
                    }
                    DateTime minEpoch = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                    if (issuedDto.UtcDateTime < minEpoch) return false;
                    DateTime effectiveNow = DateTime.UtcNow.AddSeconds(Interlocked.Read(ref _clockOffsetSeconds));
                    if (effectiveNow.Year >= 2025)
                    {
                        if (issuedDto.UtcDateTime > effectiveNow.AddDays(2)) return false;
                        if (issuedDto.UtcDateTime < effectiveNow.AddDays(-180)) return false;
                    }
                }

                string topSecret = ExtractJsonStr(json, "secret");

                MatchCollection objMatches = Regex.Matches(json, "\\{[^{}]*\"host\"\\s*:\\s*\"[^\"]+\"[^{}]*\\}");
                if (objMatches.Count == 0) return false;

                List<PixelServerNode> parsedNodes = new List<PixelServerNode>();
                foreach (Match om in objMatches)
                {
                    string item = om.Value;
                    string name = ExtractJsonStr(item, "name");
                    string region = ExtractJsonStr(item, "region");
                    string host = ExtractJsonStr(item, "host");
                    string sni = ExtractJsonStr(item, "sni");
                    string path = ExtractJsonStr(item, "path");
                    string nodeSecret = ExtractJsonStr(item, "secret");
                    int port = ExtractJsonInt(item, "port", 443);
                    bool tls = ExtractJsonBool(item, "tls", true);
                    bool mux = ExtractJsonBool(item, "mux", true);
                    bool frag = ExtractJsonBool(item, "frag", true);

                    if (string.IsNullOrEmpty(host) || port <= 0) continue;
                    if (!tls && !IsLoopbackHostString(host)) continue;

                    string effectiveSecret = !string.IsNullOrEmpty(nodeSecret)
                        ? nodeSecret
                        : (!string.IsNullOrEmpty(topSecret) ? topSecret : _secret);

                    parsedNodes.Add(new PixelServerNode
                    {
                        Name = string.IsNullOrEmpty(name) ? (host + ":" + port) : name,
                        Region = string.IsNullOrEmpty(region) ? "nl" : region.ToLowerInvariant(),
                        Host = host,
                        Port = port,
                        Secret = effectiveSecret,
                        Sni = string.IsNullOrEmpty(sni) ? host : sni,
                        UpgradePath = string.IsNullOrEmpty(path) ? (mux ? "/api/v3/telemetry/mux" : "/api/v2/telemetry/stream") : path,
                        UseTls = tls,
                        SupportsMuxV3 = mux,
                        EnableDpiSplit = frag,
                        IsCloudflareWs = host.StartsWith("ws.", StringComparison.OrdinalIgnoreCase),
                        LatencyMs = 22
                    });
                }

                if (parsedNodes.Count == 0) return false;

                string[] spkiPins = ExtractJsonStrArray(json, "spki_sha256");
                if (spkiPins == null || spkiPins.Length == 0) spkiPins = ExtractJsonStrArray(json, "cert_pins");
                if (spkiPins != null && spkiPins.Length > 0)
                {
                    var nextPins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { DEFAULT_PINNED_SPKI_SHA256 };
                    foreach (string rawPin in spkiPins)
                    {
                        string normPin = NormalizeSpkiPinToHex(rawPin);
                        if (!string.IsNullOrEmpty(normPin)) nextPins.Add(normPin);
                    }
                    _pinnedSpkiHashes = nextPins;
                }

                string latestVer = ExtractJsonStr(json, "latest_version");
                string updUrl = ExtractJsonStr(json, "update_url");
                string updSha = ExtractJsonStr(json, "update_sha256");
                string updNotes = ExtractJsonStr(json, "update_notes");
                if (!string.IsNullOrEmpty(latestVer))
                {
                    ManifestLatestVersion = latestVer;
                    ManifestUpdateUrl = updUrl;
                    ManifestUpdateSha256 = updSha;
                    ManifestUpdateNotes = updNotes;
                }
                string donUrl = ExtractJsonStr(json, "donate_url");
                if (!string.IsNullOrEmpty(donUrl))
                {
                    ManifestDonateUrl = donUrl;
                }

                string[] edgeArr = ExtractJsonStrArray(json, "edge_snis");
                if (edgeArr != null && edgeArr.Length > 0) _edgeSnis = edgeArr;

                string[] decoyArr = ExtractJsonStrArray(json, "decoy_snis");
                if (decoyArr != null && decoyArr.Length > 0) _decoySnis = decoyArr;

                lock (_nodesLock)
                {
                    SnapshotMeasuredNodesLocked();
                    _nodes.Clear();
                    _nodes.AddRange(parsedNodes);
                    RestoreNodeHealthFromSnapshotsLocked();
                }
                RebuildServerBypassSet();
                ManifestVersion = ver;
                ManifestSource = sourceLabel;
                if (ver > _persistedManifestVersion)
                {
                    _persistedManifestVersion = ver;
                    PersistManifestVersion(ver);
                }

                if (saveToCache && !string.IsNullOrEmpty(_manifestCachePath))
                {
                    try { File.WriteAllText(_manifestCachePath, env, Encoding.ASCII); } catch { }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string[] ExtractJsonStrArray(string obj, string key)
        {
            Match m = Regex.Match(obj, "\"" + key + "\"\\s*:\\s*\\[([^\\]]*)\\]", RegexOptions.IgnoreCase);
            if (!m.Success) return null;
            MatchCollection items = Regex.Matches(m.Groups[1].Value, "\"([^\"]+)\"");
            if (items.Count == 0) return null;
            List<string> list = new List<string>();
            foreach (Match im in items)
            {
                string val = im.Groups[1].Value.Trim();
                if (!string.IsNullOrEmpty(val)) list.Add(val);
            }
            return list.Count > 0 ? list.ToArray() : null;
        }

        private static string ExtractJsonStr(string obj, string key)
        {
            Match m = Regex.Match(obj, "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim() : "";
        }

        private static int ExtractJsonInt(string obj, string key, int defVal)
        {
            Match m = Regex.Match(obj, "\"" + key + "\"\\s*:\\s*(\\d+)", RegexOptions.IgnoreCase);
            int v;
            if (m.Success && int.TryParse(m.Groups[1].Value, out v)) return v;
            return defVal;
        }

        private static bool ExtractJsonBool(string obj, string key, bool defVal)
        {
            Match m = Regex.Match(obj, "\"" + key + "\"\\s*:\\s*(true|false)", RegexOptions.IgnoreCase);
            if (!m.Success) return defVal;
            return string.Equals(m.Groups[1].Value, "true", StringComparison.OrdinalIgnoreCase);
        }

        private static void TryLoadCachedManifest()
        {
            try
            {
                if (!string.IsNullOrEmpty(_manifestCachePath) && File.Exists(_manifestCachePath))
                {
                    string cached = File.ReadAllText(_manifestCachePath, Encoding.ASCII);
                    TryApplySignedManifestEnvelope(cached, "SignedCache", false);
                }
            }
            catch { }
        }

        private static void RefreshRemoteManifestInBackground()
        {
            if (!_enableRemoteManifestFetch) return;

            // Канал 1a: Прямой Edge-манифест PixelStore (несёт актуальные per-node secrets)
            string rawEdge = FetchUrlDirectBypassProxy("https://ai.pixelstore.space/nodes_v3.enc", null, 4500);
            if (!string.IsNullOrEmpty(rawEdge) && TryApplySignedManifestEnvelope(rawEdge, "Edge-Signed", true) && HasAnyNodeWithSecret())
            {
                return;
            }

            // Канал 1b: GitHub Raw (прямое соединение мимо системного прокси)
            if (!string.IsNullOrEmpty(_manifestGithubUrl))
            {
                string rawGh = FetchUrlDirectBypassProxy(_manifestGithubUrl, null, 4500);
                if (!string.IsNullOrEmpty(rawGh) && TryApplySignedManifestEnvelope(rawGh, "GitHub-Signed", true) && HasAnyNodeWithSecret())
                {
                    return;
                }
            }

            // Канал 2: DNS-over-HTTPS (Cloudflare 1.1.1.1 & Google 8.8.8.8 TXT запись _v3.pixelstore.space)
            if (!string.IsNullOrEmpty(_manifestDohDomain))
            {
                string[] dohUrls = new string[]
                {
                    "https://1.1.1.1/dns-query?name=" + Uri.EscapeDataString(_manifestDohDomain) + "&type=TXT",
                    "https://dns.google/resolve?name=" + Uri.EscapeDataString(_manifestDohDomain) + "&type=TXT"
                };
                foreach (string u in dohUrls)
                {
                    string dohJson = FetchUrlDirectBypassProxy(u, "application/dns-json", 4000);
                    if (string.IsNullOrEmpty(dohJson)) continue;
                    MatchCollection matches = Regex.Matches(dohJson, "\"data\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
                    foreach (Match mData in matches)
                    {
                        string rawVal = mData.Groups[1].Value;
                        if (rawVal.IndexOf("PTM3.", StringComparison.Ordinal) < 0) continue;
                        string cleaned = rawVal.Replace("\\\"", "").Replace(" ", "");
                        if (TryApplySignedManifestEnvelope(cleaned, "DoH-DNS-Signed", true) && HasAnyNodeWithSecret())
                        {
                            return;
                        }
                    }
                }
            }
        }

        private static string FetchUrlDirectBypassProxy(string url, string acceptHeader, int timeoutMs)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Proxy = null; // Всегда напрямую в обход WinINET системного прокси
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0";
                if (!string.IsNullOrEmpty(acceptHeader)) req.Accept = acceptHeader;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (Stream rs = resp.GetResponseStream())
                using (StreamReader sr = new StreamReader(rs, Encoding.UTF8))
                {
                    return sr.ReadToEnd();
                }
            }
            catch
            {
                return null;
            }
        }

        // =========================================================================
        // MUX LANE MANAGEMENT & MAINTENANCE LOOP
        // =========================================================================
        private static async Task EnsureInteractiveLaneWarmAsync(CancellationToken token)
        {
            try
            {
                await GetOrConnectMuxLaneAsync(false, token).ConfigureAwait(false);
            }
            catch { }
        }

        private static async Task MuxMaintenanceAndManifestLoopAsync(CancellationToken token)
        {
            // Фоновая проверка облачного манифеста через 1.5 сек после старта (0 мс задержки запуска туннеля)
            try
            {
                await Task.Delay(1500, token).ConfigureAwait(false);
                RefreshRemoteManifestInBackground();
            }
            catch { return; }

            int tickCount = 0;
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(20000, token).ConfigureAwait(false);
                }
                catch { break; }

                tickCount++;
                if (!string.IsNullOrEmpty(LastLicenseError)) continue;

                // 1. Live Keep-Alive PING на Lane 0 (и мягкий ресайкл перед порогом счётчика шифра)
                Pwp3MuxClient l0 = _laneInteractive;
                if (l0 != null && !l0.IsClosed)
                {
                    if (l0.IsCipherLimitNear)
                    {
                        if (l0.ActiveStreamCount == 0 && l0.ActiveUdpCount == 0 &&
                            Interlocked.CompareExchange(ref _laneInteractive, null, l0) == l0)
                        {
                            l0.Dispose();
                            await EnsureInteractiveLaneWarmAsync(token).ConfigureAwait(false);
                        }
                        else
                        {
                            await EnsureInteractiveLaneWarmAsync(token).ConfigureAwait(false);
                        }
                    }
                    else
                    {
                        try { l0.SendPing(); }
                        catch { l0.Shutdown(); }
                    }
                }
                else
                {
                    await EnsureInteractiveLaneWarmAsync(token).ConfigureAwait(false);
                }

                // 2. Lane 1 (Bulk/Media): закрываем при простое > 180 сек или приближении лимита счётчика шифра
                Pwp3MuxClient l1 = _laneBulk;
                if (l1 != null)
                {
                    if (l1.IsClosed)
                    {
                        Interlocked.CompareExchange(ref _laneBulk, null, l1);
                    }
                    else if (l1.ActiveStreamCount == 0 && l1.ActiveUdpCount == 0 &&
                             (l1.IsCipherLimitNear || (DateTime.UtcNow - l1.LastActivityUtc).TotalSeconds > 180.0))
                    {
                        if (Interlocked.CompareExchange(ref _laneBulk, null, l1) == l1)
                        {
                            l1.Dispose();
                        }
                    }
                    else
                    {
                        try { l1.SendPing(); } catch { l1.Shutdown(); }
                    }
                }

                // 3. Каждые ~30 минут проверяем обновления подписанного манифеста узлов
                if (tickCount % 90 == 0)
                {
                    RefreshRemoteManifestInBackground();
                }
            }
        }

        private static List<PixelServerNode> GetOrderedCandidateNodes(bool requireMuxV3)
        {
            List<PixelServerNode> list = new List<PixelServerNode>();
            string pref = _preferredRegion;
            lock (_nodesLock)
            {
                foreach (var n in _nodes)
                {
                    if (requireMuxV3 && !n.SupportsMuxV3) continue;
                    if (!string.Equals(pref, "auto", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(n.Region, pref, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    list.Add(n);
                }
                // Если для выбранного региона (например US до добавления узла) нет узлов — мягкий откат к auto
                if (list.Count == 0)
                {
                    foreach (var n in _nodes)
                    {
                        if (requireMuxV3 && !n.SupportsMuxV3) continue;
                        list.Add(n);
                    }
                }
            }

            list.Sort((a, b) =>
            {
                if (a.IsOnline != b.IsOnline) return a.IsOnline ? -1 : 1;
                bool aTimedOut = a.LatencyMs >= 9000 || a.FailCount > 0;
                bool bTimedOut = b.LatencyMs >= 9000 || b.FailCount > 0;
                if (aTimedOut != bTimedOut) return aTimedOut ? 1 : -1;
                bool aMeasuredOk = a.LastHealthMeasuredUtc != DateTime.MinValue && a.LatencyMs > 0 && !aTimedOut;
                bool bMeasuredOk = b.LastHealthMeasuredUtc != DateTime.MinValue && b.LatencyMs > 0 && !bTimedOut;
                if (aMeasuredOk != bMeasuredOk) return aMeasuredOk ? -1 : 1;
                if (a.ProbeVerified != b.ProbeVerified) return a.ProbeVerified ? -1 : 1;
                if (a.SupportsMuxV3 != b.SupportsMuxV3) return a.SupportsMuxV3 ? -1 : 1;
                if (a.UseTls != b.UseTls) return a.UseTls ? -1 : 1;
                if (a.IsCloudflareWs != b.IsCloudflareWs) return a.IsCloudflareWs ? 1 : -1; // Прямой Edge быстрее CF прокси
                if ((a.Port == 443) != (b.Port == 443) && Math.Abs(a.LatencyMs - b.LatencyMs) < 35)
                    return (a.Port == 443) ? -1 : 1;
                return a.LatencyMs.CompareTo(b.LatencyMs);
            });
            return list;
        }

        private static async Task<Pwp3MuxClient> GetOrConnectMuxLaneAsync(bool isBulkMediaLane, CancellationToken token)
        {
            Pwp3MuxClient existing = isBulkMediaLane ? _laneBulk : _laneInteractive;
            if (existing != null && !existing.IsClosed && !existing.IsCipherLimitNear) return existing;

            SemaphoreSlim sem = isBulkMediaLane ? _lane1ConnectSem : _lane0ConnectSem;
            await sem.WaitAsync(token).ConfigureAwait(false);
            try
            {
                existing = isBulkMediaLane ? _laneBulk : _laneInteractive;
                if (existing != null && !existing.IsClosed && !existing.IsCipherLimitNear) return existing;
                if (existing != null && existing.IsCipherLimitNear && existing.ActiveStreamCount == 0 && existing.ActiveUdpCount == 0)
                {
                    if (isBulkMediaLane) Interlocked.CompareExchange(ref _laneBulk, null, existing);
                    else Interlocked.CompareExchange(ref _laneInteractive, null, existing);
                    existing.Dispose();
                }
                if (!string.IsNullOrEmpty(LastLicenseError)) return null;

                if (!HasAnyNodeWithSecret())
                {
                    await Task.Run(() => EnsureManifestSecretsLoaded(4500)).ConfigureAwait(false);
                }

                List<PixelServerNode> candidates = GetOrderedCandidateNodes(true);
                foreach (var node in candidates)
                {
                    if (token.IsCancellationRequested || !IsRunning) break;
                    try
                    {
                        Pwp3MuxClient created = await Task.Run(() => CreateMuxSession(isBulkMediaLane ? "Lane1-Media" : "Lane0-AI", node, 2400)).ConfigureAwait(false);
                        if (created != null)
                        {
                            if (isBulkMediaLane) _laneBulk = created;
                            else _laneInteractive = created;

                            ActiveNodeName = node.Name;
                            ActiveNodeLatencyMs = node.LatencyMs;
                            ActiveProtocol = "PWP-3 Mux";
                            return created;
                        }
                    }
                    catch (Exception ex)
                    {
                        LastConnectError = node.Name + ": " + ex.Message;
                        if (!string.IsNullOrEmpty(LastLicenseError)) return null;
                        lock (_nodesLock)
                        {
                            node.FailCount++;
                            node.ProbeVerified = false;
                            node.LatencyMs = 9999;
                            node.LastHealthMeasuredUtc = DateTime.UtcNow;
                            if (node.FailCount >= 2 || (ex.Message != null && ex.Message.IndexOf("TSPU", StringComparison.OrdinalIgnoreCase) >= 0))
                            {
                                node.IsOnline = false;
                            }
                            SnapshotNodeHealthLocked(node);
                        }
                    }
                }
                return null;
            }
            finally
            {
                sem.Release();
            }
        }

        private static string ResolveEffectiveSni(PixelServerNode node, int rotationStep)
        {
            if (node == null) return DEFAULT_SNI;
            // Cloudflare WS требует точного Host/SNI своего поддомена
            if (node.IsCloudflareWs) return node.Sni;
            // Локальный стенд (127.0.0.1) сохраняет свой SNI, если не вращали
            if (rotationStep <= 0 && !string.IsNullOrEmpty(node.Sni)) return node.Sni;

            // Порт 443 за Nginx SSL Stream Map маршрутизирует по белым поддоменам edge_snis
            if (node.Port == 443)
            {
                string[] pool = _edgeSnis;
                if (pool != null && pool.Length > 0)
                {
                    int idx = ((rotationStep % pool.Length) + pool.Length) % pool.Length;
                    return pool[idx];
                }
                return node.Sni;
            }

            // Прямые TLS-порты Go-сервера (:25443, :24443) принимают любой decoy_snis!
            if (node.UseTls)
            {
                string[] pool = _decoySnis;
                if (pool != null && pool.Length > 0)
                {
                    int idx = ((rotationStep % pool.Length) + pool.Length) % pool.Length;
                    return pool[idx];
                }
            }
            return node.Sni;
        }

        /// <summary>
        /// Anti-DPI Shield v2: Детектор 16-КБ заморозки ТСПУ (probe.internal.pixel:36 = 36 864 байт высокой энтропии).
        /// Возвращает true, если поток прошёл без зависания после 16..24 КБ (или если старый узел мгновенно вернул RST).
        /// </summary>
        internal static async Task<bool> Run32KbAntiFreezeProbeAsync(Pwp3MuxClient mux, int timeoutMs = 3200)
        {
            if (mux == null || mux.IsClosed) return false;
            const int ExpectedProbeBytes = 36 * 1024;
            int totalRead = 0;
            bool gotFin = false;

            using (CancellationTokenSource probeCts = new CancellationTokenSource(timeoutMs))
            {
                ClientMuxStream st = null;
                try
                {
                    st = mux.OpenTcpStream("probe.internal.pixel", 36, null, true);
                    while (!probeCts.IsCancellationRequested)
                    {
                        MuxRxChunk chunk = await st.DequeueInboundAsync(probeCts.Token).ConfigureAwait(false);
                        if (chunk.Data != null && chunk.Data.Length > 0)
                        {
                            totalRead += chunk.Data.Length;
                            st.NotifyBytesWrittenToLocal(chunk.Data.Length);
                        }
                        if (chunk.IsFin)
                        {
                            gotFin = true;
                            break;
                        }
                        if (chunk.IsRst)
                        {
                            // Если 0 байт и быстрый RST без таймаута — старый узел без probe.internal.pixel (не блокировка ТСПУ)
                            if (totalRead == 0 && !probeCts.IsCancellationRequested && !mux.IsClosed)
                            {
                                return true;
                            }
                            break;
                        }
                    }
                }
                catch
                {
                    return false;
                }
                finally
                {
                    if (st != null) st.Dispose();
                }
            }

            return gotFin && totalRead >= ExpectedProbeBytes;
        }

        private static Pwp3MuxClient CreateMuxSession(string laneName, PixelServerNode node, int connectTimeoutMs = 2400)
        {
            if (connectTimeoutMs <= 0) connectTimeoutMs = 2400;
            Exception lastErr = null;
            bool runProbe = _enableAntiFreezeProbe &&
                            node.UseTls &&
                            !node.ProbeVerified;

            int maxAttempts = (_enableDpiFragment && node.EnableDpiSplit && node.UseTls) ? 2 : 1;
            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                TcpClient tcp = new TcpClient();
                Pwp3MuxClient mux = null;
                try
                {
                    tcp.NoDelay = true;
                    tcp.ReceiveTimeout = 12000;
                    tcp.SendTimeout = 12000;

                    int profileToUse = _activeDpiProfile;
                    string effectiveSni = ResolveEffectiveSni(node, _sniRotationIndex);

                    Stopwatch sw = Stopwatch.StartNew();
                    IAsyncResult ar = tcp.BeginConnect(node.Host, node.Port, null, null);
                    WaitHandle wh = ar.AsyncWaitHandle;
                    try
                    {
                        if (!wh.WaitOne(connectTimeoutMs))
                        {
                            try { tcp.Close(); } catch { }
                            try { ((IDisposable)tcp).Dispose(); } catch { }
                            throw new TimeoutException("Mux connect timeout to " + node.Name);
                        }
                        tcp.EndConnect(ar);
                    }
                    finally
                    {
                        try { wh.Close(); } catch { }
                    }
                    EnableTcpKeepAlive(tcp.Client);

                    PixelStreamCipher enc;
                    PixelStreamCipher dec;
                    bool nativeTlsBulk;
                    bool negotiatedMuxV3;
                    Stream transport = HandshakeWithServer(
                        tcp, node, true,
                        out enc, out dec, out nativeTlsBulk, out negotiatedMuxV3,
                        effectiveSni, profileToUse);
                    sw.Stop();

                    if (!negotiatedMuxV3)
                    {
                        // Узел поддерживает только PWP-2 (например старый порт 2087) -> помечаем для PWP-2 фоллбэка
                        node.SupportsMuxV3 = false;
                        try { transport.Close(); } catch { }
                        try { tcp.Close(); } catch { }
                        return null;
                    }

                    int measuredRtt = (int)Math.Max(1L, sw.ElapsedMilliseconds / 2);
                    mux = new Pwp3MuxClient(laneName, node, tcp, transport, enc, dec, nativeTlsBulk);

                    if (runProbe)
                    {
                        bool probeOk = Run32KbAntiFreezeProbeAsync(mux, 3200).GetAwaiter().GetResult();
                        LastAntiFreezeProbePassed = probeOk;
                        if (!probeOk)
                        {
                            mux.Dispose();
                            mux = null;
                            throw new IOException("TSPU 16KB stream freeze detected on " + node.Name + " (" + effectiveSni + ")");
                        }
                        node.ProbeVerified = true;
                    }

                    ActiveEffectiveSni = effectiveSni;
                    lock (_nodesLock)
                    {
                        node.IsOnline = true;
                        node.FailCount = 0;
                        node.LatencyMs = measuredRtt;
                        node.LastHealthMeasuredUtc = DateTime.UtcNow;
                        SnapshotNodeHealthLocked(node);
                    }
                    return mux;
                }
                catch (UnauthorizedAccessException)
                {
                    if (mux != null) mux.Dispose();
                    try { tcp.Close(); } catch { }
                    try { ((IDisposable)tcp).Dispose(); } catch { }
                    throw;
                }
                catch (TimeoutException tex)
                {
                    lastErr = tex;
                    if (mux != null) mux.Dispose();
                    try { tcp.Close(); } catch { }
                    try { ((IDisposable)tcp).Dispose(); } catch { }
                    lock (_nodesLock)
                    {
                        node.IsOnline = false;
                        node.ProbeVerified = false;
                        node.FailCount++;
                        node.LatencyMs = 9999;
                        node.LastHealthMeasuredUtc = DateTime.UtcNow;
                        SnapshotNodeHealthLocked(node);
                    }
                    break;
                }
                catch (Exception ex)
                {
                    lastErr = ex;
                    if (mux != null) mux.Dispose();
                    try { tcp.Close(); } catch { }
                    try { ((IDisposable)tcp).Dispose(); } catch { }

                    if (ex.Message != null && ex.Message.IndexOf("CLOCK_RESYNCED", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (maxAttempts < 2) maxAttempts = 2;
                        continue;
                    }

                    // Эскалация Anti-DPI Shield v2: меняем профиль фрагментации ClientHello + вращаем SNI
                    if (_enableDpiFragment && node.EnableDpiSplit && node.UseTls)
                    {
                        _activeDpiProfile = (_activeDpiProfile + 1) % 3;
                        Interlocked.Increment(ref _sniRotationIndex);
                        AntiFreezeEscalations++;
                    }
                }
            }

            if (lastErr != null) throw lastErr;
            return null;
        }

        // =========================================================================
        // ROUTING, DUAL-LANE CLASSIFICATION & LOCAL ACCEPT LOOP
        // =========================================================================
        private static bool HostMatchesDomain(string host, string dom)
        {
            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(dom)) return false;
            string nh = host.Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
            string nd = dom.Trim().TrimEnd('.').ToLowerInvariant();
            if (nh.Length == 0 || nd.Length == 0) return false;
            return nh.Equals(nd, StringComparison.Ordinal) || nh.EndsWith("." + nd, StringComparison.Ordinal);
        }

        private static bool IsBulkMediaHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            if (HostMatchesDomain(host, "googlevideo.com") || HostMatchesDomain(host, "ytimg.com") ||
                HostMatchesDomain(host, "youtube.com") || HostMatchesDomain(host, "youtu.be") ||
                HostMatchesDomain(host, "ggpht.com") || HostMatchesDomain(host, "youtubei.googleapis.com") ||
                HostMatchesDomain(host, "nflxvideo.net") || HostMatchesDomain(host, "netflix.com") ||
                HostMatchesDomain(host, "ttvnw.net") || HostMatchesDomain(host, "jtvnw.net") ||
                HostMatchesDomain(host, "twitch.tv") || HostMatchesDomain(host, "scdn.co") ||
                HostMatchesDomain(host, "spotifycdn.com") || HostMatchesDomain(host, "cdn.discordapp.com") ||
                HostMatchesDomain(host, "media.discordapp.net") || HostMatchesDomain(host, "fbcdn.net") ||
                HostMatchesDomain(host, "cdninstagram.com") || HostMatchesDomain(host, "tiktokcdn.com"))
            {
                return true;
            }
            return false;
        }

        private static bool MatchesDomainSet(string host, HashSet<string> set)
        {
            if (set == null || set.Count == 0) return false;
            string nh = host.Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
            if (set.Contains(nh)) return true;
            int dot = nh.IndexOf('.');
            while (dot > 0 && dot + 1 < nh.Length)
            {
                string parent = nh.Substring(dot + 1);
                if (set.Contains(parent)) return true;
                dot = nh.IndexOf('.', dot + 1);
            }
            return false;
        }

        private static bool IsPrivateOrServerLoopbackHost(string h)
        {
            if (string.IsNullOrEmpty(h)) return true;
            string clean = h.Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
            if (clean == "localhost" || clean == "::1" || clean == "0.0.0.0") return true;
            HashSet<string> srvBypass = _serverHostBypass;
            if (srvBypass != null && srvBypass.Contains(clean)) return true;
            if (HostMatchesDomain(clean, "pixelstore.space")) return true;

            IPAddress ip;
            if (IPAddress.TryParse(clean, out ip))
            {
                if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
                if (IPAddress.IsLoopback(ip)) return true;
                byte[] b = ip.GetAddressBytes();
                if (ip.AddressFamily == AddressFamily.InterNetwork && b.Length == 4)
                {
                    if (b[0] == 10 || b[0] == 127 || b[0] == 0) return true;
                    if (b[0] == 192 && b[1] == 168) return true;
                    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                    if (b[0] == 169 && b[1] == 254) return true;
                    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
                }
                else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && b.Length == 16)
                {
                    if (ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6Loopback)) return true;
                    if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return true;
                    if ((b[0] & 0xFE) == 0xFC) return true;
                }
            }
            return false;
        }

        private static bool IsTelegramDcIp(IPAddress ip)
        {
            if (ip == null) return false;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

            byte[] b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork && b.Length == 4)
            {
                if (b[0] == 149 && b[1] == 154 && b[2] >= 160 && b[2] <= 175) return true; // 149.154.160.0/20
                if (b[0] == 91 && b[1] == 108)
                {
                    if ((b[2] >= 4 && b[2] <= 23) || (b[2] >= 56 && b[2] <= 59)) return true; // 91.108.4-23, 56-59
                }
                if (b[0] == 91 && b[1] == 105 && (b[2] == 192 || b[2] == 193)) return true; // 91.105.192.0/23
                if (b[0] == 185 && b[1] == 76 && b[2] == 151) return true; // 185.76.151.0/24
                if (b[0] == 95 && b[1] == 161 && b[2] >= 64 && b[2] <= 79) return true; // 95.161.64.0/20
                return false;
            }
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && b.Length == 16)
            {
                // 2001:b28:f23d::/48
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0b && b[3] == 0x28 && b[4] == 0xf2 && b[5] == 0x3d) return true;
                // 2001:67c:4e8::/48
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x06 && b[3] == 0x7c && b[4] == 0x04 && b[5] == 0xe8) return true;
                // 2a0a:f280::/32
                if (b[0] == 0x2a && b[1] == 0x0a && b[2] == 0xf2 && b[3] == 0x80) return true;
                return false;
            }
            return false;
        }

        private static void ClassifyRoute(string host, out bool bypassDirect, out string ruleLabel)
        {
            bypassDirect = false;
            ruleLabel = "proxy-default";
            if (string.IsNullOrEmpty(host)) return;
            string h = host.Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

            if (IsPrivateOrServerLoopbackHost(h)) { bypassDirect = true; ruleLabel = "loopback-private"; return; }
            if (MatchesDomainSet(h, _proxyDomains)) { bypassDirect = false; ruleLabel = "proxy-rule"; return; }

            IPAddress parsedIp;
            if (IPAddress.TryParse(h, out parsedIp) && IsTelegramDcIp(parsedIp) && MatchesDomainSet("telegram.org", _proxyDomains))
            { bypassDirect = false; ruleLabel = "telegram-dc"; return; }

            if (HostMatchesDomain(h, "googleapis.com") || HostMatchesDomain(h, "antigravity.google") ||
                HostMatchesDomain(h, "antigravity-unleash.goog") || HostMatchesDomain(h, "1e100.net") ||
                HostMatchesDomain(h, "gstatic.com") || HostMatchesDomain(h, "google.com") || HostMatchesDomain(h, "gvt1.com"))
            { bypassDirect = false; ruleLabel = "antigravity-core"; return; }

            if (h.EndsWith(".ru", StringComparison.Ordinal) || h.EndsWith(".su", StringComparison.Ordinal) ||
                h.EndsWith(".xn--p1ai", StringComparison.Ordinal) || h.EndsWith(".by", StringComparison.Ordinal) ||
                HostMatchesDomain(h, "yastatic.net") || HostMatchesDomain(h, "yandex.net") ||
                HostMatchesDomain(h, "userapi.com") || HostMatchesDomain(h, "vkuseraudio.net") ||
                HostMatchesDomain(h, "wbstatic.net") || HostMatchesDomain(h, "ozonusercontent.com") ||
                HostMatchesDomain(h, "ozon.kz") || HostMatchesDomain(h, "ozon.tech") ||
                HostMatchesDomain(h, "ozon.com") || HostMatchesDomain(h, "ozon.travel") ||
                HostMatchesDomain(h, "ozon.team") || HostMatchesDomain(h, "ozonru.me") ||
                HostMatchesDomain(h, "ozonrucn.me") || HostMatchesDomain(h, "ozoncom.me") ||
                HostMatchesDomain(h, "steamcontent.com") || HostMatchesDomain(h, "steampowered.com"))
            { bypassDirect = true; ruleLabel = "ru-direct"; return; }

            if (MatchesDomainSet(h, _directDomains)) { bypassDirect = true; ruleLabel = "direct-rule"; return; }

            bypassDirect = !_defaultOutboundIsProxy;
            ruleLabel = bypassDirect ? "default-direct" : "default-proxy";
        }

        private static bool ShouldBypassDirect(string host)
        {
            bool bypass;
            string rule;
            ClassifyRoute(host, out bypass, out rule);
            return bypass;
        }

        private static async Task AcceptLoopAsync(TcpListener listener, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                bool hadError = false;
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    var unused = Task.Run(() => HandleLocalClientAsync(client));
                }
                catch
                {
                    if (token.IsCancellationRequested) break;
                    hadError = true;
                }
                if (hadError)
                {
                    await Task.Delay(25).ConfigureAwait(false);
                }
            }
        }

        private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int r = await s.ReadAsync(buf, offset + total, count - total).ConfigureAwait(false);
                if (r <= 0) return false;
                total += r;
            }
            return true;
        }

        private static int FindHeaderTerminator(byte[] buf, int len)
        {
            for (int i = 0; i <= len - 4; i++)
            {
                if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
                {
                    return i;
                }
            }
            return -1;
        }

        private static async Task<Tuple<string, byte[]>> ReadHttpRequestHeadersBufferedAsync(NetworkStream stream, byte firstByte, int maxHeaderBytes = 8192)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(firstByte);
                byte[] chunk = new byte[1024];
                while (ms.Length < maxHeaderBytes)
                {
                    byte[] cur = ms.GetBuffer();
                    int len = (int)ms.Length;
                    int foundIdx = FindHeaderTerminator(cur, len);
                    if (foundIdx >= 0)
                    {
                        int hdrEnd = foundIdx + 4;
                        string hdr = Encoding.ASCII.GetString(cur, 0, hdrEnd);
                        byte[] extra = null;
                        if (len > hdrEnd)
                        {
                            extra = new byte[len - hdrEnd];
                            Buffer.BlockCopy(cur, hdrEnd, extra, 0, extra.Length);
                        }
                        return Tuple.Create(hdr, extra);
                    }

                    int maxRead = Math.Min(chunk.Length, maxHeaderBytes - len);
                    int nr = await stream.ReadAsync(chunk, 0, maxRead).ConfigureAwait(false);
                    if (nr <= 0) return null;
                    ms.Write(chunk, 0, nr);
                }

                byte[] finalBuf = ms.GetBuffer();
                int finalLen = (int)ms.Length;
                int finalIdx = FindHeaderTerminator(finalBuf, finalLen);
                if (finalIdx >= 0)
                {
                    int hdrEnd = finalIdx + 4;
                    string hdr = Encoding.ASCII.GetString(finalBuf, 0, hdrEnd);
                    byte[] extra = null;
                    if (finalLen > hdrEnd)
                    {
                        extra = new byte[finalLen - hdrEnd];
                        Buffer.BlockCopy(finalBuf, hdrEnd, extra, 0, extra.Length);
                    }
                    return Tuple.Create(hdr, extra);
                }
                return null;
            }
        }

        private static async Task HandleLocalClientAsync(TcpClient localClient)
        {
            Interlocked.Increment(ref _activeConns);
            localClient.NoDelay = true;
            localClient.ReceiveTimeout = 30000;
            localClient.SendTimeout = 30000;
            EnableTcpKeepAlive(localClient.Client);

            try
            {
                NetworkStream localStream = localClient.GetStream();
                byte[] fb = new byte[1];
                int r0 = await localStream.ReadAsync(fb, 0, 1).ConfigureAwait(false);
                if (r0 <= 0) return;
                int firstByte = fb[0];

                string targetHost = null;
                int targetPort = 0;
                byte[] initialPayload = null;
                bool isHttpConnect = false;
                bool suppressRadar = false;
                bool isSocks5 = (firstByte == 0x05);

                if (isSocks5)
                {
                    byte[] nmBuf = new byte[1];
                    if (!await ReadExactAsync(localStream, nmBuf, 0, 1).ConfigureAwait(false)) return;
                    int nMethods = nmBuf[0];
                    if (nMethods <= 0)
                    {
                        await localStream.WriteAsync(new byte[] { 0x05, 0xFF }, 0, 2).ConfigureAwait(false);
                        return;
                    }
                    byte[] methods = new byte[nMethods];
                    if (!await ReadExactAsync(localStream, methods, 0, nMethods).ConfigureAwait(false)) return;
                    bool hasNoAuth = false;
                    for (int i = 0; i < nMethods; i++)
                    {
                        if (methods[i] == 0x00) { hasNoAuth = true; break; }
                    }
                    if (!hasNoAuth)
                    {
                        await localStream.WriteAsync(new byte[] { 0x05, 0xFF }, 0, 2).ConfigureAwait(false);
                        return;
                    }
                    await localStream.WriteAsync(new byte[] { 0x05, 0x00 }, 0, 2).ConfigureAwait(false);

                    byte[] reqHdr = new byte[4];
                    if (!await ReadExactAsync(localStream, reqHdr, 0, 4).ConfigureAwait(false)) return;
                    byte cmd = reqHdr[1];
                    byte atyp = reqHdr[3];

                    string parsedAddr;
                    int parsedPort;
                    if (!ReadSocksAddress(localStream, atyp, out parsedAddr, out parsedPort))
                    {
                        return;
                    }

                    // RFC 1928 SOCKS5 UDP ASSOCIATE (CMD = 0x03) — для голоса Discord / WebRTC / QUIC без драйверов!
                    if (cmd == 0x03)
                    {
                        await HandleSocks5UdpAssociateAsync(localClient, localStream).ConfigureAwait(false);
                        return;
                    }

                    if (cmd != 0x01)
                    {
                        await localStream.WriteAsync(new byte[] { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10).ConfigureAwait(false);
                        return;
                    }

                    targetHost = parsedAddr;
                    targetPort = parsedPort;
                }
                else
                {
                    Tuple<string, byte[]> hdrRead = await ReadHttpRequestHeadersBufferedAsync(localStream, (byte)firstByte, 8192).ConfigureAwait(false);
                    if (hdrRead == null) return;
                    string headerStr = hdrRead.Item1;
                    byte[] extraBody = hdrRead.Item2;
                    suppressRadar = string.Equals((ExtractHeader(headerStr, "X-Pixel-Internal-Probe") ?? "").Trim(), "1", StringComparison.Ordinal);

                    string firstLine = headerStr.Split(new[] { "\r\n" }, StringSplitOptions.None)[0];
                    string[] parts = firstLine.Split(' ');
                    if (parts.Length < 2) return;

                    string method = parts[0].ToUpperInvariant();
                    string rawTarget = parts[1];

                    if (rawTarget.StartsWith("/proxy.pac", StringComparison.OrdinalIgnoreCase) ||
                        rawTarget.StartsWith("/__pixelcore/", StringComparison.OrdinalIgnoreCase))
                    {
                        await HandleLocalControlHttpAsync(localClient, localStream, method, rawTarget, headerStr, extraBody).ConfigureAwait(false);
                        return;
                    }

                    if (method == "CONNECT")
                    {
                        isHttpConnect = true;
                        ParseConnectHostPort(rawTarget, out targetHost, out targetPort);
                        if (extraBody != null && extraBody.Length > 0)
                        {
                            initialPayload = extraBody;
                        }
                    }
                    else
                    {
                        Uri uri;
                        if (!Uri.TryCreate(rawTarget, UriKind.Absolute, out uri)) return;
                        targetHost = uri.Host.Trim('[', ']');
                        targetPort = uri.Port > 0 ? uri.Port : 80;
                        byte[] reqHead = RewritePlainHttpProxyRequest(headerStr, uri);
                        if (extraBody != null && extraBody.Length > 0)
                        {
                            initialPayload = new byte[reqHead.Length + extraBody.Length];
                            Buffer.BlockCopy(reqHead, 0, initialPayload, 0, reqHead.Length);
                            Buffer.BlockCopy(extraBody, 0, initialPayload, reqHead.Length, extraBody.Length);
                        }
                        else
                        {
                            initialPayload = reqHead;
                        }
                    }
                }

                if (string.IsNullOrEmpty(targetHost) || targetPort <= 0) return;

                bool bypassDirect;
                string routeRule;
                ClassifyRoute(targetHost, out bypassDirect, out routeRule);

                if (!suppressRadar && !string.Equals(targetHost, "127.0.0.1", StringComparison.OrdinalIgnoreCase))
                {
                    int clientPid = 0;
                    string clientProc = "";
                    try
                    {
                        IPEndPoint rep = localClient.Client.RemoteEndPoint as IPEndPoint;
                        if (rep != null && IPAddress.IsLoopback(rep.Address))
                        {
                            Win32TcpProcessResolver.ResolveLocalPortOwner(rep.Port, out clientPid, out clientProc);
                        }
                    }
                    catch { }
                    string protoName = isSocks5 ? "SOCKS5" : (isHttpConnect ? "HTTPS" : "HTTP");
                    RecordLiveRoute(
                        clientPid,
                        string.IsNullOrEmpty(clientProc) ? "local" : clientProc,
                        targetHost,
                        targetPort,
                        protoName,
                        bypassDirect ? "direct" : "tunnel",
                        routeRule,
                        bypassDirect ? "DIRECT" : (ActiveNodeName ?? "NL-Edge"),
                        bypassDirect ? "direct" : "ai",
                        bypassDirect ? 0 : ActiveNodeLatencyMs,
                        "");
                }

                if (bypassDirect)
                {
                    await BridgeDirectAsync(localClient, localStream, targetHost, targetPort, isHttpConnect, isSocks5, initialPayload).ConfigureAwait(false);
                }
                else
                {
                    await ForwardProxyTrafficV3Async(localClient, localStream, targetHost, targetPort, isHttpConnect, isSocks5, initialPayload).ConfigureAwait(false);
                }
            }
            catch
            {
            }
            finally
            {
                try { localClient.Close(); } catch { }
                Interlocked.Decrement(ref _activeConns);
            }
        }

        private static bool ReadSocksAddress(Stream s, byte atyp, out string host, out int port)
        {
            host = null;
            port = 0;
            if (atyp == 0x01)
            {
                byte[] ipBytes = new byte[4];
                ReadExactInternal(s, ipBytes, 0, 4);
                host = new IPAddress(ipBytes).ToString();
            }
            else if (atyp == 0x03)
            {
                int domLen = s.ReadByte();
                if (domLen <= 0) return false;
                byte[] domBytes = new byte[domLen];
                ReadExactInternal(s, domBytes, 0, domLen);
                host = Encoding.ASCII.GetString(domBytes).Trim('[', ']');
            }
            else if (atyp == 0x04)
            {
                byte[] ip6Bytes = new byte[16];
                ReadExactInternal(s, ip6Bytes, 0, 16);
                host = new IPAddress(ip6Bytes).ToString();
            }
            else
            {
                return false;
            }

            byte[] portBytes = new byte[2];
            ReadExactInternal(s, portBytes, 0, 2);
            port = (portBytes[0] << 8) | portBytes[1];
            return true;
        }

        // =========================================================================
        // 0-RTT OPTIMISTIC CONNECT + DUAL-LANE PWP-3 STREAM RELAY
        // =========================================================================
        private static async Task ForwardProxyTrafficV3Async(
            TcpClient localClient,
            NetworkStream localStream,
            string targetHost,
            int targetPort,
            bool isHttpConnect,
            bool isSocks5,
            byte[] initialPayload)
        {
            if (!string.IsNullOrEmpty(LastLicenseError))
            {
                SendLocalProxyError(localStream, isHttpConnect, isSocks5);
                return;
            }

            CancellationToken serviceToken = (_cts != null) ? _cts.Token : CancellationToken.None;
            bool isBulk = IsBulkMediaHost(targetHost);

            // Пытаемся открыть мультиплексированный поток PWP-3 (с 0-RTT склейкой ClientHello)
            Pwp3MuxClient mux = await GetOrConnectMuxLaneAsync(isBulk, serviceToken).ConfigureAwait(false);
            if (mux != null)
            {
                // 0-RTT Optimistic Connect: мгновенно отдаём 200 OK локальному клиенту и ловим первый пакет (TLS ClientHello)
                bool proxyAckSent = false;
                if (isHttpConnect || isSocks5)
                {
                    SendLocalProxySuccess(localStream, isHttpConnect, isSocks5);
                    proxyAckSent = true;
                    if (initialPayload == null)
                    {
                        initialPayload = PeekInitialClientHello(localClient, localStream, 18);
                    }
                }

                ClientMuxStream muxStream = null;
                for (int muxAttempt = 0; muxAttempt < 2; muxAttempt++)
                {
                    bool needReconnect = false;
                    try
                    {
                        muxStream = mux.OpenTcpStream(targetHost, targetPort, initialPayload);
                        break;
                    }
                    catch
                    {
                        needReconnect = true;
                    }
                    if (needReconnect)
                    {
                        mux = await GetOrConnectMuxLaneAsync(isBulk, serviceToken).ConfigureAwait(false);
                        if (mux == null) break;
                    }
                }

                if (muxStream != null)
                {
                    using (muxStream)
                    {
                        localStream.ReadTimeout = 3600000;
                        localStream.WriteTimeout = 3600000;

                        CancellationTokenSource bridgeCts = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
                        try
                        {
                            Task upTask = PumpLocalToMuxStreamAsync(localStream, muxStream, bridgeCts.Token);
                            Task downTask = PumpMuxStreamToLocalAsync(muxStream, localStream, bridgeCts.Token);
                            Task finished = await Task.WhenAny(upTask, downTask).ConfigureAwait(false);
                            if (finished == upTask)
                            {
                                await Task.WhenAny(downTask, Task.Delay(1800000, bridgeCts.Token)).ConfigureAwait(false);
                            }
                            else
                            {
                                bridgeCts.Cancel();
                            }
                            try { localClient.Client.Shutdown(SocketShutdown.Both); } catch { }
                        }
                        finally
                        {
                            bridgeCts.Cancel();
                            bridgeCts.Dispose();
                        }
                    }
                    return;
                }

                if (proxyAckSent)
                {
                    // Если прокси-ответ уже ушёл, но оба узла Mux недоступны — корректно закрываем локальный сокет
                    return;
                }
            }

            // Бесшовный фоллбэк на PWP-2 (если активный резервный узел работает только на PWP-2)
            await ForwardProxyTrafficPwp2FallbackAsync(localClient, localStream, targetHost, targetPort, isHttpConnect, isSocks5, initialPayload).ConfigureAwait(false);
        }

        private static byte[] PeekInitialClientHello(TcpClient localClient, NetworkStream localStream, int waitMicrosMs)
        {
            try
            {
                Socket sock = localClient.Client;
                if (sock == null) return null;
                if (sock.Available == 0)
                {
                    sock.Poll(waitMicrosMs * 1000, SelectMode.SelectRead);
                }
                int avail = sock.Available;
                if (avail <= 0) return null;
                int toRead = Math.Min(avail, 16384);
                byte[] buf = new byte[toRead];
                int n = localStream.Read(buf, 0, toRead);
                if (n <= 0) return null;
                if (n == buf.Length) return buf;
                byte[] trimmed = new byte[n];
                Buffer.BlockCopy(buf, 0, trimmed, 0, n);
                return trimmed;
            }
            catch
            {
                return null;
            }
        }

        private static async Task PumpLocalToMuxStreamAsync(NetworkStream localStream, ClientMuxStream muxStream, CancellationToken token)
        {
            byte[] buf = new byte[Pwp3MuxClient.MaxChunkSize];
            try
            {
                while (!token.IsCancellationRequested && !muxStream.IsClosed)
                {
                    int n = await localStream.ReadAsync(buf, 0, buf.Length, token).ConfigureAwait(false);
                    if (n <= 0)
                    {
                        try { muxStream.Session.WriteFrame(Pwp3MuxClient.FrameFin, muxStream.StreamId, 0, null, 0, 0, 0); } catch { }
                        return;
                    }

                    int offset = 0;
                    while (offset < n)
                    {
                        int grant = await muxStream.AcquireSendWindowAsync(n - offset, token).ConfigureAwait(false);
                        if (grant <= 0) return;
                        muxStream.Session.WriteFrame(Pwp3MuxClient.FrameData, muxStream.StreamId, 0, buf, offset, grant, 0);
                        Interlocked.Add(ref _totalBytesUp, grant);
                        offset += grant;
                    }
                }
            }
            catch
            {
                try { muxStream.Session.WriteFrame(Pwp3MuxClient.FrameRst, muxStream.StreamId, 0, new byte[] { 0x01 }, 0, 1, 0); } catch { }
            }
        }

        private static async Task PumpMuxStreamToLocalAsync(ClientMuxStream muxStream, NetworkStream localStream, CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    MuxRxChunk chunk = await muxStream.DequeueInboundAsync(token).ConfigureAwait(false);
                    if (chunk.Data != null && chunk.Data.Length > 0)
                    {
                        await localStream.WriteAsync(chunk.Data, 0, chunk.Data.Length, token).ConfigureAwait(false);
                        await localStream.FlushAsync(token).ConfigureAwait(false);
                        muxStream.NotifyBytesWrittenToLocal(chunk.Data.Length);
                    }
                    if (chunk.IsFin || chunk.IsRst)
                    {
                        return;
                    }
                }
            }
            catch
            {
                try { muxStream.Session.WriteFrame(Pwp3MuxClient.FrameRst, muxStream.StreamId, 0, new byte[] { 0x02 }, 0, 1, 0); } catch { }
            }
        }

        // =========================================================================
        // RFC 1928 SOCKS5 UDP ASSOCIATE (DISCORD VOICE / WEBRTC / QUIC OVER PWP-3)
        // =========================================================================
        private static async Task HandleSocks5UdpAssociateAsync(TcpClient controlTcp, NetworkStream controlStream)
        {
            CancellationToken serviceToken = (_cts != null) ? _cts.Token : CancellationToken.None;
            Pwp3MuxClient mux = await GetOrConnectMuxLaneAsync(false, serviceToken).ConfigureAwait(false);
            if (mux == null)
            {
                await controlStream.WriteAsync(new byte[] { 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10).ConfigureAwait(false);
                return;
            }

            IPEndPoint ctrlEp = null;
            try { ctrlEp = controlTcp.Client.LocalEndPoint as IPEndPoint; } catch { }
            bool isV6 = (ctrlEp != null && ctrlEp.AddressFamily == AddressFamily.InterNetworkV6);

            Socket localUdp = new Socket(isV6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            Socket directUdp4 = null;
            Socket directUdp6 = null;
            object directLock = new object();
            uint assocId = 0;

            try
            {
                localUdp.Bind(new IPEndPoint(isV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
                int boundPort = ((IPEndPoint)localUdp.LocalEndPoint).Port;

                EndPoint learnedClientEp = null;
                object epLock = new object();

                assocId = mux.RegisterUdpAssociation((payload, len) =>
                {
                    if (len < 4) return;
                    int hostLen = payload[0];
                    if (hostLen <= 0 || 1 + hostLen + 2 > len) return;
                    string srcHost = Encoding.ASCII.GetString(payload, 1, hostLen);
                    int srcPort = (payload[1 + hostLen] << 8) | payload[1 + hostLen + 1];
                    int dgramOff = 1 + hostLen + 2;
                    int dgramLen = len - dgramOff;
                    if (dgramLen <= 0) return;

                    EndPoint targetEp;
                    lock (epLock) { targetEp = learnedClientEp; }
                    if (targetEp == null) return;

                    byte[] socksPkt = BuildSocks5UdpPacket(srcHost, srcPort, payload, dgramOff, dgramLen);
                    if (socksPkt != null)
                    {
                        try { localUdp.SendTo(socksPkt, 0, socksPkt.Length, SocketFlags.None, targetEp); } catch { }
                    }
                });

                byte[] reply;
                if (isV6)
                {
                    reply = new byte[4 + 16 + 2];
                    reply[0] = 0x05;
                    reply[1] = 0x00;
                    reply[2] = 0x00;
                    reply[3] = 0x04;
                    Buffer.BlockCopy(IPAddress.IPv6Loopback.GetAddressBytes(), 0, reply, 4, 16);
                    reply[20] = (byte)((boundPort >> 8) & 0xFF);
                    reply[21] = (byte)(boundPort & 0xFF);
                }
                else
                {
                    reply = new byte[]
                    {
                        0x05, 0x00, 0x00, 0x01,
                        127, 0, 0, 1,
                        (byte)((boundPort >> 8) & 0xFF),
                        (byte)(boundPort & 0xFF)
                    };
                }
                await controlStream.WriteAsync(reply, 0, reply.Length).ConfigureAwait(false);
                await controlStream.FlushAsync().ConfigureAwait(false);

                // Фоновый поток приёма локальных SOCKS5 UDP дейтаграмм от приложения (Discord и др.)
                Thread udpPump = new Thread(() =>
                {
                    byte[] rxBuf = new byte[16384];
                    EndPoint senderEp = new IPEndPoint(isV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                    while (!serviceToken.IsCancellationRequested)
                    {
                        int n;
                        try
                        {
                            n = localUdp.ReceiveFrom(rxBuf, 0, rxBuf.Length, SocketFlags.None, ref senderEp);
                        }
                        catch { break; }
                        if (n <= 10) continue;

                        lock (epLock) { learnedClientEp = senderEp; }

                        string dstHost;
                        int dstPort;
                        int dataOff;
                        if (!TryParseSocks5UdpHeader(rxBuf, n, out dstHost, out dstPort, out dataOff)) continue;
                        int dataLen = n - dataOff;
                        if (dataLen <= 0) continue;

                        if (ShouldBypassDirect(dstHost))
                        {
                            byte[] rawOut = new byte[dataLen];
                            Buffer.BlockCopy(rxBuf, dataOff, rawOut, 0, dataLen);
                            string capHost = dstHost;
                            int capPort = dstPort;

                            var unused = Task.Run(async delegate
                            {
                                try
                                {
                                    IPAddress[] addrs;
                                    IPAddress parsedDirect;
                                    if (IPAddress.TryParse(capHost, out parsedDirect))
                                    {
                                        addrs = new[] { parsedDirect };
                                    }
                                    else
                                    {
                                        addrs = await Dns.GetHostAddressesAsync(capHost).ConfigureAwait(false);
                                    }

                                    IPAddress chosen = null;
                                    foreach (var a in addrs)
                                    {
                                        if (a.AddressFamily == AddressFamily.InterNetwork) { chosen = a; break; }
                                    }
                                    if (chosen == null && addrs.Length > 0) chosen = addrs[0];
                                    if (chosen == null) return;

                                    bool targetV6 = (chosen.AddressFamily == AddressFamily.InterNetworkV6);
                                    Socket sendSock = null;
                                    lock (directLock)
                                    {
                                        if (targetV6)
                                        {
                                            if (directUdp6 == null)
                                            {
                                                directUdp6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                                                directUdp6.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
                                                StartDirectUdpRxLoop(directUdp6, IPAddress.IPv6Any, localUdp, epLock, () => learnedClientEp);
                                            }
                                            sendSock = directUdp6;
                                        }
                                        else
                                        {
                                            if (directUdp4 == null)
                                            {
                                                directUdp4 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                                                directUdp4.Bind(new IPEndPoint(IPAddress.Any, 0));
                                                StartDirectUdpRxLoop(directUdp4, IPAddress.Any, localUdp, epLock, () => learnedClientEp);
                                            }
                                            sendSock = directUdp4;
                                        }
                                    }
                                    if (sendSock != null)
                                    {
                                        sendSock.SendTo(rawOut, new IPEndPoint(chosen, capPort));
                                    }
                                }
                                catch { }
                            });
                        }
                        else
                        {
                            byte[] hostBytes = Encoding.ASCII.GetBytes(dstHost);
                            if (hostBytes.Length == 0 || hostBytes.Length > 250) continue;
                            byte[] framePayload = new byte[1 + hostBytes.Length + 2 + dataLen];
                            framePayload[0] = (byte)hostBytes.Length;
                            Buffer.BlockCopy(hostBytes, 0, framePayload, 1, hostBytes.Length);
                            framePayload[1 + hostBytes.Length] = (byte)((dstPort >> 8) & 0xFF);
                            framePayload[1 + hostBytes.Length + 1] = (byte)(dstPort & 0xFF);
                            Buffer.BlockCopy(rxBuf, dataOff, framePayload, 1 + hostBytes.Length + 2, dataLen);

                            try
                            {
                                mux.WriteFrame(Pwp3MuxClient.FrameUdpData, assocId, 0, framePayload, 0, framePayload.Length, 0);
                                Interlocked.Add(ref _totalBytesUp, dataLen);
                            }
                            catch { break; }
                        }
                    }
                });
                udpPump.IsBackground = true;
                udpPump.Name = "SOCKS5-UDP-" + boundPort;
                udpPump.Start();

                // Согласно RFC 1928, UDP-ассоциация живёт ровно пока открыто управляющее TCP-соединение
                controlTcp.ReceiveTimeout = 0;
                controlStream.ReadTimeout = Timeout.Infinite;
                byte[] eofProbe = new byte[16];
                while (!serviceToken.IsCancellationRequested)
                {
                    int nr = await controlStream.ReadAsync(eofProbe, 0, eofProbe.Length, serviceToken).ConfigureAwait(false);
                    if (nr <= 0) break;
                }
            }
            finally
            {
                if (assocId != 0 && mux != null)
                {
                    mux.UnregisterUdpAssociation(assocId);
                }
                try { localUdp.Close(); } catch { }
                lock (directLock)
                {
                    try { if (directUdp4 != null) directUdp4.Close(); } catch { }
                    try { if (directUdp6 != null) directUdp6.Close(); } catch { }
                }
            }
        }

        private static void StartDirectUdpRxLoop(Socket capDirect, IPAddress anyAddr, Socket localUdp, object epLock, Func<EndPoint> getClientEp)
        {
            Thread dRx = new Thread(() =>
            {
                byte[] dBuf = new byte[16384];
                EndPoint rEp = new IPEndPoint(anyAddr, 0);
                while (true)
                {
                    try
                    {
                        int dn = capDirect.ReceiveFrom(dBuf, 0, dBuf.Length, SocketFlags.None, ref rEp);
                        IPEndPoint rip = rEp as IPEndPoint;
                        EndPoint cEp;
                        lock (epLock) { cEp = getClientEp(); }
                        if (dn > 0 && rip != null && cEp != null)
                        {
                            byte[] sp = BuildSocks5UdpPacket(rip.Address.ToString(), rip.Port, dBuf, 0, dn);
                            if (sp != null) localUdp.SendTo(sp, 0, sp.Length, SocketFlags.None, cEp);
                        }
                    }
                    catch { break; }
                }
            });
            dRx.IsBackground = true;
            dRx.Start();
        }

        private static bool TryParseSocks5UdpHeader(byte[] buf, int pktLen, out string host, out int port, out int dataOffset)
        {
            host = null;
            port = 0;
            dataOffset = 0;
            if (pktLen < 10) return false;
            if (buf[2] != 0x00) return false; // FRAG != 0 не поддерживается (standalone RFC 1928)

            byte atyp = buf[3];
            int pos = 4;
            if (atyp == 0x01)
            {
                if (pos + 4 + 2 > pktLen) return false;
                byte[] ip4 = new byte[4];
                Buffer.BlockCopy(buf, pos, ip4, 0, 4);
                host = new IPAddress(ip4).ToString();
                pos += 4;
            }
            else if (atyp == 0x03)
            {
                int domLen = buf[pos++];
                if (domLen <= 0 || pos + domLen + 2 > pktLen) return false;
                host = Encoding.ASCII.GetString(buf, pos, domLen).Trim('[', ']');
                pos += domLen;
            }
            else if (atyp == 0x04)
            {
                if (pos + 16 + 2 > pktLen) return false;
                byte[] ip6 = new byte[16];
                Buffer.BlockCopy(buf, pos, ip6, 0, 16);
                host = new IPAddress(ip6).ToString();
                pos += 16;
            }
            else
            {
                return false;
            }

            port = (buf[pos] << 8) | buf[pos + 1];
            dataOffset = pos + 2;
            return port > 0;
        }

        private static byte[] BuildSocks5UdpPacket(string srcHost, int srcPort, byte[] data, int dataOff, int dataLen)
        {
            IPAddress ip;
            if (IPAddress.TryParse(srcHost, out ip) && ip.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] ipBytes = ip.GetAddressBytes();
                byte[] pkt = new byte[4 + 4 + 2 + dataLen];
                pkt[3] = 0x01;
                Buffer.BlockCopy(ipBytes, 0, pkt, 4, 4);
                pkt[8] = (byte)((srcPort >> 8) & 0xFF);
                pkt[9] = (byte)(srcPort & 0xFF);
                Buffer.BlockCopy(data, dataOff, pkt, 10, dataLen);
                return pkt;
            }
            else if (ip != null && ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] ipBytes = ip.GetAddressBytes();
                byte[] pkt = new byte[4 + 16 + 2 + dataLen];
                pkt[3] = 0x04;
                Buffer.BlockCopy(ipBytes, 0, pkt, 4, 16);
                pkt[20] = (byte)((srcPort >> 8) & 0xFF);
                pkt[21] = (byte)(srcPort & 0xFF);
                Buffer.BlockCopy(data, dataOff, pkt, 22, dataLen);
                return pkt;
            }
            else
            {
                byte[] hb = Encoding.ASCII.GetBytes(srcHost);
                if (hb.Length == 0 || hb.Length > 250) return null;
                byte[] pkt = new byte[4 + 1 + hb.Length + 2 + dataLen];
                pkt[3] = 0x03;
                pkt[4] = (byte)hb.Length;
                Buffer.BlockCopy(hb, 0, pkt, 5, hb.Length);
                pkt[5 + hb.Length] = (byte)((srcPort >> 8) & 0xFF);
                pkt[6 + hb.Length] = (byte)(srcPort & 0xFF);
                Buffer.BlockCopy(data, dataOff, pkt, 7 + hb.Length, dataLen);
                return pkt;
            }
        }

        // =========================================================================
        // PWP-2 FALLBACK & SHARED HANDSHAKE / DIRECT BRIDGE HELPERS
        // =========================================================================
        private static PixelWarmTunnel TryPopWarmTunnel()
        {
            PixelWarmTunnel wt;
            while (_warmPool.TryDequeue(out wt))
            {
                if (wt.IsFreshAndAlive())
                {
                    TriggerPoolReplenish();
                    return wt;
                }
                wt.Dispose();
            }
            TriggerPoolReplenish();
            return null;
        }

        private static void TriggerPoolReplenish()
        {
            if (!IsRunning || !string.IsNullOrEmpty(LastLicenseError)) return;
            if (Interlocked.CompareExchange(ref _poolReplenishing, 1, 0) != 0) return;

            Task.Run(() =>
            {
                try
                {
                    while (IsRunning && string.IsNullOrEmpty(LastLicenseError) && _warmPool.Count < WARM_POOL_TARGET)
                    {
                        var candidates = GetOrderedCandidateNodes(false);
                        bool added = false;
                        foreach (var node in candidates)
                        {
                            if (!IsRunning) break;
                            try
                            {
                                PixelWarmTunnel wt = CreatePwp2Tunnel(node, 4000);
                                if (wt != null)
                                {
                                    _warmPool.Enqueue(wt);
                                    added = true;
                                    break;
                                }
                            }
                            catch
                            {
                                if (!string.IsNullOrEmpty(LastLicenseError)) return;
                            }
                        }
                        if (!added) break;
                    }
                }
                finally
                {
                    Interlocked.Exchange(ref _poolReplenishing, 0);
                }
            });
        }

        private static PixelWarmTunnel CreatePwp2Tunnel(PixelServerNode node, int connectTimeoutMs = 2400)
        {
            if (connectTimeoutMs <= 0) connectTimeoutMs = 2400;
            TcpClient tcp = new TcpClient();
            try
            {
                tcp.NoDelay = true;
                tcp.ReceiveTimeout = 12000;
                tcp.SendTimeout = 12000;

                IAsyncResult ar = tcp.BeginConnect(node.Host, node.Port, null, null);
                WaitHandle wh = ar.AsyncWaitHandle;
                try
                {
                    if (!wh.WaitOne(connectTimeoutMs))
                    {
                        try { tcp.Close(); } catch { }
                        try { ((IDisposable)tcp).Dispose(); } catch { }
                        throw new TimeoutException("Connect timeout to " + node.Name);
                    }
                    tcp.EndConnect(ar);
                }
                finally
                {
                    try { wh.Close(); } catch { }
                }
                EnableTcpKeepAlive(tcp.Client);

                PixelStreamCipher enc;
                PixelStreamCipher dec;
                bool nativeTlsBulk;
                bool negotiatedMux;
                Stream transport = HandshakeWithServer(tcp, node, false, out enc, out dec, out nativeTlsBulk, out negotiatedMux);

                lock (_nodesLock)
                {
                    node.IsOnline = true;
                    node.FailCount = 0;
                    node.LastHealthMeasuredUtc = DateTime.UtcNow;
                    SnapshotNodeHealthLocked(node);
                }

                return new PixelWarmTunnel
                {
                    Tcp = tcp,
                    Transport = transport,
                    Encryptor = enc,
                    Decryptor = dec,
                    NativeTlsBulk = nativeTlsBulk,
                    Node = node,
                    CreatedUtc = DateTime.UtcNow
                };
            }
            catch
            {
                try { tcp.Close(); } catch { }
                try { ((IDisposable)tcp).Dispose(); } catch { }
                throw;
            }
        }

        private static async Task ForwardProxyTrafficPwp2FallbackAsync(
            TcpClient localClient,
            NetworkStream localStream,
            string targetHost,
            int targetPort,
            bool isHttpConnect,
            bool isSocks5,
            byte[] initialPayload)
        {
            byte[] hostBytes = Encoding.UTF8.GetBytes(targetHost);
            if (hostBytes.Length > 250) return;

            for (int attempt = 0; attempt < 2; attempt++)
            {
                if (!string.IsNullOrEmpty(LastLicenseError)) return;

                PixelWarmTunnel tunnel = (attempt == 0) ? TryPopWarmTunnel() : null;
                if (tunnel == null)
                {
                    if (!HasAnyNodeWithSecret())
                    {
                        await Task.Run(() => EnsureManifestSecretsLoaded(4500)).ConfigureAwait(false);
                    }
                    var candidates = GetOrderedCandidateNodes(false);
                    foreach (var cand in candidates)
                    {
                        try
                        {
                            tunnel = CreatePwp2Tunnel(cand, 2400);
                            if (tunnel != null) break;
                        }
                        catch
                        {
                            if (!string.IsNullOrEmpty(LastLicenseError)) return;
                            lock (_nodesLock)
                            {
                                cand.FailCount++;
                                cand.LastHealthMeasuredUtc = DateTime.UtcNow;
                                if (cand.FailCount >= 2)
                                {
                                    cand.IsOnline = false;
                                    cand.LatencyMs = 9999;
                                }
                                SnapshotNodeHealthLocked(cand);
                            }
                        }
                    }
                }

                if (tunnel == null)
                {
                    await Task.Delay(80).ConfigureAwait(false);
                    continue;
                }

                try
                {
                    using (tunnel)
                    {
                        byte[] rnd = new byte[1];
                        using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(rnd);
                        byte padLen = (byte)(8 + (rnd[0] % 40));
                        int hdrLen = 2 + padLen + 1 + hostBytes.Length + 2;
                        int extraLen = (initialPayload != null) ? initialPayload.Length : 0;

                        byte[] packet = new byte[hdrLen + extraLen];
                        packet[0] = 0x01;
                        packet[1] = padLen;
                        using (var rng = new RNGCryptoServiceProvider())
                        {
                            byte[] pad = new byte[padLen];
                            rng.GetBytes(pad);
                            Buffer.BlockCopy(pad, 0, packet, 2, padLen);
                        }
                        packet[2 + padLen] = (byte)hostBytes.Length;
                        Buffer.BlockCopy(hostBytes, 0, packet, 2 + padLen + 1, hostBytes.Length);
                        int portOff = 2 + padLen + 1 + hostBytes.Length;
                        packet[portOff] = (byte)((targetPort >> 8) & 0xFF);
                        packet[portOff + 1] = (byte)(targetPort & 0xFF);

                        if (extraLen > 0)
                        {
                            Buffer.BlockCopy(initialPayload, 0, packet, hdrLen, extraLen);
                        }

                        if (tunnel.NativeTlsBulk)
                        {
                            tunnel.Encryptor.ProcessBytes(packet, 0, hdrLen);
                        }
                        else
                        {
                            tunnel.Encryptor.ProcessBytes(packet, 0, packet.Length);
                        }

                        await tunnel.Transport.WriteAsync(packet, 0, packet.Length).ConfigureAwait(false);
                        await tunnel.Transport.FlushAsync().ConfigureAwait(false);

                        byte[] ackHdr = new byte[2];
                        ReadExactInternal(tunnel.Transport, ackHdr, 0, 2);
                        tunnel.Decryptor.ProcessBytes(ackHdr, 0, 2);
                        if (ackHdr[0] != 0x00)
                        {
                            SendLocalProxyError(localStream, isHttpConnect, isSocks5);
                            return;
                        }
                        int ackPadLen = ackHdr[1];
                        if (ackPadLen > 0)
                        {
                            byte[] ackPad = new byte[ackPadLen];
                            ReadExactInternal(tunnel.Transport, ackPad, 0, ackPadLen);
                            tunnel.Decryptor.ProcessBytes(ackPad, 0, ackPadLen);
                        }

                        ActiveNodeName = tunnel.Node.Name;
                        ActiveProtocol = "PWP-2";
                        SendLocalProxySuccess(localStream, isHttpConnect, isSocks5);

                        tunnel.Tcp.ReceiveTimeout = 3600000;
                        tunnel.Tcp.SendTimeout = 3600000;
                        localStream.ReadTimeout = 3600000;
                        localStream.WriteTimeout = 3600000;

                        PixelStreamCipher upCipher = tunnel.NativeTlsBulk ? null : tunnel.Encryptor;
                        PixelStreamCipher downCipher = tunnel.NativeTlsBulk ? null : tunnel.Decryptor;

                        Task upTask = RelayStreamAsync(localStream, tunnel.Transport, upCipher, true);
                        Task downTask = RelayStreamAsync(tunnel.Transport, localStream, downCipher, false);
                        Task finished = await Task.WhenAny(upTask, downTask).ConfigureAwait(false);
                        if (finished == upTask)
                        {
                            using (CancellationTokenSource delayCts = new CancellationTokenSource())
                            {
                                try
                                {
                                    await Task.WhenAny(downTask, Task.Delay(1800000, delayCts.Token)).ConfigureAwait(false);
                                }
                                finally
                                {
                                    delayCts.Cancel();
                                }
                            }
                        }
                        try { localClient.Client.Shutdown(SocketShutdown.Both); } catch { }
                        return;
                    }
                }
                catch
                {
                }
            }
        }

        private static bool ReadAsnLen(byte[] buf, ref int pos, int limit, out int len)
        {
            len = 0;
            if (pos >= limit) return false;
            byte first = buf[pos++];
            if ((first & 0x80) == 0)
            {
                len = first;
                return pos + len <= limit;
            }
            int numBytes = first & 0x7F;
            if (numBytes == 0 || numBytes > 4 || pos + numBytes > limit) return false;
            int val = 0;
            for (int i = 0; i < numBytes; i++)
            {
                val = (val << 8) | buf[pos++];
            }
            len = val;
            return len >= 0 && pos + len <= limit;
        }

        private static bool ReadAsnTlv(byte[] buf, ref int pos, int limit, out byte tag, out int contentOff, out int contentLen, out int totalEnd)
        {
            tag = 0;
            contentOff = 0;
            contentLen = 0;
            totalEnd = 0;
            if (pos >= limit) return false;
            tag = buf[pos++];
            if (!ReadAsnLen(buf, ref pos, limit, out contentLen)) return false;
            contentOff = pos;
            totalEnd = pos + contentLen;
            if (totalEnd > limit) return false;
            pos = totalEnd;
            return true;
        }

        private static string GetCertSpkiSha256Hex(X509Certificate cert)
        {
            if (cert == null) return "";
            try
            {
                byte[] raw = cert.GetRawCertData();
                if (raw == null || raw.Length < 32) return "";
                int pos = 0;
                byte tag;
                int certOff, certLen, certEnd;
                if (!ReadAsnTlv(raw, ref pos, raw.Length, out tag, out certOff, out certLen, out certEnd) || tag != 0x30) return "";
                pos = certOff;
                int tbsOff, tbsLen, tbsEnd;
                if (!ReadAsnTlv(raw, ref pos, certEnd, out tag, out tbsOff, out tbsLen, out tbsEnd) || tag != 0x30) return "";
                pos = tbsOff;
                int elOff, elLen, elEnd;
                if (!ReadAsnTlv(raw, ref pos, tbsEnd, out tag, out elOff, out elLen, out elEnd)) return "";
                if (tag == 0xA0)
                {
                    if (!ReadAsnTlv(raw, ref pos, tbsEnd, out tag, out elOff, out elLen, out elEnd)) return ""; // serialNumber
                }
                for (int skip = 0; skip < 4; skip++) // signature, issuer, validity, subject
                {
                    if (!ReadAsnTlv(raw, ref pos, tbsEnd, out tag, out elOff, out elLen, out elEnd)) return "";
                }
                int spkiStart = pos;
                if (!ReadAsnTlv(raw, ref pos, tbsEnd, out tag, out elOff, out elLen, out elEnd) || tag != 0x30) return "";
                int spkiLen = elEnd - spkiStart;
                using (var sha = SHA256.Create())
                {
                    byte[] h = sha.ComputeHash(raw, spkiStart, spkiLen);
                    return BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return "";
            }
        }

        private static string NormalizeSpkiPinToHex(string rawPin)
        {
            if (string.IsNullOrEmpty(rawPin)) return "";
            string clean = rawPin.Trim();
            if (clean.StartsWith("sha256/", StringComparison.OrdinalIgnoreCase))
            {
                clean = clean.Substring(7).Trim();
            }
            if (clean.Length == 64 && Regex.IsMatch(clean, "^[0-9a-fA-F]{64}$"))
            {
                return clean.ToLowerInvariant();
            }
            try
            {
                byte[] bytes = Convert.FromBase64String(clean);
                if (bytes.Length == 32)
                {
                    return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch { }
            return "";
        }

        private static bool IsPinnedServerSpki(X509Certificate cert)
        {
            string actual = GetCertSpkiSha256Hex(cert);
            if (string.IsNullOrEmpty(actual)) return false;
            HashSet<string> pins = _pinnedSpkiHashes;
            return pins != null && pins.Contains(actual);
        }

        private static void ParseEdgeTelemetryHeader(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return;
            string[] parts = raw.Split(';');
            foreach (string part in parts)
            {
                int eq = part.IndexOf('=');
                if (eq <= 0 || eq + 1 >= part.Length) continue;
                string k = part.Substring(0, eq).Trim().ToLowerInvariant();
                string v = part.Substring(eq + 1).Trim();
                int num;
                switch (k)
                {
                    case "t":
                        ServerLicenseTier = v.ToLowerInvariant();
                        break;
                    case "d":
                        if (int.TryParse(v, out num)) ServerDaysLeft = num;
                        break;
                    case "h":
                        if (int.TryParse(v, out num)) ServerHoursLeft = num;
                        break;
                    case "u":
                        if (int.TryParse(v, out num)) ServerDevicesUsed = num;
                        break;
                    case "m":
                        if (int.TryParse(v, out num)) ServerDevicesMax = num;
                        break;
                }
            }
        }

        private static Stream HandshakeWithServer(
            TcpClient serverTcp,
            PixelServerNode node,
            bool wantMuxV3,
            out PixelStreamCipher encryptor,
            out PixelStreamCipher decryptor,
            out bool nativeTlsBulk,
            out bool negotiatedMuxV3,
            string overrideSni = null,
            int dpiProfile = -1)
        {
            string sniHost = string.IsNullOrEmpty(overrideSni) ? node.Sni : overrideSni;
            int prof = (dpiProfile >= 0) ? dpiProfile : _activeDpiProfile;

            DpiFragmentingStream fragStream = new DpiFragmentingStream(serverTcp.GetStream(), sniHost, prof);
            fragStream.FragmentActive = _enableDpiFragment && node.EnableDpiSplit;
            Stream transportStream = fragStream;

            if (node.UseTls)
            {
                IPAddress tmpHostIp;
                bool isRawIpHost = !string.IsNullOrEmpty(node.Host) && IPAddress.TryParse(node.Host.Trim('[', ']'), out tmpHostIp);
                bool isMaskedRawIp = isRawIpHost && !HostMatchesDomain(sniHost, "pixelstore.space");

                SslStream ssl = new SslStream(fragStream, false, (sender, cert, chain, errors) =>
                {
                    if (isMaskedRawIp)
                    {
                        if (_allowSelfSignedFallback) return true;
                        return IsPinnedServerSpki(cert);
                    }
                    if (errors == SslPolicyErrors.None) return true;
                    return _allowSelfSignedFallback;
                });

                try
                {
                    ssl.AuthenticateAsClient(sniHost, null, (SslProtocols)12288 | SslProtocols.Tls12, false);
                }
                catch (ArgumentException)
                {
                    ssl.AuthenticateAsClient(sniHost, null, SslProtocols.Tls12, false);
                }
                catch (NotSupportedException)
                {
                    ssl.AuthenticateAsClient(sniHost, null, SslProtocols.Tls12, false);
                }

                fragStream.FragmentActive = false;
                transportStream = ssl;
            }

            if (string.IsNullOrEmpty(node.Secret))
            {
                throw new InvalidOperationException("Missing manifest secret for " + node.Name);
            }

            long prevOffset = Interlocked.Read(ref _clockOffsetSeconds);
            long ts = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds + prevOffset;
            string tsStr = ts.ToString();

            byte[] wsKeyRaw = new byte[16];
            byte[] junkBytes = new byte[18];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(wsKeyRaw);
                rng.GetBytes(junkBytes);
            }
            string wsKey = Convert.ToBase64String(wsKeyRaw);
            string junkToken = Convert.ToBase64String(junkBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

            string cUuid = string.IsNullOrEmpty(_clientUuid) ? "" : _clientUuid;
            string cHwid = string.IsNullOrEmpty(_machineHwid) ? ComputeHardwareId() : _machineHwid;

            string sigHex32;
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(node.Secret)))
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(tsStr + ":" + wsKey + ":" + cUuid + ":" + cHwid));
                sigHex32 = BitConverter.ToString(hash, 0, 16).Replace("-", "").ToLowerInvariant();
            }

            string reqPath = wantMuxV3
                ? (string.IsNullOrEmpty(node.UpgradePath) ? "/api/v3/telemetry/mux" : node.UpgradePath)
                : "/api/v2/telemetry/stream";

            string upgradeReq =
                "GET " + reqPath + " HTTP/1.1\r\n" +
                "Host: " + sniHost + "\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                "Cookie: _cfuvid=" + tsStr + "." + cHwid + "." + cUuid + "; __cf_bm=" + sigHex32 + "." + junkToken + "\r\n\r\n";

            byte[] reqBytes = Encoding.ASCII.GetBytes(upgradeReq);
            transportStream.Write(reqBytes, 0, reqBytes.Length);
            transportStream.Flush();
            fragStream.FragmentActive = false;

            string respHeaders = ReadHttpHeaders(transportStream);
            bool clockAdjustedNow = TrySyncClockFromHttpHeaders(respHeaders, prevOffset);

            if (respHeaders.StartsWith("HTTP/1.1 403"))
            {
                string edgeStatus = ExtractHeader(respHeaders, "X-Edge-Status");
                if (clockAdjustedNow && (string.IsNullOrEmpty(edgeStatus) || edgeStatus.IndexOf("TIME", StringComparison.OrdinalIgnoreCase) >= 0 || edgeStatus.IndexOf("SIG", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    throw new IOException("CLOCK_RESYNCED on " + node.Name);
                }
                if (!string.IsNullOrEmpty(edgeStatus))
                {
                    LastLicenseError = edgeStatus.Trim().ToUpperInvariant();
                }
                throw new UnauthorizedAccessException("License rejected: " + LastLicenseError);
            }

            if (!respHeaders.StartsWith("HTTP/1.1 101"))
            {
                if (!clockAdjustedNow && string.IsNullOrEmpty(ExtractHeader(respHeaders, "Date")))
                {
                    long probedDrift;
                    string probedSrc;
                    if (ProbeAndSyncClockOffset(out probedDrift, out probedSrc))
                    {
                        long updatedOffset = Interlocked.Read(ref _clockOffsetSeconds);
                        if (Math.Abs(updatedOffset - prevOffset) >= 90L)
                        {
                            clockAdjustedNow = true;
                        }
                    }
                }
                if (clockAdjustedNow)
                {
                    throw new IOException("CLOCK_RESYNCED on " + node.Name);
                }
                throw new Exception("Handshake rejected by " + node.Name);
            }

            LastLicenseError = "";
            string edgeTelemetry = ExtractHeader(respHeaders, "X-Edge-Telemetry");
            if (!string.IsNullOrEmpty(edgeTelemetry))
            {
                ParseEdgeTelemetryHeader(edgeTelemetry);
            }
            string serverSalt = null;
            nativeTlsBulk = false;
            negotiatedMuxV3 = false;

            string setCookie = ExtractHeader(respHeaders, "Set-Cookie");
            if (!string.IsNullOrEmpty(setCookie))
            {
                Match mc3 = Regex.Match(setCookie, "__cfruid=([0-9a-fA-F]+)\\.m3\\.([ns])");
                if (mc3.Success)
                {
                    serverSalt = mc3.Groups[1].Value;
                    nativeTlsBulk = (mc3.Groups[2].Value == "n") && node.UseTls;
                    negotiatedMuxV3 = true;
                }
                else
                {
                    Match mc2 = Regex.Match(setCookie, "__cfruid=([0-9a-fA-F]+)\\.([ns])");
                    if (mc2.Success)
                    {
                        serverSalt = mc2.Groups[1].Value;
                        nativeTlsBulk = (mc2.Groups[2].Value == "n") && node.UseTls;
                        negotiatedMuxV3 = false;
                    }
                }
            }

            if (string.IsNullOrEmpty(serverSalt))
            {
                serverSalt = ExtractHeader(respHeaders, "X-Pixel-Salt");
            }
            if (string.IsNullOrEmpty(serverSalt))
            {
                throw new Exception("Missing session salt");
            }

            encryptor = new PixelStreamCipher(node.Secret, wsKey + ":c2s");
            decryptor = new PixelStreamCipher(node.Secret, serverSalt + ":s2c");
            return transportStream;
        }

        private static async Task BridgeDirectAsync(
            TcpClient localClient,
            NetworkStream localStream,
            string targetHost,
            int targetPort,
            bool isHttpConnect,
            bool isSocks5,
            byte[] initialPayload)
        {
            using (TcpClient remote = new TcpClient())
            {
                remote.NoDelay = true;
                await remote.ConnectAsync(targetHost, targetPort).ConfigureAwait(false);
                EnableTcpKeepAlive(remote.Client);
                NetworkStream remoteStream = remote.GetStream();

                SendLocalProxySuccess(localStream, isHttpConnect, isSocks5);
                if (initialPayload != null && initialPayload.Length > 0)
                {
                    await remoteStream.WriteAsync(initialPayload, 0, initialPayload.Length).ConfigureAwait(false);
                    await remoteStream.FlushAsync().ConfigureAwait(false);
                }

                Task upTask = RelayStreamAsync(localStream, remoteStream, null, true);
                Task downTask = RelayStreamAsync(remoteStream, localStream, null, false);
                Task finished = await Task.WhenAny(upTask, downTask).ConfigureAwait(false);
                if (finished == upTask)
                {
                    try { remote.Client.Shutdown(SocketShutdown.Send); } catch { }
                    using (CancellationTokenSource delayCts = new CancellationTokenSource())
                    {
                        try
                        {
                            await Task.WhenAny(downTask, Task.Delay(1800000, delayCts.Token)).ConfigureAwait(false);
                        }
                        finally
                        {
                            delayCts.Cancel();
                        }
                    }
                }
                try { localClient.Client.Shutdown(SocketShutdown.Both); } catch { }
            }
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            StringBuilder sb = new StringBuilder(s.Length + 8);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20)
                            sb.AppendFormat(CultureInfo.InvariantCulture, "\\u{0:x4}", (int)c);
                        else
                            sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        private static void ServeTelemetryApi(NetworkStream localStream)
        {
            StringBuilder nodesJson = new StringBuilder("[");
            lock (_nodesLock)
            {
                for (int i = 0; i < _nodes.Count; i++)
                {
                    var n = _nodes[i];
                    if (i > 0) nodesJson.Append(",");
                    nodesJson.AppendFormat(
                        CultureInfo.InvariantCulture,
                        "{{\"name\":\"{0}\",\"region\":\"{1}\",\"host\":\"{2}\",\"port\":{3},\"mux\":{4},\"online\":{5},\"latency_ms\":{6}}}",
                        EscapeJson(n.Name), EscapeJson(n.Region), EscapeJson(n.Host), n.Port,
                        n.SupportsMuxV3 ? "true" : "false",
                        n.IsOnline ? "true" : "false",
                        n.LatencyMs);
                }
            }
            nodesJson.Append("]");

            SampleLiveSpeed();
            long uptimeSec = (long)(DateTime.UtcNow - _startTime).TotalSeconds;
            string standby = FindStandbyNodeNameLocked();
            string body = string.Format(
                CultureInfo.InvariantCulture,
                "{{\"engine\":\"PixelCore v3.0 (v{23})\",\"engine_version\":\"{23}\",\"protocol\":\"{0}\",\"region\":\"{1}\",\"manifest_ver\":{2},\"manifest_src\":\"{3}\",\"mux_streams\":{4},\"udp_assocs\":{5},\"dpi_clienthello_split\":{6},\"dpi_profile\":\"{7}\",\"anti_freeze_ok\":{8},\"dpi_escalations\":{9},\"clock_offset_sec\":{22},\"license_tier\":\"{10}\",\"days_left\":{11},\"devices_used\":{12},\"devices_max\":{13},\"speed_mbps\":{14:0.00},\"latest_version\":\"{15}\",\"license_error\":\"{16}\",\"uptime_sec\":{17},\"active_connections\":{18},\"bytes_up\":{19},\"bytes_down\":{20},\"utls_profile\":\"{24}\",\"standby_node\":\"{25}\",\"standby_ready\":{26},\"failover_count\":{27},\"instant_wake_count\":{28},\"pac_rev\":{29},\"wsl_bridge_ip\":\"{30}\",\"nodes\":{21}}}",
                EscapeJson(ActiveProtocol ?? "PWP-3 Mux"),
                EscapeJson(_preferredRegion),
                ManifestVersion,
                EscapeJson(ManifestSource ?? "Embedded"),
                ActiveMuxStreams,
                ActiveUdpAssociations,
                _enableDpiFragment ? "true" : "false",
                EscapeJson(AntiDpiProfileName),
                LastAntiFreezeProbePassed ? "true" : "false",
                AntiFreezeEscalations,
                EscapeJson(ServerLicenseTier ?? ""),
                ServerDaysLeft,
                ServerDevicesUsed,
                ServerDevicesMax,
                LiveTotalMbps,
                EscapeJson(ManifestLatestVersion ?? ""),
                EscapeJson(LastLicenseError ?? ""),
                uptimeSec,
                Interlocked.Read(ref _activeConns),
                Interlocked.Read(ref _totalBytesUp),
                Interlocked.Read(ref _totalBytesDown),
                nodesJson.ToString(),
                Interlocked.Read(ref _clockOffsetSeconds),
                ENGINE_VERSION,
                UsingGoEngine ? "chrome" : "csharp-fallback",
                EscapeJson(standby),
                StandbyReady ? "true" : "false",
                FailoverCount,
                InstantWakeCount,
                _pacRevision,
                EscapeJson(ActiveWslBridgeIp ?? ""));

            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            string respHdr =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json; charset=utf-8\r\n" +
                "Content-Length: " + bodyBytes.Length + "\r\n" +
                "Connection: close\r\n\r\n";
            byte[] hdrBytes = Encoding.ASCII.GetBytes(respHdr);
            localStream.Write(hdrBytes, 0, hdrBytes.Length);
            localStream.Write(bodyBytes, 0, bodyBytes.Length);
        }

        private static void ParseConnectHostPort(string rawTarget, out string host, out int port)
        {
            host = "";
            port = 443;
            if (string.IsNullOrEmpty(rawTarget)) return;
            string t = rawTarget.Trim();

            if (t.StartsWith("["))
            {
                int close = t.IndexOf(']');
                if (close > 1)
                {
                    host = t.Substring(1, close - 1);
                    if (close + 2 <= t.Length && t[close + 1] == ':')
                    {
                        int parsed;
                        if (int.TryParse(t.Substring(close + 2), out parsed) && parsed > 0) port = parsed;
                    }
                    return;
                }
            }

            int colon = t.LastIndexOf(':');
            if (colon > 0 && t.IndexOf(':') == colon)
            {
                host = t.Substring(0, colon);
                int parsed;
                if (int.TryParse(t.Substring(colon + 1), out parsed) && parsed > 0) port = parsed;
            }
            else
            {
                host = t;
            }
        }

        private static byte[] RewritePlainHttpProxyRequest(string headerStr, Uri uri)
        {
            string[] lines = headerStr.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0) return Encoding.ASCII.GetBytes(headerStr);

            string[] firstParts = lines[0].Split(' ');
            string method = firstParts.Length > 0 ? firstParts[0] : "GET";
            string ver = firstParts.Length > 2 ? firstParts[2] : "HTTP/1.1";
            string pathAndQuery = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;

            StringBuilder sb = new StringBuilder();
            sb.Append(method).Append(' ').Append(pathAndQuery).Append(' ').Append(ver).Append("\r\n");
            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrEmpty(line)) continue;
                if (line.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase)) continue;
                if (line.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase)) continue;
                sb.Append(line).Append("\r\n");
            }
            sb.Append("\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private static void EnableTcpKeepAlive(Socket sock)
        {
            if (sock == null) return;
            try
            {
                sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                byte[] ka = new byte[12];
                BitConverter.GetBytes((uint)1).CopyTo(ka, 0);
                BitConverter.GetBytes((uint)20000).CopyTo(ka, 4);
                BitConverter.GetBytes((uint)8000).CopyTo(ka, 8);
                sock.IOControl(IOControlCode.KeepAliveValues, ka, null);
            }
            catch { }
        }

        private static void SendLocalProxySuccess(NetworkStream localStream, bool isHttpConnect, bool isSocks5)
        {
            if (isSocks5)
            {
                byte[] ok = new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                localStream.Write(ok, 0, ok.Length);
            }
            else if (isHttpConnect)
            {
                byte[] ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                localStream.Write(ok, 0, ok.Length);
            }
        }

        private static void SendLocalProxyError(NetworkStream localStream, bool isHttpConnect, bool isSocks5)
        {
            try
            {
                if (isSocks5)
                {
                    byte[] err = new byte[] { 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                    localStream.Write(err, 0, err.Length);
                }
                else if (isHttpConnect)
                {
                    byte[] err = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                    localStream.Write(err, 0, err.Length);
                }
            }
            catch { }
        }

        private static async Task RelayStreamAsync(Stream src, Stream dst, PixelStreamCipher cipher, bool isUpload)
        {
            byte[] buf = new byte[65536];
            try
            {
                int n;
                while ((n = await src.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
                {
                    if (cipher != null)
                    {
                        cipher.ProcessBytes(buf, 0, n);
                    }
                    await dst.WriteAsync(buf, 0, n).ConfigureAwait(false);
                    await dst.FlushAsync().ConfigureAwait(false);
                    if (isUpload) Interlocked.Add(ref _totalBytesUp, n);
                    else Interlocked.Add(ref _totalBytesDown, n);
                }
            }
            catch { }
        }

        internal static void ReadExactInternal(Stream s, byte[] buf, int offset, int count)
        {
            int readTotal = 0;
            while (readTotal < count)
            {
                int r = s.Read(buf, offset + readTotal, count - readTotal);
                if (r <= 0) throw new EndOfStreamException();
                readTotal += r;
            }
        }

        private static string ReadHttpHeaders(Stream s)
        {
            MemoryStream ms = new MemoryStream();
            int state = 0;
            while (ms.Length < 8192)
            {
                int b = s.ReadByte();
                if (b == -1) throw new EndOfStreamException();
                ms.WriteByte((byte)b);
                if (state == 0 && b == '\r') state = 1;
                else if (state == 1 && b == '\n') state = 2;
                else if (state == 2 && b == '\r') state = 3;
                else if (state == 3 && b == '\n') return Encoding.ASCII.GetString(ms.ToArray());
                else if (b != '\r') state = 0;
            }
            throw new Exception("Header too large");
        }

        private static string ExtractHeader(string rawHeaders, string headerName)
        {
            string[] lines = rawHeaders.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                int idx = line.IndexOf(':');
                if (idx > 0)
                {
                    string k = line.Substring(0, idx).Trim();
                    if (string.Equals(k, headerName, StringComparison.OrdinalIgnoreCase))
                    {
                        return line.Substring(idx + 1).Trim();
                    }
                }
            }
            return null;
        }

        // =========================================================================
        // SMART DIAGNOSTICS v3.0: ZERO-ADMIN CLOCK COMPENSATOR, SSL-MITM & NODE MATRIX
        // =========================================================================
        private static bool TrySyncClockFromHttpHeaders(string rawHeaders, long previousOffsetSec)
        {
            try
            {
                string dateVal = ExtractHeader(rawHeaders, "Date");
                if (string.IsNullOrEmpty(dateVal)) return false;
                DateTimeOffset serverUtc;
                if (!DateTimeOffset.TryParse(dateVal, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out serverUtc))
                    return false;

                long driftSec = (long)Math.Round((serverUtc.UtcDateTime - DateTime.UtcNow).TotalSeconds);
                if (Math.Abs(driftSec) >= 45L)
                {
                    Interlocked.Exchange(ref _clockOffsetSeconds, driftSec);
                    return Math.Abs(driftSec - previousOffsetSec) >= 90L;
                }
                else
                {
                    Interlocked.Exchange(ref _clockOffsetSeconds, 0L);
                    return Math.Abs(previousOffsetSec) >= 90L;
                }
            }
            catch
            {
                return false;
            }
        }

        internal static string[] _clockProbeUrls = new[] { "https://ya.ru", "http://www.gstatic.com/generate_204", "https://www.microsoft.com" };

        /// <summary>
        /// Измеряет расхождение системных часов ПК относительно эталонного HTTP Date (без прав админа и без w32tm)
        /// и автоматически выставляет поправку ClockOffsetSeconds для HMAC-подписи PWP-3.
        /// </summary>
        public static bool ProbeAndSyncClockOffset(out long driftSeconds, out string sourceHost)
        {
            driftSeconds = Interlocked.Read(ref _clockOffsetSeconds);
            sourceHost = "";

            string[] probeUrls = _clockProbeUrls ?? new[] { "https://ya.ru", "http://www.gstatic.com/generate_204", "https://www.microsoft.com" };
            foreach (string url in probeUrls)
            {
                try
                {
                    HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                    req.Method = "HEAD";
                    req.Proxy = null; // строго напрямую для быстрой проверки локальных часов
                    req.Timeout = 2800;
                    req.ReadWriteTimeout = 2800;
                    req.AllowAutoRedirect = false;

                    string dateHeader = null;
                    try
                    {
                        using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                        {
                            dateHeader = resp.Headers["Date"];
                        }
                    }
                    catch (WebException wex)
                    {
                        if (wex.Response != null)
                        {
                            using (HttpWebResponse eresp = (HttpWebResponse)wex.Response)
                            {
                                dateHeader = eresp.Headers["Date"];
                            }
                        }
                    }

                    if (!string.IsNullOrEmpty(dateHeader))
                    {
                        DateTimeOffset srvUtc;
                        if (DateTimeOffset.TryParse(dateHeader, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out srvUtc))
                        {
                            driftSeconds = (long)Math.Round((srvUtc.UtcDateTime - DateTime.UtcNow).TotalSeconds);
                            Interlocked.Exchange(ref _clockOffsetSeconds, Math.Abs(driftSeconds) >= 45L ? driftSeconds : 0L);
                            Uri u = new Uri(url);
                            sourceHost = u.Host;
                            return true;
                        }
                    }
                }
                catch { }
            }
            return false;
        }

        /// <summary>
        /// Проверяет TLS-цепочку до эталонного узла на наличие перехвата HTTPS антивирусом (Kaspersky, Dr.Web, ESET, AdGuard и др.),
        /// из-за которого падают Node.js / MCP / language_server с ошибкой x509 unknown authority.
        /// </summary>
        public static bool DetectSslMitmInterceptor(out string certIssuerSummary, out string avProductName)
        {
            certIssuerSummary = "";
            avProductName = "";

            string[] targets = new[] { "dl.google.com", "www.gstatic.com", "ya.ru" };
            foreach (string host in targets)
            {
                try
                {
                    using (TcpClient tcp = new TcpClient())
                    {
                        IAsyncResult ar = tcp.BeginConnect(host, 443, null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(2200)) continue;
                        tcp.EndConnect(ar);
                        tcp.ReceiveTimeout = 2500;
                        tcp.SendTimeout = 2500;

                        string capturedIssuer = "";
                        using (SslStream ssl = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
                        {
                            if (cert != null) capturedIssuer = cert.Issuer ?? "";
                            return true;
                        }))
                        {
                            try
                            {
                                ssl.AuthenticateAsClient(host, null, (SslProtocols)12288 | SslProtocols.Tls12, false);
                            }
                            catch
                            {
                                ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
                            }
                        }

                        if (!string.IsNullOrEmpty(capturedIssuer))
                        {
                            certIssuerSummary = capturedIssuer;
                            LastCertIssuer = capturedIssuer;
                            string low = capturedIssuer.ToLowerInvariant();

                            string[][] signatures = new string[][]
                            {
                                new[] { "kaspersky", "Kaspersky Anti-Virus (HTTPS-проверка)" },
                                new[] { "dr.web", "Dr.Web SpIDer Gate (SSL-перехват)" },
                                new[] { "doctor web", "Dr.Web SpIDer Gate (SSL-перехват)" },
                                new[] { "eset", "ESET SSL Filter" },
                                new[] { "avast", "Avast Web Shield (HTTPS Scan)" },
                                new[] { "avg", "AVG Web Shield (HTTPS Scan)" },
                                new[] { "bitdefender", "Bitdefender Encrypted Web Scan" },
                                new[] { "adguard", "AdGuard HTTPS-фильтрация" },
                                new[] { "fiddler", "Fiddler Root Proxy" },
                                new[] { "charles", "Charles Proxy SSL" },
                                new[] { "mitmproxy", "mitmproxy SSL" },
                                new[] { "fortinet", "FortiGate Deep SSL Inspection" },
                                new[] { "zscaler", "Zscaler SSL Inspection" }
                            };

                            foreach (var sig in signatures)
                            {
                                if (low.Contains(sig[0]))
                                {
                                    avProductName = sig[1];
                                    LastDetectedSslMitm = avProductName;
                                    return true;
                                }
                            }

                            LastDetectedSslMitm = "";
                            return false;
                        }
                    }
                }
                catch { }
            }
            return false;
        }

        /// <summary>
        /// Параллельный турбо-бенчмарк всех узлов манифеста (реальный PWP-3 хендшейк + 36 КБ тест ТСПУ)
        /// с автоматическим закреплением самого быстрого рабочего маршрута под провайдера клиента.
        /// </summary>
        public static async Task<List<NodeBenchmarkResult>> RunParallelNodeBenchmarkAsync(int timeoutMs = 3400)
        {
            if (!HasAnyNodeWithSecret())
                await Task.Run(() => EnsureManifestSecretsLoaded(4500)).ConfigureAwait(false);
            List<PixelServerNode> snapshot = new List<PixelServerNode>();
            lock (_nodesLock)
            {
                if (_nodes.Count == 0) BuildDefaultNodesIfEmpty();
                snapshot.AddRange(_nodes);
            }

            Task<NodeBenchmarkResult>[] tasks = new Task<NodeBenchmarkResult>[snapshot.Count];
            for (int i = 0; i < snapshot.Count; i++)
            {
                PixelServerNode node = snapshot[i];
                tasks[i] = Task.Run(() =>
                {
                    var res = new NodeBenchmarkResult
                    {
                        Name = node.Name,
                        Region = node.Region,
                        Host = node.Host,
                        Port = node.Port,
                        UseTls = node.UseTls,
                        SupportsMuxV3 = node.SupportsMuxV3,
                        DpiProfile = AntiDpiProfileName,
                        EffectiveSni = ResolveEffectiveSni(node, _sniRotationIndex)
                    };

                    for (int benchAttempt = 0; benchAttempt < 2; benchAttempt++)
                    {
                        TcpClient tcp = new TcpClient();
                        Pwp3MuxClient tempMux = null;
                        try
                        {
                            tcp.NoDelay = true;
                            tcp.ReceiveTimeout = timeoutMs;
                            tcp.SendTimeout = timeoutMs;

                            Stopwatch sw = Stopwatch.StartNew();
                            IAsyncResult ar = tcp.BeginConnect(node.Host, node.Port, null, null);
                            WaitHandle wh = ar.AsyncWaitHandle;
                            try
                            {
                                if (!wh.WaitOne(Math.Min(timeoutMs, 2400)))
                                {
                                    try { tcp.Close(); } catch { }
                                    try { ((IDisposable)tcp).Dispose(); } catch { }
                                    res.Ok = false;
                                    res.Error = "TCP таймаут";
                                    lock (_nodesLock)
                                    {
                                        node.IsOnline = false;
                                        node.ProbeVerified = false;
                                        node.FailCount++;
                                        node.LatencyMs = 9999;
                                        node.LastHealthMeasuredUtc = DateTime.UtcNow;
                                        SnapshotNodeHealthLocked(node);
                                    }
                                    return res;
                                }
                                tcp.EndConnect(ar);
                            }
                            finally
                            {
                                try { wh.Close(); } catch { }
                            }

                            PixelStreamCipher enc;
                            PixelStreamCipher dec;
                            bool nativeBulk;
                            bool muxOk;
                            Stream tr = HandshakeWithServer(tcp, node, node.SupportsMuxV3, out enc, out dec, out nativeBulk, out muxOk, res.EffectiveSni, _activeDpiProfile);
                            sw.Stop();
                            res.HandshakeMs = (int)Math.Max(1L, sw.ElapsedMilliseconds);

                            if (muxOk)
                            {
                                tempMux = new Pwp3MuxClient("DiagBench", node, tcp, tr, enc, dec, nativeBulk);
                                if (node.UseTls && _enableAntiFreezeProbe)
                                {
                                    res.AntiFreezeOk = Run32KbAntiFreezeProbeAsync(tempMux, 2400).GetAwaiter().GetResult();
                                }
                                else
                                {
                                    res.AntiFreezeOk = true;
                                }

                                if (!res.AntiFreezeOk)
                                {
                                    res.Ok = false;
                                    res.Error = "ТСПУ 16KB фриз";
                                    lock (_nodesLock)
                                    {
                                        node.ProbeVerified = false;
                                        node.IsOnline = false;
                                        node.FailCount++;
                                        node.LatencyMs = 9999;
                                        node.LastHealthMeasuredUtc = DateTime.UtcNow;
                                        SnapshotNodeHealthLocked(node);
                                    }
                                    return res;
                                }

                                res.Ok = true;
                                res.Error = null;
                                lock (_nodesLock)
                                {
                                    node.IsOnline = true;
                                    node.ProbeVerified = true;
                                    node.FailCount = 0;
                                    node.LatencyMs = Math.Max(1, res.HandshakeMs / 2);
                                    node.LastHealthMeasuredUtc = DateTime.UtcNow;
                                    SnapshotNodeHealthLocked(node);
                                }
                            }
                            else
                            {
                                // PWP-2 fallback node
                                res.Ok = true;
                                res.Error = null;
                                res.AntiFreezeOk = true;
                                lock (_nodesLock)
                                {
                                    node.IsOnline = true;
                                    node.FailCount = 0;
                                    node.LatencyMs = Math.Max(1, res.HandshakeMs / 2);
                                    node.LastHealthMeasuredUtc = DateTime.UtcNow;
                                    SnapshotNodeHealthLocked(node);
                                }
                                try { tr.Close(); } catch { }
                            }
                            break;
                        }
                        catch (Exception ex)
                        {
                            if (benchAttempt == 0 && ex.Message != null && ex.Message.IndexOf("CLOCK_RESYNCED", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                continue;
                            }
                            res.Ok = false;
                            res.Error = ex.Message;
                            lock (_nodesLock)
                            {
                                node.IsOnline = false;
                                node.ProbeVerified = false;
                                node.FailCount++;
                                node.LatencyMs = 9999;
                                node.LastHealthMeasuredUtc = DateTime.UtcNow;
                                SnapshotNodeHealthLocked(node);
                            }
                            break;
                        }
                        finally
                        {
                            if (tempMux != null) tempMux.Dispose();
                            try { tcp.Close(); } catch { }
                            try { ((IDisposable)tcp).Dispose(); } catch { }
                        }
                    }
                    return res;
                });
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
            lock (_nodesLock)
            {
                foreach (var n in snapshot)
                {
                    SnapshotNodeHealthLocked(n);
                }
            }

            List<NodeBenchmarkResult> results = new List<NodeBenchmarkResult>(tasks.Length);
            NodeBenchmarkResult bestMux = null;
            foreach (var t in tasks)
            {
                NodeBenchmarkResult r = t.Result;
                results.Add(r);
                if (r.Ok && r.SupportsMuxV3 && r.AntiFreezeOk)
                {
                    if (bestMux == null || r.HandshakeMs < bestMux.HandshakeMs)
                    {
                        bestMux = r;
                    }
                }
            }

            if (bestMux != null)
            {
                bestMux.IsBestSelected = true;
                // Если текущий активный канал висит на более медленном или мёртвом узле — мягко переключим на победителя (если нет активного стрима)
                Pwp3MuxClient curL0 = _laneInteractive;
                if (IsRunning && (curL0 == null || curL0.IsClosed || (curL0.Node != null && curL0.Node.Name != bestMux.Name && curL0.ActiveStreamCount == 0)))
                {
                    if (curL0 != null && Interlocked.CompareExchange(ref _laneInteractive, null, curL0) == curL0)
                    {
                        curL0.Dispose();
                    }
                    CancellationToken tok = (_cts != null) ? _cts.Token : CancellationToken.None;
                    await EnsureInteractiveLaneWarmAsync(tok).ConfigureAwait(false);
                }
            }

            return results;
        }

        // =========================================================================
        // V2.0 CONTROL API, SMART PAC, LIVE RADAR, WSL2 BRIDGE & GO CORE FORWARDING
        // =========================================================================
        private static string GenerateLocalTokenHex(int byteLen)
        {
            byte[] buf = new byte[byteLen];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buf);
            }
            var sb = new StringBuilder(byteLen * 2);
            foreach (byte b in buf) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        private static string FindStandbyNodeNameLocked()
        {
            lock (_nodesLock)
            {
                string active = ActiveNodeName ?? "";
                foreach (var n in _nodes)
                {
                    if (n != null && !string.Equals(n.Name, active, StringComparison.OrdinalIgnoreCase) && n.IsOnline)
                    {
                        StandbyNodeName = n.Name;
                        StandbyReady = true;
                        return n.Name;
                    }
                }
            }
            StandbyReady = false;
            return StandbyNodeName ?? "";
        }

        private static void EnsurePowerModeHook()
        {
            if (Interlocked.CompareExchange(ref _powerHookRegistered, 1, 0) == 0)
            {
                try
                {
                    SystemEvents.PowerModeChanged += (s, e) =>
                    {
                        if (e.Mode == PowerModes.Resume && IsRunning)
                        {
                            Task.Run(() => TriggerInstantWakeAsync("power_resume"));
                        }
                    };
                }
                catch { }
            }
        }

        private static void TryStartWslBridgeListeners(CancellationToken token)
        {
            try
            {
                IPAddress wslIp = FindWslBridgeIpv4();
                if (wslIp == null) return;
                _wslHttpListener = new TcpListener(wslIp, _localPort);
                _wslHttpListener.Start(128);
                Task.Run(() => AcceptLoopAsync(_wslHttpListener, token));
                if (_socksPort > 0 && _socksPort != _localPort)
                {
                    _wslSocksListener = new TcpListener(wslIp, _socksPort);
                    _wslSocksListener.Start(128);
                    Task.Run(() => AcceptLoopAsync(_wslSocksListener, token));
                }
                ActiveWslBridgeIp = wslIp.ToString();
            }
            catch
            {
                ActiveWslBridgeIp = "";
            }
        }

        public static IPAddress FindWslBridgeIpv4()
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    string combined = (ni.Name + " " + ni.Description);
                    if (combined.IndexOf("WSL", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address != null && ua.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ua.Address))
                        {
                            return ua.Address;
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private static async Task GoTelemetryPollLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested && IsRunning && UsingGoEngine)
            {
                try
                {
                    await SyncGoTelemetryAsync().ConfigureAwait(false);
                }
                catch { }
                try { await Task.Delay(1500, token).ConfigureAwait(false); } catch { break; }
            }
        }

        public static async Task SyncGoTelemetryAsync()
        {
            if (!IsRunning || !UsingGoEngine) return;
            try
            {
                string raw = await QueryLocalEndpointAsync("GET", "/__pixelcore/v4/status", null, 2500).ConfigureAwait(false);
                if (string.IsNullOrEmpty(raw))
                    raw = await QueryLocalEndpointAsync("GET", "/__pixelcore/telemetry", null, 2500).ConfigureAwait(false);
                var obj = MiniJson.Deserialize(raw) as Dictionary<string, object>;
                if (obj == null) return;

                string proto = MiniJson.GetStr(obj, "protocol");
                if (!string.IsNullOrEmpty(proto)) ActiveProtocol = proto;
                string node = MiniJson.GetStr(obj, "active_node");
                if (!string.IsNullOrEmpty(node)) ActiveNodeName = node;
                string standby = MiniJson.GetStr(obj, "standby_node");
                if (!string.IsNullOrEmpty(standby)) StandbyNodeName = standby;
                StandbyReady = MiniJson.GetBool(obj, "standby_ready", StandbyReady);
                FailoverCount = MiniJson.GetInt(obj, "failover_count", FailoverCount);
                InstantWakeCount = MiniJson.GetInt(obj, "instant_wake_count", InstantWakeCount);
                string wakeReason = MiniJson.GetStr(obj, "last_wake_reason");
                if (wakeReason != null) LastWakeReason = wakeReason;
                LastWakeUnix = MiniJson.GetLong(obj, "last_wake_unix", LastWakeUnix);
                int pr = MiniJson.GetInt(obj, "pac_rev", 0);
                if (pr > 0) _pacRevision = pr;
                string wsl = MiniJson.GetStr(obj, "wsl_bridge_ip");
                if (wsl != null) ActiveWslBridgeIp = wsl;
                string tier = MiniJson.GetStr(obj, "license_tier");
                if (!string.IsNullOrEmpty(tier)) ServerLicenseTier = tier;
                int dl = MiniJson.GetInt(obj, "days_left", int.MinValue);
                if (dl != int.MinValue) ServerDaysLeft = dl;
                int mv = MiniJson.GetInt(obj, "manifest_ver", 0);
                if (mv > 0) ManifestVersion = mv;
                string ms = MiniJson.GetStr(obj, "manifest_src");
                if (!string.IsNullOrEmpty(ms)) ManifestSource = ms;
                long bup = MiniJson.GetLong(obj, "bytes_up", -1);
                if (bup >= 0) Interlocked.Exchange(ref _totalBytesUp, bup);
                long bdn = MiniJson.GetLong(obj, "bytes_down", -1);
                if (bdn >= 0) Interlocked.Exchange(ref _totalBytesDown, bdn);
                long ac = MiniJson.GetLong(obj, "active_connections", -1);
                if (ac >= 0) Interlocked.Exchange(ref _activeConns, ac);
                double mbps = MiniJson.GetDouble(obj, "speed_mbps", -1.0);
                if (mbps >= 0.0) LiveTotalMbps = mbps;
                SampleLiveSpeed();
            }
            catch { }
        }

        private static void RecordLiveRoute(int pid, string procName, string domain, int port, string proto, string action, string rule, string node, string role, int pingMs, string error)
        {
            long seq = Interlocked.Increment(ref _liveRouteSeq);
            DateTime now = DateTime.Now;
            var entry = new LiveRouteEntry
            {
                Seq = seq,
                Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                TimeStr = now.ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                Pid = pid,
                ProcessName = procName ?? "",
                Domain = domain ?? "",
                Port = port,
                Proto = proto ?? "TCP",
                Action = action ?? "tunnel",
                Rule = rule ?? "",
                Node = node ?? "",
                Role = role ?? "",
                PingMs = pingMs,
                BytesUp = 0,
                BytesDown = 0,
                Error = error ?? ""
            };
            lock (_liveRoutesLock)
            {
                _liveRoutes.AddFirst(entry);
                while (_liveRoutes.Count > 100) _liveRoutes.RemoveLast();
            }
        }

        public static string GeneratePacScript()
        {
            var sb = new StringBuilder();
            sb.AppendLine("// PixelTunnel v" + ENGINE_VERSION + " Smart PAC (rev " + _pacRevision + ")");
            sb.AppendLine("function FindProxyForURL(url, host) {");
            sb.AppendLine("  var h = (host || '').toLowerCase();");
            sb.AppendLine("  if (isPlainHostName(h) || shExpMatch(h, '127.*') || shExpMatch(h, 'localhost') || shExpMatch(h, '10.*') || shExpMatch(h, '192.168.*') || isInNet(h, '172.16.0.0', '255.240.0.0')) return 'DIRECT';");
            sb.AppendLine("  var px = 'PROXY 127.0.0.1:" + _localPort.ToString(CultureInfo.InvariantCulture) + "; DIRECT';");

            foreach (string dom in _proxyDomains)
            {
                string d = (dom ?? "").Trim().TrimStart('.').ToLowerInvariant();
                if (string.IsNullOrEmpty(d)) continue;
                sb.AppendLine("  if (dnsDomainIs(h, '." + d + "') || h === '" + d + "') return px;");
            }

            sb.AppendLine("  if (shExpMatch(h, '*.ru') || shExpMatch(h, '*.su') || shExpMatch(h, '*.by') || shExpMatch(h, '*.xn--p1ai')) return 'DIRECT';");

            foreach (string dom in _directDomains)
            {
                string d = (dom ?? "").Trim().TrimStart('.').ToLowerInvariant();
                if (string.IsNullOrEmpty(d)) continue;
                sb.AppendLine("  if (dnsDomainIs(h, '." + d + "') || h === '" + d + "') return 'DIRECT';");
            }

            sb.AppendLine(_defaultOutboundIsProxy ? "  return px;" : "  return 'DIRECT';");
            sb.AppendLine("}");
            return sb.ToString();
        }

        private static async Task<string> ReadHttpBodyAsync(NetworkStream stream, string headerStr, byte[] extraBody)
        {
            int contentLen = 0;
            int.TryParse((ExtractHeader(headerStr, "Content-Length") ?? "").Trim(), out contentLen);
            if (contentLen <= 0 || contentLen > 262144)
                return (extraBody != null && extraBody.Length > 0) ? Encoding.UTF8.GetString(extraBody) : "";

            byte[] buf = new byte[contentLen];
            int have = 0;
            if (extraBody != null && extraBody.Length > 0)
            {
                have = Math.Min(extraBody.Length, contentLen);
                Buffer.BlockCopy(extraBody, 0, buf, 0, have);
            }
            while (have < contentLen)
            {
                int r = await stream.ReadAsync(buf, have, contentLen - have).ConfigureAwait(false);
                if (r <= 0) break;
                have += r;
            }
            return Encoding.UTF8.GetString(buf, 0, have);
        }

        private static async Task WriteHttpResponseAsync(NetworkStream stream, int code, string statusText, string contentType, string body)
        {
            byte[] data = Encoding.UTF8.GetBytes(body ?? "");
            string hdr = string.Format(
                CultureInfo.InvariantCulture,
                "HTTP/1.1 {0} {1}\r\nContent-Type: {2}\r\nCache-Control: no-store\r\nContent-Length: {3}\r\nConnection: close\r\n\r\n",
                code, statusText, contentType, data.Length);
            byte[] hdrBytes = Encoding.ASCII.GetBytes(hdr);
            await stream.WriteAsync(hdrBytes, 0, hdrBytes.Length).ConfigureAwait(false);
            if (data.Length > 0)
                await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        private static async Task HandleLocalControlHttpAsync(TcpClient localClient, NetworkStream localStream, string method, string rawTarget, string headerStr, byte[] extraBody)
        {
            string pathOnly = rawTarget.Split('?')[0].ToLowerInvariant();
            string hostHdr = (ExtractHeader(headerStr, "Host") ?? "").Trim();
            int listenPort = _localPort;
            try
            {
                IPEndPoint lep = localClient.Client.LocalEndPoint as IPEndPoint;
                if (lep != null && lep.Port > 0) listenPort = lep.Port;
            }
            catch { }

            string portStr = listenPort.ToString(CultureInfo.InvariantCulture);
            bool validLoopbackHost =
                string.Equals(hostHdr, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(hostHdr, "127.0.0.1:" + portStr, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(hostHdr, "localhost", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(hostHdr, "localhost:" + portStr, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrEmpty(ActiveWslBridgeIp) &&
                 (string.Equals(hostHdr, ActiveWslBridgeIp, StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(hostHdr, ActiveWslBridgeIp + ":" + portStr, StringComparison.OrdinalIgnoreCase)));

            if (!validLoopbackHost)
            {
                await WriteHttpResponseAsync(localStream, 403, "Forbidden", "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"invalid_host\"}").ConfigureAwait(false);
                return;
            }

            if (pathOnly == "/proxy.pac")
            {
                await WriteHttpResponseAsync(localStream, 200, "OK", "application/x-ns-proxy-autoconfig; charset=utf-8", GeneratePacScript()).ConfigureAwait(false);
                return;
            }

            if (pathOnly == "/__pixelcore/status" || pathOnly == "/__pixelcore/telemetry")
            {
                ServeTelemetryApi(localStream);
                return;
            }

            if (pathOnly.StartsWith("/__pixelcore/v4/", StringComparison.Ordinal))
            {
                string tokHdr = (ExtractHeader(headerStr, "X-Pixel-Local-Token") ?? "").Trim();
                if (!string.IsNullOrEmpty(_localControlToken) && !string.Equals(tokHdr, _localControlToken, StringComparison.Ordinal))
                {
                    await WriteHttpResponseAsync(localStream, 403, "Forbidden", "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"unauthorized\"}").ConfigureAwait(false);
                    return;
                }

                string reqBody = (method == "POST" || method == "PUT")
                    ? await ReadHttpBodyAsync(localStream, headerStr, extraBody).ConfigureAwait(false)
                    : "";

                string jsonOut = "{}";
                if (pathOnly == "/__pixelcore/v4/status")
                    jsonOut = BuildCSharpStatusV4Json();
                else if (pathOnly == "/__pixelcore/v4/live-routes")
                    jsonOut = BuildCSharpLiveRoutesJson();
                else if (pathOnly == "/__pixelcore/v4/ai-pulse")
                    jsonOut = await ProbeAiPulseCSharpAsync(false).ConfigureAwait(false);
                else if (pathOnly == "/__pixelcore/v4/reload-rules")
                    jsonOut = ApplyCSharpReloadRules(reqBody);
                else if (pathOnly == "/__pixelcore/v4/instant-wake")
                    jsonOut = await ExecuteCSharpInstantWakeAsync(reqBody).ConfigureAwait(false);
                else if (pathOnly == "/__pixelcore/v4/run-xray")
                    jsonOut = await RunCSharpXrayAsync().ConfigureAwait(false);
                else
                {
                    await WriteHttpResponseAsync(localStream, 404, "Not Found", "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"not_found\"}").ConfigureAwait(false);
                    return;
                }

                await WriteHttpResponseAsync(localStream, 200, "OK", "application/json; charset=utf-8", jsonOut).ConfigureAwait(false);
                return;
            }

            await WriteHttpResponseAsync(localStream, 404, "Not Found", "text/plain; charset=utf-8", "Not Found").ConfigureAwait(false);
        }

        private static string BuildCSharpStatusV4Json()
        {
            SampleLiveSpeed();
            long uptimeSec = (long)(DateTime.UtcNow - _startTime).TotalSeconds;
            string standby = FindStandbyNodeNameLocked();
            var d = new Dictionary<string, object>
            {
                { "ok", true },
                { "engine", "PixelCore-CSharp-Fallback" },
                { "engine_version", ENGINE_VERSION },
                { "connected", IsRunning },
                { "protocol", ActiveProtocol ?? "PWP-3 Mux" },
                { "utls_profile", "csharp-fallback" },
                { "dpi_profile", AntiDpiProfileName },
                { "active_node", ActiveNodeName ?? "NL-Edge-443" },
                { "active_role", "ai" },
                { "standby_node", standby },
                { "standby_ready", StandbyReady },
                { "failover_count", FailoverCount },
                { "instant_wake_count", InstantWakeCount },
                { "last_wake_reason", LastWakeReason ?? "" },
                { "last_wake_unix", LastWakeUnix },
                { "pac_rev", _pacRevision },
                { "http_port", _localPort },
                { "socks_port", _socksPort },
                { "wsl_bridge_ip", ActiveWslBridgeIp ?? "" },
                { "license_tier", ServerLicenseTier ?? "" },
                { "days_left", ServerDaysLeft },
                { "manifest_ver", ManifestVersion },
                { "manifest_src", ManifestSource ?? "Embedded" },
                { "uptime_sec", uptimeSec },
                { "bytes_up", Interlocked.Read(ref _totalBytesUp) },
                { "bytes_down", Interlocked.Read(ref _totalBytesDown) },
                { "active_connections", Interlocked.Read(ref _activeConns) }
            };
            return MiniJson.Serialize(d);
        }

        private static string BuildCSharpLiveRoutesJson()
        {
            var list = new List<object>();
            lock (_liveRoutesLock)
            {
                foreach (var e in _liveRoutes)
                {
                    list.Add(new Dictionary<string, object>
                    {
                        { "seq", e.Seq },
                        { "ts", e.Ts },
                        { "time", e.TimeStr },
                        { "pid", e.Pid },
                        { "process", e.ProcessName },
                        { "domain", e.Domain },
                        { "port", e.Port },
                        { "proto", e.Proto },
                        { "action", e.Action },
                        { "rule", e.Rule },
                        { "node", e.Node },
                        { "role", e.Role },
                        { "ping_ms", e.PingMs },
                        { "bytes_up", e.BytesUp },
                        { "bytes_down", e.BytesDown },
                        { "error", e.Error }
                    });
                }
            }
            return MiniJson.Serialize(new Dictionary<string, object>
            {
                { "ok", true },
                { "pac_rev", _pacRevision },
                { "entries", list }
            });
        }

        private static string[] GetCSharpCategoryDomains(string cat)
        {
            switch ((cat ?? "").Trim().ToLowerInvariant())
            {
                case "antigravity":
                    return new[]
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
                case "mcp":
                case "dev":
                    return new[]
                    {
                        "npmjs.org", "registry.npmjs.org", "npmjs.com",
                        "pypi.org", "files.pythonhosted.org", "pythonhosted.org", "astral.sh",
                        "github.com", "api.github.com", "raw.githubusercontent.com", "githubusercontent.com", "githubassets.com", "ghcr.io",
                        "huggingface.co", "hf.co", "smithery.ai", "context7.com", "modelcontextprotocol.io", "glama.ai",
                        "deno.land", "jsr.io", "bun.sh", "pkg.dev", "docker.io", "cloudflare.com"
                    };
                case "ai":
                    return new[]
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
                case "media":
                    return new[]
                    {
                        "discord.com", "discordapp.com", "discordapp.net", "discord.gg", "discord.media", "discordstatus.com",
                        "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtubei.googleapis.com", "ggpht.com",
                        "twitch.tv", "ttvnw.net", "jtvnw.net",
                        "telegram.org", "t.me", "web.telegram.org", "tdesktop.com", "telesco.pe", "telegra.ph"
                    };
                case "social":
                    return new[]
                    {
                        "telegram.org", "t.me", "web.telegram.org", "tdesktop.com", "telesco.pe", "telegra.ph",
                        "spotify.com", "spotify.net", "scdn.co", "spotifycdn.com", "pscdn.co", "byspotify.com", "spotify.link", "spotilocal.com",
                        "spclient.wg.spotify.com", "apresolve.spotify.com", "dealer.spotify.com", "login5.spotify.com", "accounts.spotify.com", "open.spotify.com",
                        "audio-ak-spotify-com.akamaized.net", "heads4-ak-spotify-com.akamaized.net", "akamaized.net",
                        "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net",
                        "twitter.com", "x.com", "twimg.com", "t.co", "threads.net",
                        "tiktok.com", "linkedin.com", "netflix.com", "nflxvideo.net",
                        "patreon.com", "reddit.com", "redd.it", "medium.com", "quora.com",
                        "canva.com", "figma.com", "notion.so", "rutracker.org", "rutracker.net",
                        "github.com", "githubusercontent.com", "githubassets.com",
                        "vscode-cdn.net", "visualstudio.com", "jetbrains.com",
                        "docker.com", "docker.io", "npmjs.org", "pypi.org", "cloudflare.com", "ipinfo.io"
                    };
                default:
                    return new string[0];
            }
        }

        private static string ApplyCSharpReloadRules(string bodyJson)
        {
            try
            {
                var req = !string.IsNullOrEmpty(bodyJson) ? MiniJson.Deserialize(bodyJson) as Dictionary<string, object> : null;
                if (req == null)
                {
                    if (!string.IsNullOrEmpty(_activeConfigPath) && File.Exists(_activeConfigPath))
                    {
                        LoadCompatibleJsonString(File.ReadAllText(_activeConfigPath, Encoding.UTF8));
                    }
                }
                else
                {
                    bool rebuildFromCats = false;
                    var catsDict = MiniJson.GetDict(req, "categories");
                    if (catsDict != null)
                    {
                        rebuildFromCats = true;
                        var nextCats = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                        foreach (var kv in catsDict)
                            nextCats[kv.Key] = MiniJson.GetBool(catsDict, kv.Key, false);
                        _activeCategories = nextCats;
                    }

                    if (req.ContainsKey("custom_proxy_domains") || req.ContainsKey("custom_proxy"))
                    {
                        string pKey = req.ContainsKey("custom_proxy_domains") ? "custom_proxy_domains" : "custom_proxy";
                        var nextCustomProxy = new List<string>();
                        foreach (string s in MiniJson.GetStrList(req, pKey))
                        {
                            string clean = (s ?? "").Trim().ToLowerInvariant();
                            if (!string.IsNullOrEmpty(clean)) nextCustomProxy.Add(clean);
                        }
                        _customProxyList = nextCustomProxy;
                        rebuildFromCats = rebuildFromCats || _activeCategories.Count > 0;
                    }

                    if (req.ContainsKey("custom_direct_domains") || req.ContainsKey("custom_direct"))
                    {
                        string dKey = req.ContainsKey("custom_direct_domains") ? "custom_direct_domains" : "custom_direct";
                        var nextCustomDirect = new List<string>();
                        foreach (string s in MiniJson.GetStrList(req, dKey))
                        {
                            string clean = (s ?? "").Trim().ToLowerInvariant();
                            if (!string.IsNullOrEmpty(clean)) nextCustomDirect.Add(clean);
                        }
                        _customDirectList = nextCustomDirect;
                    }

                    if (req.ContainsKey("proxy_all"))
                        _defaultOutboundIsProxy = MiniJson.GetBool(req, "proxy_all", _defaultOutboundIsProxy);

                    var newDirect = new HashSet<string>(
                        _baseDirectDomains.Count > 0 ? _baseDirectDomains : _directDomains,
                        StringComparer.OrdinalIgnoreCase);
                    var newProxy = rebuildFromCats
                        ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                        : new HashSet<string>(_proxyDomains, StringComparer.OrdinalIgnoreCase);

                    if (rebuildFromCats)
                    {
                        foreach (var kv in _activeCategories)
                        {
                            if (kv.Value)
                            {
                                foreach (string dom in GetCSharpCategoryDomains(kv.Key))
                                    newProxy.Add(dom);
                            }
                        }
                    }

                    foreach (string cp in _customProxyList)
                    {
                        newProxy.Add(cp);
                        newDirect.Remove(cp);
                    }
                    foreach (string cd in _customDirectList)
                    {
                        newDirect.Add(cd);
                        newProxy.Remove(cd);
                    }

                    _proxyDomains = newProxy;
                    _directDomains = newDirect;
                }
            }
            catch { }

            _pacRevision++;
            return MiniJson.Serialize(new Dictionary<string, object>
            {
                { "ok", true },
                { "pac_rev", _pacRevision },
                { "proxy_domains", _proxyDomains.Count },
                { "direct_domains", _directDomains.Count }
            });
        }

        private static async Task<string> ExecuteCSharpInstantWakeAsync(string reqJson)
        {
            string reason = "manual";
            try
            {
                var d = MiniJson.Deserialize(reqJson) as Dictionary<string, object>;
                string r = d != null ? MiniJson.GetStr(d, "reason") : null;
                if (!string.IsNullOrEmpty(r)) reason = r;
            }
            catch { }

            var sw = Stopwatch.StartNew();
            ResetMuxLanes();
            DrainWarmPool();
            CancellationToken tok = (_cts != null) ? _cts.Token : CancellationToken.None;
            try { await EnsureInteractiveLaneWarmAsync(tok).ConfigureAwait(false); } catch { }
            sw.Stop();

            InstantWakeCount++;
            LastWakeReason = reason;
            LastWakeUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            _pacRevision++;

            return MiniJson.Serialize(new Dictionary<string, object>
            {
                { "ok", IsRunning },
                { "reason", reason },
                { "pac_rev", _pacRevision },
                { "standby_ready", StandbyReady },
                { "active_node", ActiveNodeName ?? "" },
                { "failover_ms", (int)sw.ElapsedMilliseconds },
                { "instant_wake_count", InstantWakeCount }
            });
        }

        private static void ObserveFaultedTask(Task t)
        {
            if (t != null)
            {
                t.ContinueWith(x => { var _ = x.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
            }
        }

        private static async Task<bool> AwaitSocketTaskAsync(Task opTask, TcpClient tcp, int remainingMs, CancellationToken ct)
        {
            if (remainingMs <= 0 || ct.IsCancellationRequested)
            {
                ObserveFaultedTask(opTask);
                try { if (tcp != null) tcp.Close(); } catch { }
                return false;
            }
            Task delayTask = ct.CanBeCanceled ? Task.Delay(remainingMs, ct) : Task.Delay(remainingMs);
            Task winner = await Task.WhenAny(opTask, delayTask).ConfigureAwait(false);
            if (winner != opTask)
            {
                ObserveFaultedTask(opTask);
                try { if (tcp != null) tcp.Close(); } catch { }
                return false;
            }
            await opTask.ConfigureAwait(false);
            return true;
        }

        private static async Task<int> ReadWithTimeoutAsync(Stream s, byte[] buf, int offset, int count, TcpClient tcp, int remainingMs, CancellationToken ct)
        {
            if (remainingMs <= 0 || ct.IsCancellationRequested)
            {
                try { if (tcp != null) tcp.Close(); } catch { }
                return -1;
            }
            Task<int> readTask = s.ReadAsync(buf, offset, count);
            Task delayTask = ct.CanBeCanceled ? Task.Delay(remainingMs, ct) : Task.Delay(remainingMs);
            Task winner = await Task.WhenAny(readTask, delayTask).ConfigureAwait(false);
            if (winner != readTask)
            {
                ObserveFaultedTask(readTask);
                try { if (tcp != null) tcp.Close(); } catch { }
                return -1;
            }
            return await readTask.ConfigureAwait(false);
        }

        private static async Task<Dictionary<string, object>> ProbeSingleAiHostCSharpAsync(string host, CancellationToken ct)
        {
            const int totalTimeoutMs = 4000;
            var sw = Stopwatch.StartNew();
            int httpCode = 0;
            string status;
            try
            {
                using (var tcp = new TcpClient())
                {
                    tcp.ReceiveTimeout = totalTimeoutMs;
                    tcp.SendTimeout = 2500;
                    if (IsRunning && _localPort > 0)
                    {
                        if (!await AwaitSocketTaskAsync(tcp.ConnectAsync(IPAddress.Loopback, _localPort), tcp, totalTimeoutMs - (int)sw.ElapsedMilliseconds, ct).ConfigureAwait(false))
                            return BuildAiPulseEntry("down", 0, (int)sw.ElapsedMilliseconds, host);
                        NetworkStream ns = tcp.GetStream();
                        byte[] connectReq = Encoding.ASCII.GetBytes("CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\nX-Pixel-Internal-Probe: 1\r\n\r\n");
                        if (!await AwaitSocketTaskAsync(ns.WriteAsync(connectReq, 0, connectReq.Length), tcp, totalTimeoutMs - (int)sw.ElapsedMilliseconds, ct).ConfigureAwait(false))
                            return BuildAiPulseEntry("down", 0, (int)sw.ElapsedMilliseconds, host);
                        byte[] connResp = new byte[512];
                        int cr = await ReadWithTimeoutAsync(ns, connResp, 0, connResp.Length, tcp, totalTimeoutMs - (int)sw.ElapsedMilliseconds, ct).ConfigureAwait(false);
                        string connHdr = cr > 0 ? Encoding.ASCII.GetString(connResp, 0, cr) : "";
                        if (connHdr.IndexOf("200", StringComparison.Ordinal) < 0)
                            return BuildAiPulseEntry("down", 0, (int)sw.ElapsedMilliseconds, host);
                    }
                    else
                    {
                        if (!await AwaitSocketTaskAsync(tcp.ConnectAsync(host, 443), tcp, totalTimeoutMs - (int)sw.ElapsedMilliseconds, ct).ConfigureAwait(false))
                            return BuildAiPulseEntry("down", 0, (int)sw.ElapsedMilliseconds, host);
                    }

                    using (var ssl = new SslStream(tcp.GetStream(), false, (s, cert, chain, errs) => errs == SslPolicyErrors.None))
                    {
                        if (!await AwaitSocketTaskAsync(ssl.AuthenticateAsClientAsync(host), tcp, totalTimeoutMs - (int)sw.ElapsedMilliseconds, ct).ConfigureAwait(false))
                            return BuildAiPulseEntry("down", 0, (int)sw.ElapsedMilliseconds, host);
                        byte[] req = Encoding.ASCII.GetBytes("HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: PixelTunnel/2.0\r\n\r\n");
                        if (!await AwaitSocketTaskAsync(ssl.WriteAsync(req, 0, req.Length), tcp, totalTimeoutMs - (int)sw.ElapsedMilliseconds, ct).ConfigureAwait(false))
                            return BuildAiPulseEntry("down", 0, (int)sw.ElapsedMilliseconds, host);
                        byte[] respBuf = new byte[256];
                        int n = await ReadWithTimeoutAsync(ssl, respBuf, 0, respBuf.Length, tcp, totalTimeoutMs - (int)sw.ElapsedMilliseconds, ct).ConfigureAwait(false);
                        if (n > 12)
                        {
                            string first = Encoding.ASCII.GetString(respBuf, 0, n);
                            Match m = Regex.Match(first, @"^HTTP/\d\.\d\s+(\d{3})");
                            if (m.Success) int.TryParse(m.Groups[1].Value, out httpCode);
                        }
                    }
                }
            }
            catch { }
            sw.Stop();
            if (httpCode >= 100 && httpCode < 500 && httpCode != 429) status = "ok";
            else if (httpCode == 429 || httpCode == 503 || httpCode == 529) status = "degraded";
            else status = "down";
            return BuildAiPulseEntry(status, httpCode, (int)sw.ElapsedMilliseconds, host);
        }

        private static Dictionary<string, object> BuildAiPulseEntry(string status, int httpCode, int latencyMs, string host)
        {
            return new Dictionary<string, object>
            {
                { "status", status },
                { "http_code", httpCode },
                { "latency_ms", latencyMs },
                { "host", host }
            };
        }

        private static async Task<string> ProbeAiPulseCSharpAsync(bool forceRefresh)
        {
            lock (_aiPulseCacheLock)
            {
                if (!forceRefresh && !string.IsNullOrEmpty(_cachedAiPulseJson) && (DateTime.UtcNow - _cachedAiPulseUtc).TotalSeconds < 25)
                {
                    var cachedObj = MiniJson.Deserialize(_cachedAiPulseJson) as Dictionary<string, object>;
                    if (cachedObj != null)
                    {
                        cachedObj["cached"] = true;
                        return MiniJson.Serialize(cachedObj);
                    }
                }
            }

            CancellationToken ct = (_cts != null) ? _cts.Token : CancellationToken.None;
            Task<Dictionary<string, object>> tGem = ProbeSingleAiHostCSharpAsync("daily-cloudcode-pa.googleapis.com", ct);
            Task<Dictionary<string, object>> tCla = ProbeSingleAiHostCSharpAsync("api.anthropic.com", ct);
            Task<Dictionary<string, object>> tOai = ProbeSingleAiHostCSharpAsync("api.openai.com", ct);
            await Task.WhenAll(tGem, tCla, tOai).ConfigureAwait(false);

            var payload = new Dictionary<string, object>
            {
                { "ok", true },
                { "node", ActiveNodeName ?? "CSharp-Fallback" },
                { "checked_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                { "ttl_sec", 30 },
                { "cached", false },
                { "providers", new Dictionary<string, object>
                    {
                        { "gemini", tGem.Result },
                        { "claude", tCla.Result },
                        { "openai", tOai.Result }
                    }
                }
            };
            string json = MiniJson.Serialize(payload);
            lock (_aiPulseCacheLock)
            {
                _cachedAiPulseJson = json;
                _cachedAiPulseUtc = DateTime.UtcNow;
            }
            return json;
        }

        private static async Task<string> RunCSharpXrayAsync()
        {
            var sw = Stopwatch.StartNew();
            long driftSec;
            string clockSrc;
            bool clockSynced = false;
            try { clockSynced = ProbeAndSyncClockOffset(out driftSec, out clockSrc); }
            catch { driftSec = 0; clockSrc = "none"; }

            string certIssuer = "";
            string avMitm = "";
            bool sslClean = true;
            try { sslClean = !DetectSslMitmInterceptor(out certIssuer, out avMitm); } catch { }

            List<NodeBenchmarkResult> bench = new List<NodeBenchmarkResult>();
            try { bench = await RunParallelNodeBenchmarkAsync(3200).ConfigureAwait(false); } catch { }

            int healthyNodes = 0;
            int bestPing = 9999;
            foreach (var b in bench)
            {
                if (b.Ok)
                {
                    healthyNodes++;
                    if (b.HandshakeMs < bestPing) bestPing = b.HandshakeMs;
                }
            }

            string pulseRaw = await ProbeAiPulseCSharpAsync(true).ConfigureAwait(false);
            var pulseObj = MiniJson.Deserialize(pulseRaw) as Dictionary<string, object>;
            var provs = pulseObj != null ? MiniJson.GetDict(pulseObj, "providers") : null;
            var gem = provs != null ? MiniJson.GetDict(provs, "gemini") : null;
            var cla = provs != null ? MiniJson.GetDict(provs, "claude") : null;
            var oai = provs != null ? MiniJson.GetDict(provs, "openai") : null;
            string gemSt = gem != null ? MiniJson.GetStr(gem, "status") : "down";
            string claSt = cla != null ? MiniJson.GetStr(cla, "status") : "down";
            string oaiSt = oai != null ? MiniJson.GetStr(oai, "status") : "down";
            int gemMs = gem != null ? MiniJson.GetInt(gem, "latency_ms", 0) : 0;

            bool aiAllOk = (gemSt == "ok" && claSt == "ok");
            string utlsStatus = string.IsNullOrEmpty(GoEngineFallbackReason) && sslClean ? "ok" : "warn";
            string utlsSummary = !sslClean
                ? ("Обнаружен SSL-перехватчик: " + (string.IsNullOrEmpty(avMitm) ? certIssuer : avMitm))
                : (!string.IsNullOrEmpty(GoEngineFallbackReason) ? GoEngineFallbackReason : "TLS без локального MITM-перехвата");

            var cards = new List<object>
            {
                new Dictionary<string, object> {
                    { "id", "isp_hosts" }, { "title", "Провайдер & Hosts" },
                    { "status", clockSynced ? "ok" : "warn" },
                    { "summary", clockSynced ? ("Время синхронизировано (" + clockSrc + ", сдвиг " + driftSec + "s)") : "Требуется проверка Hosts/DNS провайдера" },
                    { "latency_ms", 0 }
                },
                new Dictionary<string, object> {
                    { "id", "tspu_mtu" }, { "title", "ТСПУ 64KB & MTU Upload" },
                    { "status", LastAntiFreezeProbePassed ? "ok" : "warn" },
                    { "summary", "Anti-DPI профиль: " + AntiDpiProfileName + (LastAntiFreezeProbePassed ? " (без 16KB фризов)" : " (эскалация DPI)") },
                    { "latency_ms", bestPing < 9999 ? bestPing : 0 }
                },
                new Dictionary<string, object> {
                    { "id", "utls_mitm" }, { "title", "uTLS Chrome & Антивирус SSL" },
                    { "status", utlsStatus },
                    { "summary", utlsSummary },
                    { "latency_ms", 0 }
                },
                new Dictionary<string, object> {
                    { "id", "node_matrix" }, { "title", "Ноды & Горячий резерв" },
                    { "status", healthyNodes > 0 ? "ok" : "down" },
                    { "summary", healthyNodes + "/" + bench.Count + " узлов онлайн, пинг " + (bestPing < 9999 ? (bestPing + " мс") : "—") },
                    { "latency_ms", bestPing < 9999 ? bestPing : 0 }
                },
                new Dictionary<string, object> {
                    { "id", "ide_sockets" }, { "title", "Сокеты IDE по PID" },
                    { "status", IsRunning ? "ok" : "warn" },
                    { "summary", IsRunning ? ("HTTP :" + _localPort + " • SOCKS :" + _socksPort + (string.IsNullOrEmpty(ActiveWslBridgeIp) ? "" : (" • WSL " + ActiveWslBridgeIp))) : "Локальные порты не активны" },
                    { "latency_ms", 0 }
                },
                new Dictionary<string, object> {
                    { "id", "ai_pulse" }, { "title", "AI API & OAuth2" },
                    { "status", aiAllOk ? "ok" : ((gemSt == "ok" || claSt == "ok") ? "warn" : "down") },
                    { "summary", string.Format(CultureInfo.InvariantCulture, "Gemini: {0} ({1}ms) • Claude: {2} • OpenAI: {3}", gemSt, gemMs, claSt, oaiSt) },
                    { "latency_ms", gemMs }
                }
            };

            sw.Stop();
            return MiniJson.Serialize(new Dictionary<string, object>
            {
                { "ok", healthyNodes > 0 },
                { "checked_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                { "duration_ms", (int)sw.ElapsedMilliseconds },
                { "overall", (healthyNodes > 0 && sslClean) ? "ok" : "warn" },
                { "cards", cards },
                { "report_text", "" }
            });
        }

        private static async Task<string> QueryLocalEndpointAsync(string method, string pathAndQuery, string jsonBody, int timeoutMs)
        {
            if (_localPort <= 0) return "";
            int totalTimeout = timeoutMs > 0 ? timeoutMs : 3000;
            var sw = Stopwatch.StartNew();
            try
            {
                using (var tcp = new TcpClient())
                {
                    if (!await AwaitSocketTaskAsync(tcp.ConnectAsync(IPAddress.Loopback, _localPort), tcp, Math.Min(totalTimeout, 2500), CancellationToken.None).ConfigureAwait(false))
                        return "";
                    tcp.ReceiveTimeout = totalTimeout;
                    tcp.SendTimeout = 3000;

                    byte[] bodyBytes = string.IsNullOrEmpty(jsonBody) ? new byte[0] : Encoding.UTF8.GetBytes(jsonBody);
                    var reqSb = new StringBuilder();
                    reqSb.Append(method).Append(' ').Append(pathAndQuery).Append(" HTTP/1.1\r\n");
                    reqSb.Append("Host: 127.0.0.1:").Append(_localPort.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
                    if (!string.IsNullOrEmpty(_localControlToken))
                        reqSb.Append("X-Pixel-Local-Token: ").Append(_localControlToken).Append("\r\n");
                    if (bodyBytes.Length > 0)
                    {
                        reqSb.Append("Content-Type: application/json; charset=utf-8\r\n");
                        reqSb.Append("Content-Length: ").Append(bodyBytes.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
                    }
                    reqSb.Append("Connection: close\r\n\r\n");

                    byte[] hdrBytes = Encoding.ASCII.GetBytes(reqSb.ToString());
                    NetworkStream ns = tcp.GetStream();
                    if (!await AwaitSocketTaskAsync(ns.WriteAsync(hdrBytes, 0, hdrBytes.Length), tcp, totalTimeout - (int)sw.ElapsedMilliseconds, CancellationToken.None).ConfigureAwait(false))
                        return "";
                    if (bodyBytes.Length > 0 &&
                        !await AwaitSocketTaskAsync(ns.WriteAsync(bodyBytes, 0, bodyBytes.Length), tcp, totalTimeout - (int)sw.ElapsedMilliseconds, CancellationToken.None).ConfigureAwait(false))
                        return "";

                    using (var ms = new MemoryStream())
                    {
                        byte[] buf = new byte[4096];
                        while (true)
                        {
                            int r = await ReadWithTimeoutAsync(ns, buf, 0, buf.Length, tcp, totalTimeout - (int)sw.ElapsedMilliseconds, CancellationToken.None).ConfigureAwait(false);
                            if (r < 0) return "";
                            if (r == 0) break;
                            ms.Write(buf, 0, r);
                            if (ms.Length > 2 * 1024 * 1024) break;
                        }
                        string full = Encoding.UTF8.GetString(ms.ToArray());
                        int sep = full.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                        if (sep < 0) return "";
                        string respHdr = full.Substring(0, sep);
                        string rawBody = full.Substring(sep + 4);
                        if (respHdr.IndexOf("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                            return DecodeHttpChunkedBody(rawBody);
                        return rawBody;
                    }
                }
            }
            catch
            {
                return "";
            }
        }

        private static string DecodeHttpChunkedBody(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            var sb = new StringBuilder(raw.Length);
            int pos = 0;
            while (pos < raw.Length)
            {
                int crlf = raw.IndexOf("\r\n", pos, StringComparison.Ordinal);
                if (crlf < 0) break;
                string sizeHex = raw.Substring(pos, crlf - pos).Split(';')[0].Trim();
                int chunkLen;
                if (!int.TryParse(sizeHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out chunkLen) || chunkLen <= 0)
                    break;
                pos = crlf + 2;
                int take = Math.Min(chunkLen, raw.Length - pos);
                if (take > 0) sb.Append(raw, pos, take);
                pos += take + 2;
            }
            return sb.ToString();
        }

        public static Task<string> QueryStatusV4JsonAsync()
        {
            if (UsingGoEngine) return QueryLocalEndpointAsync("GET", "/__pixelcore/v4/status", null, 3000);
            return Task.FromResult(BuildCSharpStatusV4Json());
        }

        public static Task<string> QueryTelemetryV2JsonAsync()
        {
            if (UsingGoEngine) return QueryLocalEndpointAsync("GET", "/__pixelcore/telemetry", null, 3000);
            return Task.FromResult(BuildCSharpStatusV4Json());
        }

        public static Task<string> QueryLiveRoutesV4JsonAsync()
        {
            if (UsingGoEngine) return QueryLocalEndpointAsync("GET", "/__pixelcore/v4/live-routes", null, 3000);
            return Task.FromResult(BuildCSharpLiveRoutesJson());
        }

        public static Task<string> QueryAiPulseV4JsonAsync(bool forceRefresh = false)
        {
            if (UsingGoEngine) return QueryLocalEndpointAsync("GET", "/__pixelcore/v4/ai-pulse", null, 6000);
            return ProbeAiPulseCSharpAsync(forceRefresh);
        }

        public static async Task<int> ReloadRulesV4Async(string optionalBodyJson)
        {
            string resJson;
            if (UsingGoEngine)
            {
                resJson = await QueryLocalEndpointAsync("POST", "/__pixelcore/v4/reload-rules", optionalBodyJson ?? "{}", 4000).ConfigureAwait(false);
            }
            else
            {
                resJson = ApplyCSharpReloadRules(optionalBodyJson);
            }
            var obj = MiniJson.Deserialize(resJson) as Dictionary<string, object>;
            int pr = obj != null ? MiniJson.GetInt(obj, "pac_rev", 0) : 0;
            if (pr > 0) _pacRevision = pr;
            return _pacRevision;
        }

        public static Task<string> TriggerInstantWakeAsync(string reason = "manual")
        {
            if (UsingGoEngine)
            {
                string body = "{\"reason\":\"" + EscapeJson(reason ?? "manual") + "\"}";
                return QueryLocalEndpointAsync("POST", "/__pixelcore/v4/instant-wake", body, 5000);
            }
            return ExecuteCSharpInstantWakeAsync("{\"reason\":\"" + EscapeJson(reason ?? "manual") + "\"}");
        }

        public static Task<string> RunXrayV4Async()
        {
            if (UsingGoEngine) return QueryLocalEndpointAsync("POST", "/__pixelcore/v4/run-xray", "{}", 15000);
            return RunCSharpXrayAsync();
        }
    }

    // =========================================================================
    // V2.0 NATIVE GO uTLS ENGINE HOST + WIN32 JOBOBJECT + PROCESS RESOLVER + JSON
    // =========================================================================
    internal sealed class Win32JobObject : IDisposable
    {
        private IntPtr _handle;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr hJob, int jobObjectInfoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        private const int JobObjectExtendedLimitInformation = 9;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

        public Win32JobObject()
        {
            _handle = CreateJobObject(IntPtr.Zero, null);
            if (_handle == IntPtr.Zero) return;

            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            uint len = (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            if (!SetInformationJobObject(_handle, JobObjectExtendedLimitInformation, ref info, len))
            {
                CloseHandle(_handle);
                _handle = IntPtr.Zero;
            }
        }

        public bool TryAttach(Process proc)
        {
            if (_handle == IntPtr.Zero || proc == null) return false;
            try
            {
                return AssignProcessToJobObject(_handle, proc.Handle);
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            IntPtr h = Interlocked.Exchange(ref _handle, IntPtr.Zero);
            if (h != IntPtr.Zero)
            {
                try { CloseHandle(h); } catch { }
            }
        }
    }

    internal static class Win32TcpProcessResolver
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private static readonly ConcurrentDictionary<int, Tuple<string, long>> _pidNameCache = new ConcurrentDictionary<int, Tuple<string, long>>();

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        private static int NetworkPortToHost(uint netPortDword)
        {
            ushort low = (ushort)(netPortDword & 0xFFFF);
            return ((low & 0xFF) << 8) | ((low >> 8) & 0xFF);
        }

        public static void ResolveLocalPortOwner(int clientSourcePort, out int pid, out string procName)
        {
            pid = 0;
            procName = "";
            if (clientSourcePort <= 0) return;

            IntPtr buf = IntPtr.Zero;
            try
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (size <= 0 || size > 4 * 1024 * 1024) return;
                buf = Marshal.AllocHGlobal(size);
                if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;

                int count = Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                IntPtr rowPtr = IntPtr.Add(buf, 4);
                for (int i = 0; i < count; i++)
                {
                    var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                    // 0x0100007F == 127.0.0.1 in network byte order
                    if (row.localAddr == 0x0100007Fu && NetworkPortToHost(row.localPort) == clientSourcePort && row.owningPid > 0)
                    {
                        pid = (int)row.owningPid;
                        break;
                    }
                }
            }
            catch { }
            finally
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            }

            if (pid > 0)
            {
                long nowTicks = DateTime.UtcNow.Ticks;
                Tuple<string, long> cached;
                if (_pidNameCache.TryGetValue(pid, out cached) && (nowTicks - cached.Item2) < TimeSpan.TicksPerSecond * 15)
                {
                    procName = cached.Item1;
                    return;
                }
                try
                {
                    using (var p = Process.GetProcessById(pid))
                    {
                        procName = p.ProcessName;
                        _pidNameCache[pid] = Tuple.Create(procName, nowTicks);
                    }
                }
                catch { }
            }
        }
    }

    internal static class NativeUtlsEngineHost
    {
        private static readonly object _hostLock = new object();
        private static Process _goProc;
        private static StreamWriter _goStdin;
        private static Win32JobObject _job;

        public static string EngineCacheDir
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PixelTunnel",
                    "engine");
            }
        }

        private static string ComputeSha256Hex(Stream s)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(s);
                var sb = new StringBuilder(64);
                foreach (byte b in hash) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        private static bool EnsureVerifiedGoBinary(out string exePath, out string failReason)
        {
            exePath = Path.Combine(EngineCacheDir, "pixelcore-utls-" + EmbeddedEngineMeta.EngineVersion + ".exe");
            failReason = "";

            string expected = (EmbeddedEngineMeta.ExpectedSha256 ?? "").Trim().ToLowerInvariant();
            Stream resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(EmbeddedEngineMeta.ResourceName);
            if (resStream == null)
            {
                failReason = "Встроенный Go uTLS модуль отсутствует — используется C# Fallback";
                return false;
            }

            try
            {
                Directory.CreateDirectory(EngineCacheDir);
                if (File.Exists(exePath) && !string.IsNullOrEmpty(expected))
                {
                    using (var fs = File.OpenRead(exePath))
                    {
                        if (string.Equals(ComputeSha256Hex(fs), expected, StringComparison.OrdinalIgnoreCase))
                        {
                            resStream.Dispose();
                            return true;
                        }
                    }
                }

                byte[] rawExe;
                using (resStream)
                using (var gzip = new GZipStream(resStream, CompressionMode.Decompress))
                using (var ms = new MemoryStream())
                {
                    gzip.CopyTo(ms);
                    rawExe = ms.ToArray();
                }

                if (rawExe.Length < 4096)
                {
                    failReason = "Распакованный Go uTLS модуль повреждён — активирован C# Fallback";
                    return false;
                }

                if (!string.IsNullOrEmpty(expected))
                {
                    using (var verifyMs = new MemoryStream(rawExe, false))
                    {
                        string actual = ComputeSha256Hex(verifyMs);
                        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                        {
                            failReason = "Несовпадение SHA-256 встроенного Go uTLS модуля — активирован C# Fallback";
                            return false;
                        }
                    }
                }

                string tmpPath = exePath + ".tmp." + Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture);
                File.WriteAllBytes(tmpPath, rawExe);
                if (File.Exists(exePath)) File.Delete(exePath);
                File.Move(tmpPath, exePath);
                return true;
            }
            catch (Exception ex)
            {
                failReason = "Ошибка распаковки Go uTLS (" + ex.Message + ") — активирован C# Fallback";
                return false;
            }
        }

        public static bool TryStart(string configPath, string localToken, int httpPort, out string failReason)
        {
            lock (_hostLock)
            {
                StopLocked();
                string exePath;
                if (!EnsureVerifiedGoBinary(out exePath, out failReason))
                {
                    return false;
                }

                if (string.IsNullOrEmpty(configPath) || !File.Exists(configPath))
                {
                    failReason = "Отсутствует active_config.json для Go uTLS — активирован C# Fallback";
                    return false;
                }

                try
                {
                    var job = new Win32JobObject();
                    var psi = new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = "--headless --watch-stdin --config \"" + configPath + "\"",
                        WorkingDirectory = Path.GetDirectoryName(configPath) ?? EngineCacheDir,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardInput = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    if (!string.IsNullOrEmpty(localToken))
                    {
                        psi.EnvironmentVariables["PIXEL_LOCAL_TOKEN"] = localToken;
                    }

                    Process proc = Process.Start(psi);
                    if (proc == null)
                    {
                        job.Dispose();
                        failReason = "Не удалось запустить Go uTLS процесс — активирован C# Fallback";
                        return false;
                    }

                    StreamWriter stdinWriter = null;
                    try { stdinWriter = proc.StandardInput; } catch { }

                    if (!job.TryAttach(proc))
                    {
                        if (stdinWriter != null) { try { stdinWriter.Dispose(); } catch { } }
                        try { proc.Kill(); } catch { }
                        proc.Dispose();
                        job.Dispose();
                        failReason = "Ошибка Win32 JobObject привязки — активирован C# Fallback";
                        return false;
                    }

                    _job = job;
                    _goStdin = stdinWriter;
                    _goProc = proc;

                    Stopwatch sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < 2500)
                    {
                        if (proc.HasExited)
                        {
                            int exitCode = proc.ExitCode;
                            StopLocked();
                            failReason = "Go uTLS завершился при старте (код " + exitCode + ") — активирован C# Fallback";
                            return false;
                        }
                        if (ProbeGoControlReady(httpPort, localToken))
                        {
                            failReason = "";
                            return true;
                        }
                        Thread.Sleep(45);
                    }

                    StopLocked();
                    failReason = "Go uTLS не поднял локальный порт за 2.5с — активирован C# Fallback";
                    return false;
                }
                catch (Exception ex)
                {
                    StopLocked();
                    failReason = "Запуск Go uTLS заблокирован (" + ex.Message + ") — активирован C# Fallback";
                    return false;
                }
            }
        }

        private static bool ProbeGoControlReady(int port, string token)
        {
            try
            {
                using (var tcp = new TcpClient())
                {
                    var res = tcp.BeginConnect(IPAddress.Loopback, port, null, null);
                    if (!res.AsyncWaitHandle.WaitOne(120)) return false;
                    tcp.EndConnect(res);
                    tcp.ReceiveTimeout = 250;
                    tcp.SendTimeout = 250;
                    string req = "GET /__pixelcore/v4/status HTTP/1.1\r\nHost: 127.0.0.1:" +
                                 port.ToString(CultureInfo.InvariantCulture) +
                                 (string.IsNullOrEmpty(token) ? "" : ("\r\nX-Pixel-Local-Token: " + token)) +
                                 "\r\nConnection: close\r\n\r\n";
                    byte[] b = Encoding.ASCII.GetBytes(req);
                    NetworkStream ns = tcp.GetStream();
                    ns.Write(b, 0, b.Length);
                    byte[] rb = new byte[64];
                    int n = ns.Read(rb, 0, rb.Length);
                    return n > 12 && Encoding.ASCII.GetString(rb, 0, n).Contains("200");
                }
            }
            catch { return false; }
        }

        public static void Stop()
        {
            lock (_hostLock) { StopLocked(); }
        }

        private static void StopLocked()
        {
            if (_goStdin != null)
            {
                try { _goStdin.Close(); } catch { }
                try { _goStdin.Dispose(); } catch { }
                _goStdin = null;
            }
            if (_goProc != null)
            {
                try
                {
                    if (!_goProc.HasExited && !_goProc.WaitForExit(300))
                    {
                        _goProc.Kill();
                        _goProc.WaitForExit(400);
                    }
                }
                catch { }
                try { _goProc.Dispose(); } catch { }
                _goProc = null;
            }
            if (_job != null)
            {
                _job.Dispose();
                _job = null;
            }
        }
    }

    internal static class MiniJson
    {
        public static object Deserialize(string json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            int idx = 0;
            try { return ParseValue(json, ref idx); }
            catch { return null; }
        }

        public static Dictionary<string, object> GetDict(Dictionary<string, object> d, string key)
        {
            object v;
            if (d != null && d.TryGetValue(key, out v)) return v as Dictionary<string, object>;
            return null;
        }

        public static List<object> GetList(Dictionary<string, object> d, string key)
        {
            object v;
            if (d != null && d.TryGetValue(key, out v)) return v as List<object>;
            return null;
        }

        public static List<string> GetStrList(Dictionary<string, object> d, string key)
        {
            var res = new List<string>();
            var lst = GetList(d, key);
            if (lst != null)
            {
                foreach (var item in lst)
                {
                    if (item != null) res.Add(item.ToString());
                }
            }
            return res;
        }

        public static string GetStr(Dictionary<string, object> d, string key)
        {
            object v;
            if (d != null && d.TryGetValue(key, out v) && v != null) return v.ToString();
            return null;
        }

        public static bool GetBool(Dictionary<string, object> d, string key, bool def)
        {
            object v;
            if (d != null && d.TryGetValue(key, out v))
            {
                if (v is bool) return (bool)v;
                bool b;
                if (v != null && bool.TryParse(v.ToString(), out b)) return b;
            }
            return def;
        }

        public static int GetInt(Dictionary<string, object> d, string key, int def)
        {
            object v;
            if (d != null && d.TryGetValue(key, out v) && v != null)
            {
                if (v is long) return (int)(long)v;
                if (v is double) return (int)(double)v;
                int i;
                if (int.TryParse(v.ToString(), NumberStyles.Any, CultureInfo.InvariantCulture, out i)) return i;
            }
            return def;
        }

        public static long GetLong(Dictionary<string, object> d, string key, long def)
        {
            object v;
            if (d != null && d.TryGetValue(key, out v) && v != null)
            {
                if (v is long) return (long)v;
                if (v is double) return (long)(double)v;
                long l;
                if (long.TryParse(v.ToString(), NumberStyles.Any, CultureInfo.InvariantCulture, out l)) return l;
            }
            return def;
        }

        public static double GetDouble(Dictionary<string, object> d, string key, double def)
        {
            object v;
            if (d != null && d.TryGetValue(key, out v) && v != null)
            {
                if (v is double) return (double)v;
                if (v is long) return (double)(long)v;
                double dbl;
                if (double.TryParse(v.ToString(), NumberStyles.Any, CultureInfo.InvariantCulture, out dbl)) return dbl;
            }
            return def;
        }

        private static void SkipWs(string s, ref int i)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        }

        private static object ParseValue(string s, ref int i)
        {
            SkipWs(s, ref i);
            if (i >= s.Length) return null;
            char c = s[i];
            if (c == '{') return ParseObject(s, ref i);
            if (c == '[') return ParseArray(s, ref i);
            if (c == '"') return ParseString(s, ref i);
            if (c == 't' && i + 4 <= s.Length && s.Substring(i, 4) == "true") { i += 4; return true; }
            if (c == 'f' && i + 5 <= s.Length && s.Substring(i, 5) == "false") { i += 5; return false; }
            if (c == 'n' && i + 4 <= s.Length && s.Substring(i, 4) == "null") { i += 4; return null; }
            return ParseNumber(s, ref i);
        }

        private static Dictionary<string, object> ParseObject(string s, ref int i)
        {
            var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            i++;
            while (i < s.Length)
            {
                SkipWs(s, ref i);
                if (i >= s.Length) break;
                if (s[i] == '}') { i++; return dict; }
                string key = ParseString(s, ref i);
                SkipWs(s, ref i);
                if (i < s.Length && s[i] == ':') i++;
                dict[key ?? ""] = ParseValue(s, ref i);
                SkipWs(s, ref i);
                if (i < s.Length && s[i] == ',') i++;
            }
            return dict;
        }

        private static List<object> ParseArray(string s, ref int i)
        {
            var list = new List<object>();
            i++;
            while (i < s.Length)
            {
                SkipWs(s, ref i);
                if (i >= s.Length) break;
                if (s[i] == ']') { i++; return list; }
                list.Add(ParseValue(s, ref i));
                SkipWs(s, ref i);
                if (i < s.Length && s[i] == ',') i++;
            }
            return list;
        }

        private static string ParseString(string s, ref int i)
        {
            if (i >= s.Length || s[i] != '"') return null;
            i++;
            var sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c == '\\' && i < s.Length)
                {
                    char e = s[i++];
                    if (e == 'n') sb.Append('\n');
                    else if (e == 'r') sb.Append('\r');
                    else if (e == 't') sb.Append('\t');
                    else if (e == 'b') sb.Append('\b');
                    else if (e == 'f') sb.Append('\f');
                    else if (e == 'u' && i + 4 <= s.Length)
                    {
                        ushort u;
                        if (ushort.TryParse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out u))
                            sb.Append((char)u);
                        i += 4;
                    }
                    else sb.Append(e);
                }
                else sb.Append(c);
            }
            return sb.ToString();
        }

        private static object ParseNumber(string s, ref int i)
        {
            int start = i;
            bool isFloat = false;
            while (i < s.Length)
            {
                char c = s[i];
                if ((c >= '0' && c <= '9') || c == '-' || c == '+') { i++; }
                else if (c == '.' || c == 'e' || c == 'E') { isFloat = true; i++; }
                else break;
            }
            string raw = s.Substring(start, i - start);
            if (!isFloat)
            {
                long l;
                if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out l)) return l;
            }
            double d;
            if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return d;
            return 0L;
        }

        public static string Serialize(object obj)
        {
            var sb = new StringBuilder();
            WriteJson(obj, sb);
            return sb.ToString();
        }

        private static void WriteJson(object obj, StringBuilder sb)
        {
            if (obj == null) { sb.Append("null"); return; }
            if (obj is bool) { sb.Append(((bool)obj) ? "true" : "false"); return; }
            if (obj is string) { WriteEscapedStr((string)obj, sb); return; }
            if (obj is int || obj is long || obj is short || obj is byte)
            { sb.Append(Convert.ToInt64(obj, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture)); return; }
            if (obj is double || obj is float || obj is decimal)
            { sb.Append(Convert.ToDouble(obj, CultureInfo.InvariantCulture).ToString("0.###", CultureInfo.InvariantCulture)); return; }

            var dict = obj as IDictionary<string, object>;
            if (dict != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (var kv in dict)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteEscapedStr(kv.Key, sb);
                    sb.Append(':');
                    WriteJson(kv.Value, sb);
                }
                sb.Append('}');
                return;
            }

            var seq = obj as System.Collections.IEnumerable;
            if (seq != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (var item in seq)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteJson(item, sb);
                }
                sb.Append(']');
                return;
            }

            WriteEscapedStr(obj.ToString(), sb);
        }

        private static void WriteEscapedStr(string s, StringBuilder sb)
        {
            sb.Append('"');
            if (!string.IsNullOrEmpty(s))
            {
                foreach (char c in s)
                {
                    if (c == '"') sb.Append("\\\"");
                    else if (c == '\\') sb.Append("\\\\");
                    else if (c == '\r') sb.Append("\\r");
                    else if (c == '\n') sb.Append("\\n");
                    else if (c == '\t') sb.Append("\\t");
                    else if (c < 32) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                }
            }
            sb.Append('"');
        }
    }
}
