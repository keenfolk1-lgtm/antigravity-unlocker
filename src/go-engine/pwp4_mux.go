package main

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	FrameRekey byte = 0x0A
	FramePad   byte = 0x0B

	pwp4HeaderSize          = 7
	pwp4MaxPayload          = MaxMuxChunkSize
	pwp4MinEncLen           = pwp4HeaderSize + chacha20poly1305.Overhead
	pwp4MaxEncLen           = pwp4HeaderSize + pwp4MaxPayload + chacha20poly1305.Overhead
	pwp4InitialInfo         = "pixelcore-pwp4-v1"
	pwp4RekeyInfo           = "pixelcore-pwp4-rekey"
	pwp4RekeySaltLen        = 32
	PWP4RekeyFrameThreshold = uint64(1 << 28)
	PWP4RekeyByteThreshold  = uint64(4 * 1024 * 1024 * 1024)
)

var (
	ErrPWP4FrameTooLarge    = errors.New("pwp4 frame payload exceeds 32768 bytes")
	ErrPWP4InvalidFrameLen  = errors.New("pwp4 encrypted frame length out of bounds")
	ErrPWP4AuthFailed       = errors.New("pwp4 aead authentication failed")
	ErrPWP4InvalidRekeySalt = errors.New("pwp4 rekey salt must be 32 bytes")
)

// PWP4Cipher implements ChaCha20-Poly1305 AEAD + 2B length mask with AEAD AD binding.
type PWP4Cipher struct {
	key             [32]byte
	maskKey         [16]byte
	aead            cipher.AEAD
	epoch           uint32
	seq             uint64
	bytesInEpoch    uint64
	rekeyFrameLimit uint64
	rekeyByteLimit  uint64
}

func newPWP4Cipher(keySlice, maskSlice []byte) (*PWP4Cipher, error) {
	if len(keySlice) != 32 || len(maskSlice) != 16 {
		return nil, errors.New("pwp4 invalid key material sizes")
	}
	aead, err := chacha20poly1305.New(keySlice)
	if err != nil {
		return nil, err
	}
	c := &PWP4Cipher{
		aead:            aead,
		rekeyFrameLimit: PWP4RekeyFrameThreshold,
		rekeyByteLimit:  PWP4RekeyByteThreshold,
	}
	copy(c.key[:], keySlice)
	copy(c.maskKey[:], maskSlice)
	return c, nil
}

// DerivePWP4KeyMaterial derives 96 bytes matching PixelCore_v3_Server aead.go 100%.
func DerivePWP4KeyMaterial(matchedSecret, clientNonceHex32, serverSaltHex32 string) ([96]byte, error) {
	var keyMat [96]byte
	salt := []byte(clientNonceHex32 + ":" + serverSaltHex32)
	r := hkdf.New(sha256.New, []byte(matchedSecret), salt, []byte(pwp4InitialInfo))
	if _, err := io.ReadFull(r, keyMat[:]); err != nil {
		return keyMat, err
	}
	return keyMat, nil
}

// NewPWP4ClientCiphers constructs client-side (rx=s2c, tx=c2s) AEAD ciphers.
func NewPWP4ClientCiphers(matchedSecret, clientNonceHex32, serverSaltHex32 string) (rx *PWP4Cipher, tx *PWP4Cipher, err error) {
	mat, err := DerivePWP4KeyMaterial(matchedSecret, clientNonceHex32, serverSaltHex32)
	if err != nil {
		return nil, nil, err
	}
	tx, err = newPWP4Cipher(mat[0:32], mat[64:80])
	if err != nil {
		return nil, nil, err
	}
	rx, err = newPWP4Cipher(mat[32:64], mat[80:96])
	if err != nil {
		return nil, nil, err
	}
	return rx, tx, nil
}

func (c *PWP4Cipher) Epoch() uint32        { return c.epoch }
func (c *PWP4Cipher) Seq() uint64          { return c.seq }
func (c *PWP4Cipher) BytesInEpoch() uint64 { return c.bytesInEpoch }

// SetRekeyLimits overrides frame/byte thresholds (used in unit tests).
func (c *PWP4Cipher) SetRekeyLimits(maxFrames, maxBytes uint64) {
	if maxFrames > 0 {
		c.rekeyFrameLimit = maxFrames
	}
	if maxBytes > 0 {
		c.rekeyByteLimit = maxBytes
	}
}

func (c *PWP4Cipher) NeedsRekey() bool {
	if c.seq >= ^uint64(0)-16 {
		return true
	}
	if c.rekeyFrameLimit > 0 && c.seq >= c.rekeyFrameLimit {
		return true
	}
	if c.rekeyByteLimit > 0 && c.bytesInEpoch >= c.rekeyByteLimit {
		return true
	}
	return false
}

func (c *PWP4Cipher) currentNonceAndMask() (nonce [12]byte, mask uint16) {
	binary.BigEndian.PutUint32(nonce[0:4], c.epoch)
	binary.BigEndian.PutUint64(nonce[4:12], c.seq)
	var maskInput [28]byte
	copy(maskInput[0:16], c.maskKey[:])
	copy(maskInput[16:28], nonce[:])
	h := sha256.Sum256(maskInput[:])
	return nonce, binary.BigEndian.Uint16(h[0:2])
}

// Rekey rotates curKey and maskKey using 32B random salt, increments epoch, resets seq=0.
func (c *PWP4Cipher) Rekey(newSalt []byte) error {
	if len(newSalt) != pwp4RekeySaltLen {
		return ErrPWP4InvalidRekeySalt
	}
	if c.epoch == ^uint32(0) {
		return errors.New("pwp4 epoch exhausted")
	}
	r := hkdf.New(sha256.New, c.key[:], newSalt, []byte(pwp4RekeyInfo))
	var nextMat [48]byte
	if _, err := io.ReadFull(r, nextMat[:]); err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(nextMat[0:32])
	if err != nil {
		return err
	}
	copy(c.key[:], nextMat[0:32])
	copy(c.maskKey[:], nextMat[32:48])
	c.aead = aead
	c.epoch++
	c.seq = 0
	c.bytesInEpoch = 0
	return nil
}

// SealFrame encrypts one PWP-4 wire frame using wireLenBytes[0:2] as ChaCha20-Poly1305 AD.
func (c *PWP4Cipher) SealFrame(frameType byte, streamID uint32, payload []byte) ([]byte, error) {
	if len(payload) > pwp4MaxPayload {
		return nil, ErrPWP4FrameTooLarge
	}
	if c.seq == ^uint64(0) {
		return nil, errors.New("pwp4 nonce sequence exhausted")
	}
	inner := make([]byte, pwp4HeaderSize+len(payload))
	inner[0] = frameType
	binary.BigEndian.PutUint32(inner[1:5], streamID)
	binary.BigEndian.PutUint16(inner[5:7], uint16(len(payload)))
	if len(payload) > 0 {
		copy(inner[pwp4HeaderSize:], payload)
	}
	encLen := uint16(len(inner) + chacha20poly1305.Overhead)
	nonce, mask := c.currentNonceAndMask()
	wireLen := encLen ^ mask

	out := make([]byte, 2+int(encLen))
	binary.BigEndian.PutUint16(out[0:2], wireLen)
	c.aead.Seal(out[2:2], nonce[:], inner, out[0:2])
	c.seq++
	c.bytesInEpoch += uint64(len(payload))
	return out, nil
}

// OpenFrame reads, unmasks, authenticates, and decrypts one PWP-4 wire frame.
func (c *PWP4Cipher) OpenFrame(r io.Reader, scratch []byte) (byte, uint32, []byte, []byte, error) {
	if c.seq == ^uint64(0) {
		return 0, 0, nil, scratch, errors.New("pwp4 nonce sequence exhausted")
	}
	var wireLenBytes [2]byte
	if _, err := io.ReadFull(r, wireLenBytes[:]); err != nil {
		return 0, 0, nil, scratch, err
	}
	nonce, mask := c.currentNonceAndMask()
	encLen := int(binary.BigEndian.Uint16(wireLenBytes[:]) ^ mask)
	if encLen < pwp4MinEncLen || encLen > pwp4MaxEncLen {
		return 0, 0, nil, scratch, ErrPWP4InvalidFrameLen
	}
	if cap(scratch) < encLen {
		scratch = make([]byte, encLen)
	}
	ctBuf := scratch[:encLen]
	if _, err := io.ReadFull(r, ctBuf); err != nil {
		return 0, 0, nil, scratch, err
	}
	plain, err := c.aead.Open(ctBuf[:0], nonce[:], ctBuf, wireLenBytes[:])
	if err != nil {
		return 0, 0, nil, scratch, ErrPWP4AuthFailed
	}
	if len(plain) < pwp4HeaderSize {
		return 0, 0, nil, scratch, ErrPWP4AuthFailed
	}
	fType := plain[0]
	streamID := binary.BigEndian.Uint32(plain[1:5])
	pLen := int(binary.BigEndian.Uint16(plain[5:7]))
	if pLen != len(plain)-pwp4HeaderSize || pLen > pwp4MaxPayload {
		return 0, 0, nil, scratch, ErrPWP4AuthFailed
	}
	c.seq++
	c.bytesInEpoch += uint64(pLen)
	return fType, streamID, plain[pwp4HeaderSize : pwp4HeaderSize+pLen], scratch, nil
}

type pwp4ClientCodec struct {
	rx        *PWP4Cipher
	tx        *PWP4Cipher
	rxScratch []byte
}

func (c *pwp4ClientCodec) ProtocolName() string { return "PWP-4" }

func (c *pwp4ClientCodec) WriteFrame(w io.Writer, frameType byte, streamID uint32, _ byte, payload []byte, randomPadMax int) error {
	if c.tx.NeedsRekey() && frameType != FrameRekey {
		var salt [pwp4RekeySaltLen]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return err
		}
		rekeyWire, err := c.tx.SealFrame(FrameRekey, 0, salt[:])
		if err != nil {
			return err
		}
		if err := writeFull(w, rekeyWire); err != nil {
			return err
		}
		if err := c.tx.Rekey(salt[:]); err != nil {
			return err
		}
	}

	wire, err := c.tx.SealFrame(frameType, streamID, payload)
	if err != nil {
		return err
	}
	if err := writeFull(w, wire); err != nil {
		return err
	}

	if randomPadMax > 0 && frameType != FrameRekey && frameType != FramePad {
		nBig, rErr := rand.Int(rand.Reader, big.NewInt(int64(randomPadMax+1)))
		if rErr == nil && nBig.Int64() > 0 {
			padBytes := make([]byte, int(nBig.Int64()))
			_, _ = rand.Read(padBytes)
			padWire, perr := c.tx.SealFrame(FramePad, 0, padBytes)
			if perr != nil {
				return perr
			}
			if werr := writeFull(w, padWire); werr != nil {
				return werr
			}
		}
	}
	return nil
}

func (c *pwp4ClientCodec) ReadFrame(r io.Reader) (byte, uint32, []byte, error) {
	fType, sid, payload, updated, err := c.rx.OpenFrame(r, c.rxScratch)
	c.rxScratch = updated
	if err != nil {
		return 0, 0, nil, err
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	return fType, sid, cp, nil
}

// DialPWP4Mux performs POST <pwp4_path> with random 64..512B pad and Chrome-like cookies,
// returning ErrPWP4Unsupported if the remote server looks like a v1.9.0 node (no __cfruid=...m4).
func DialPWP4Mux(
	dialRes *UTLSDialResult,
	node NodeConfig,
	clientUUID, hwid string,
	clockOffset *atomic.Int64,
) (*ClientMuxSession, error) {
	if node.Secret == "" {
		return nil, fmt.Errorf("missing manifest secret for node %s", node.Name)
	}
	conn := dialRes.Conn
	sniHost := node.SNI
	if sniHost == "" {
		sniHost = DefaultSNI
	}

	offset := int64(0)
	if clockOffset != nil {
		offset = clockOffset.Load()
	}
	tsStr := strconv.FormatInt(time.Now().Unix()+offset, 10)

	var nonceRaw [16]byte
	_, _ = rand.Read(nonceRaw[:])
	clientNonceHex32 := hex.EncodeToString(nonceRaw[:])

	padLenBig, _ := rand.Int(rand.Reader, big.NewInt(449))
	padLen := 64 + int(padLenBig.Int64())
	padBody := make([]byte, padLen)
	_, _ = rand.Read(padBody)

	hmacMsg := fmt.Sprintf("pwp4:%s:%s:%s:%s:%d", tsStr, clientNonceHex32, clientUUID, hwid, padLen)
	mac := hmac.New(sha256.New, []byte(node.Secret))
	_, _ = mac.Write([]byte(hmacMsg))
	hmacHex32 := hex.EncodeToString(mac.Sum(nil)[:16])

	pwp4Path := node.EffectivePWP4Path()
	hdrsStr := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Content-Length: 107374182400\r\n"+
			"X-Pad-Len: %d\r\n"+
			"Accept: */*\r\n"+
			"Cookie: _cfuvid=%s.%s.%s; _px4=%s.%s\r\n"+
			"Connection: keep-alive\r\n\r\n",
		pwp4Path, sniHost, padLen, tsStr, hwid, clientUUID, clientNonceHex32, hmacHex32,
	)

	pkt := make([]byte, len(hdrsStr)+len(padBody))
	copy(pkt, hdrsStr)
	copy(pkt[len(hdrsStr):], padBody)

	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := writeFull(conn, pkt); err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(conn, 64*1024)
	statusLine, hdrs, err := readHTTPResponseHeaders(br)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("pwp4 read response: %w", err)
	}

	resynced := syncClockFromHTTPDate(hdrs.Get("Date"), offset, clockOffset)

	if strings.Contains(statusLine, " 403 ") {
		edgeStatus := strings.TrimSpace(hdrs.Get("X-Edge-Status"))
		if resynced && (edgeStatus == "" || strings.Contains(strings.ToUpper(edgeStatus), "TIME") || strings.Contains(strings.ToUpper(edgeStatus), "SIG")) {
			return nil, ErrClockResynced
		}
		return nil, fmt.Errorf("%w: %s", ErrLicenseRejected, edgeStatus)
	}

	// v1.9.0 nodes return 404/405 or 200 text/html decoy without __cfruid=<32hex>.m4
	if strings.Contains(statusLine, " 404 ") || strings.Contains(statusLine, " 405 ") || strings.Contains(statusLine, " 501 ") {
		return nil, ErrPWP4Unsupported
	}
	if !strings.Contains(statusLine, " 200 ") {
		if resynced {
			return nil, ErrClockResynced
		}
		return nil, fmt.Errorf("%w (%s)", ErrPWP4Unsupported, statusLine)
	}

	serverSaltHex32 := extractPWP4Salt(hdrs.Values("Set-Cookie"))
	if serverSaltHex32 == "" {
		// e.g. v1.9.0 returned 200 OK text/html decoy or mismatched secret HMAC decoy
		if resynced {
			return nil, ErrClockResynced
		}
		return nil, ErrPWP4Unsupported
	}

	srvPadLen := 0
	if srvPadStr := strings.TrimSpace(hdrs.Get("X-Pad-Len")); srvPadStr != "" {
		parsedPad, pErr := strconv.Atoi(srvPadStr)
		if pErr != nil || parsedPad < 0 || parsedPad > 4096 {
			return nil, errors.New("pwp4 unreasonable server pad length")
		}
		srvPadLen = parsedPad
	}
	if clStr := strings.TrimSpace(hdrs.Get("Content-Length")); clStr != "" {
		respCL, clErr := strconv.ParseInt(clStr, 10, 64)
		if clErr != nil || respCL <= 0 || respCL < int64(srvPadLen) {
			return nil, errors.New("pwp4 invalid response content-length")
		}
	}
	if srvPadLen > 0 {
		srvPad := make([]byte, srvPadLen)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, rErr := io.ReadFull(br, srvPad)
		_ = conn.SetReadDeadline(time.Time{})
		if rErr != nil {
			return nil, rErr
		}
	}

	rx, tx, err := NewPWP4ClientCiphers(node.Secret, clientNonceHex32, serverSaltHex32)
	if err != nil {
		return nil, err
	}

	meta := parseEdgeTelemetryHeader(hdrs.Get("X-Edge-Telemetry"))
	meta.Proto = "PWP-4"
	codec := &pwp4ClientCodec{rx: rx, tx: tx}
	return NewClientMuxSession(conn, br, codec, node, meta), nil
}

func extractPWP4Salt(setCookies []string) string {
	for _, sc := range setCookies {
		for _, part := range strings.Split(sc, ";") {
			p := strings.TrimSpace(part)
			if !strings.HasPrefix(p, "__cfruid=") {
				continue
			}
			val := strings.TrimPrefix(p, "__cfruid=")
			if strings.HasSuffix(val, ".m4") && len(val) == 35 {
				salt := strings.TrimSuffix(val, ".m4")
				if _, err := hex.DecodeString(salt); err == nil {
					return strings.ToLower(salt)
				}
			}
		}
	}
	return ""
}

// MuxManager manages role-based active mux sessions (ai / media), pre-warmed standby,
// zero-drop hot failover (<150ms), v1.9 PWP-3 seamless fallback, and Instant Wake recovery.
type MuxManager struct {
	mu           sync.Mutex
	cfg          *EngineConfig
	resolver     *DohResolver
	autoTuner    *DPIAutoTuner
	rootCAs      *x509.CertPool
	insecureTest bool
	clockOffset  atomic.Int64
	netFP        atomic.Value

	sessions    map[string]*ClientMuxSession // role -> primary active session
	standby     *ClientMuxSession            // pre-warmed backup session
	standbyNode NodeConfig

	selector        *SmartNodeSelector
	mediaPool       *MediaSessionPool
	mediaScaleMu    sync.Mutex
	dialControlProv func() func(network, address string, c syscall.RawConn) error

	nodeStatuses map[string]NodeProbeStatus
	activeProto  string
	utlsProfile  string

	failoverCount    atomic.Int64
	instantWakeCount atomic.Int64
	lastPingSess     *ClientMuxSession
	lastPingMs       int64
	lastWakeReason   string
	lastWakeUnix     int64
	lastLicenseErr   string
	lastConnectErr   string
	connectGen       atomic.Uint64

	// Optional hook to customize dialing in unit tests without live network.
	dialNodeOverride func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error)

	wakeMu           sync.Mutex
	lastWakeAt       time.Time
	aiMigrateRunning atomic.Bool
	stopCtx          context.Context
	stopCancel       context.CancelFunc
	stopCh           chan struct{}
	stopOnce         sync.Once
	onWakeCb         func(reason string, failoverMs int64)
}

// NodeProbeStatus reports cached status for /__pixelcore/telemetry and X-Ray.
type NodeProbeStatus struct {
	Name      string   `json:"name"`
	Region    string   `json:"region"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Mux       bool     `json:"mux"`
	Online    bool     `json:"online"`
	LatencyMs int64    `json:"latency_ms"`
	Roles     []string `json:"roles,omitempty"`
	PWP4Ready bool     `json:"pwp4_ready"`
}

// NewMuxManager creates a MuxManager and starts background Instant Wake + standby pre-warming if enabled.
func NewMuxManager(cfg *EngineConfig, resolver *DohResolver) *MuxManager {
	sel := NewSmartNodeSelector()
	stopCtx, stopCancel := context.WithCancel(context.Background())
	m := &MuxManager{
		cfg:          cfg,
		resolver:     resolver,
		autoTuner:    NewDPIAutoTuner(""),
		sessions:     make(map[string]*ClientMuxSession),
		nodeStatuses: make(map[string]NodeProbeStatus),
		selector:     sel,
		mediaPool:    NewMediaSessionPool(),
		activeProto:  "PWP-4",
		utlsProfile:  "HelloChrome_Auto",
		stopCtx:      stopCtx,
		stopCancel:   stopCancel,
		stopCh:       make(chan struct{}),
	}
	sel.SetTransportDeps(resolver, nil, false, &m.clockOffset)
	m.netFP.Store(computeLocalInterfaceFingerprint())
	if cfg != nil && strings.EqualFold(cfg.V2.UTLSProfile, "firefox") {
		m.utlsProfile = "HelloFirefox_Auto"
	}
	return m
}

// SetDialControlProvider registers a dynamic callback returning a socket Control hook while TUN is active.
func (m *MuxManager) SetDialControlProvider(fn func() func(network, address string, c syscall.RawConn) error) {
	m.mu.Lock()
	m.dialControlProv = fn
	m.mu.Unlock()
}

func (m *MuxManager) getDialControl() func(network, address string, c syscall.RawConn) error {
	m.mu.Lock()
	prov := m.dialControlProv
	m.mu.Unlock()
	if prov != nil {
		return prov()
	}
	return nil
}

// SetAutoTuner sets a custom DPIAutoTuner (useful in isolated tests).
func (m *MuxManager) SetAutoTuner(t *DPIAutoTuner) {
	m.mu.Lock()
	m.autoTuner = t
	m.mu.Unlock()
}

func (m *MuxManager) getAutoTuner() *DPIAutoTuner {
	m.mu.Lock()
	t := m.autoTuner
	m.mu.Unlock()
	return t
}

func (m *MuxManager) currentNetFingerprint() string {
	if v, ok := m.netFP.Load().(string); ok && v != "" {
		return v
	}
	fp := computeLocalInterfaceFingerprint()
	if fp != "" {
		m.netFP.Store(fp)
	}
	return fp
}

// StartMonitors launches clock-jump + interface-change Instant Wake detector and standby warm loop.
func (m *MuxManager) StartMonitors(onWake func(reason string, failoverMs int64)) {
	m.mu.Lock()
	m.onWakeCb = onWake
	m.mu.Unlock()
	go m.instantWakeWatchLoop()
	go m.standbyMaintenanceLoop()
}

// Close shuts down background monitors, active sessions, and standby session.
func (m *MuxManager) Close() {
	m.stopOnce.Do(func() {
		if m.stopCancel != nil {
			m.stopCancel()
		}
		close(m.stopCh)
	})
	m.mu.Lock()
	for r, s := range m.sessions {
		if s != nil {
			_ = s.Close()
		}
		delete(m.sessions, r)
	}
	if m.standby != nil {
		_ = m.standby.Close()
		m.standby = nil
	}
	m.lastPingSess = nil
	m.lastPingMs = 0
	m.mu.Unlock()
	if m.mediaPool != nil {
		m.mediaPool.CloseAll()
	}
}

// UpdateConfig replaces the active config safely (e.g., after manifest refresh or activation).
func (m *MuxManager) UpdateConfig(cfg *EngineConfig) {
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

// WarmConnect initializes the primary session and pre-warms standby.
func (m *MuxManager) WarmConnect(ctx context.Context) error {
	_, err := m.getOrConnectRole(ctx, "ai")
	if err == nil && !m.isStopped() {
		go m.ensureStandby(context.Background())
	}
	return err
}

// OpenStream opens a proxied TCP stream using role routing ("ai" / "media") with
// automatic zero-drop hot failover (<150ms on SynAck/Ping stall) to pre-warmed standby.
func (m *MuxManager) OpenStream(ctx context.Context, role, targetHost string, targetPort int) (*ClientMuxStream, string, error) {
	if role == "" {
		role = "ai"
	}
	var sess *ClientMuxSession
	var err error
	if strings.EqualFold(role, "media") {
		sess, err = m.getOrConnectMediaSession(ctx)
	} else {
		sess, err = m.getOrConnectRole(ctx, role)
	}
	if err != nil {
		if sb := m.promoteStandby(role); sb != nil {
			m.failoverCount.Add(1)
			if strings.EqualFold(role, "media") && m.mediaPool != nil {
				m.mediaPool.Add(sb)
			}
			if st, serr := sb.OpenTCPStream(targetHost, targetPort, 3*time.Second); serr == nil {
				if !m.isStopped() {
					go m.ensureStandby(context.Background())
				}
				return st, sb.Node().Name, nil
			}
		}
		return nil, "", err
	}

	cfgMs := m.failoverTimeoutMs()
	if cfgMs <= 0 {
		cfgMs = 1200
	}
	synProbeWait := time.Duration(cfgMs/2) * time.Millisecond
	if synProbeWait < 30*time.Millisecond {
		synProbeWait = 30 * time.Millisecond
	}
	pingTimeout := synProbeWait
	if m.selector != nil {
		if rttMs := m.selector.NodeEWMA(sess.Node()); rttMs > 0 {
			minSyn := time.Duration(3*rttMs+250) * time.Millisecond
			if synProbeWait < minSyn {
				synProbeWait = minSyn
			}
			minPing := time.Duration(3*rttMs+300) * time.Millisecond
			if pingTimeout < minPing {
				pingTimeout = minPing
			}
		}
	}

	type openRes struct {
		st  *ClientMuxStream
		err error
	}
	resCh := make(chan openRes, 1)
	var resMu sync.Mutex
	var abandoned bool
	abandonOpen := func() {
		resMu.Lock()
		abandoned = true
		resMu.Unlock()
		select {
		case r := <-resCh:
			if r.st != nil {
				_ = r.st.Close()
			}
		default:
		}
	}
	go func() {
		st, oerr := sess.OpenTCPStream(targetHost, targetPort, 8*time.Second)
		resMu.Lock()
		wasAbandoned := abandoned
		resMu.Unlock()
		if wasAbandoned {
			if st != nil {
				_ = st.Close()
			}
			return
		}
		resCh <- openRes{st: st, err: oerr}
	}()

	var st *ClientMuxStream
	var serr error
	muxStalled := false
	timer := time.NewTimer(synProbeWait)
	select {
	case r := <-resCh:
		timer.Stop()
		st, serr = r.st, r.err
	case <-ctx.Done():
		timer.Stop()
		abandonOpen()
		return nil, "", ctx.Err()
	case <-m.stopCh:
		timer.Stop()
		abandonOpen()
		return nil, "", errors.New("mux manager closed")
	case <-timer.C:
		// If SynAck did not arrive in time, standby is ready, and no recent mux RX occurred, probe link with Ping.
		if m.hasStandby() && sess.TimeSinceLastRx() >= synProbeWait/2 {
			pingCh := make(chan error, 1)
			go func() {
				rtt, perr := sess.Ping(pingTimeout)
				if perr == nil {
					m.recordPrimaryPing(sess, rtt.Milliseconds())
				}
				pingCh <- perr
			}()
			select {
			case r := <-resCh:
				st, serr = r.st, r.err
			case <-ctx.Done():
				abandonOpen()
				return nil, "", ctx.Err()
			case <-m.stopCh:
				abandonOpen()
				return nil, "", errors.New("mux manager closed")
			case perr := <-pingCh:
				if perr != nil {
					muxStalled = true
					serr = fmt.Errorf("primary mux stalled (SynAck+Ping): %w", perr)
				} else {
					select {
					case r := <-resCh:
						st, serr = r.st, r.err
					case <-ctx.Done():
						abandonOpen()
						return nil, "", ctx.Err()
					case <-m.stopCh:
						abandonOpen()
						return nil, "", errors.New("mux manager closed")
					}
				}
			}
		} else {
			select {
			case r := <-resCh:
				st, serr = r.st, r.err
			case <-ctx.Done():
				abandonOpen()
				return nil, "", ctx.Err()
			case <-m.stopCh:
				abandonOpen()
				return nil, "", errors.New("mux manager closed")
			}
		}
	}

	if serr == nil && st != nil {
		return st, sess.Node().Name, nil
	}

	// Per-stream reset on a live mux session (e.g. target port closed or policy block) must NOT close the mux session.
	if !muxStalled && !sess.IsClosed() && errors.Is(serr, ErrMuxStreamReset) {
		return nil, sess.Node().Name, serr
	}

	// If session died / SynAck+Ping stalled, promote pre-warmed standby immediately
	_ = sess.Close()
	if strings.EqualFold(role, "media") && m.mediaPool != nil {
		m.mediaPool.PruneClosed()
	}
	m.clearRoleSession(role, sess)
	if sb := m.promoteStandby(role); sb != nil {
		m.failoverCount.Add(1)
		if strings.EqualFold(role, "media") && m.mediaPool != nil {
			m.mediaPool.Add(sb)
		}
		st2, serr2 := sb.OpenTCPStream(targetHost, targetPort, 8*time.Second)
		if serr2 == nil {
			go m.ensureStandby(context.Background())
			return st2, sb.Node().Name, nil
		}
	}

	// Re-dial primary pool as final fallback
	var sess2 *ClientMuxSession
	var derr error
	if strings.EqualFold(role, "media") {
		sess2, derr = m.getOrConnectMediaSession(ctx)
	} else {
		sess2, derr = m.getOrConnectRole(ctx, role)
	}
	if derr != nil {
		return nil, "", derr
	}
	m.failoverCount.Add(1)
	st3, serr3 := sess2.OpenTCPStream(targetHost, targetPort, 8*time.Second)
	if serr3 != nil {
		return nil, "", serr3
	}
	return st3, sess2.Node().Name, nil
}

func (m *MuxManager) hasStandby() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.standby != nil && !m.standby.IsClosed()
}

// ActiveSession returns the live primary session for role if any.
func (m *MuxManager) ActiveSession(role string) *ClientMuxSession {
	if role == "" {
		role = "ai"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[role]
	if s != nil && !s.IsClosed() {
		return s
	}
	return m.sessions["ai"]
}

// GetOrConnectSession returns a live session for role, dialing if necessary.
func (m *MuxManager) GetOrConnectSession(ctx context.Context, role string) (*ClientMuxSession, error) {
	if role == "" {
		role = "ai"
	}
	if strings.EqualFold(role, "media") {
		return m.getOrConnectMediaSession(ctx)
	}
	return m.getOrConnectRole(ctx, role)
}

func (m *MuxManager) getOrConnectMediaSession(ctx context.Context) (*ClientMuxSession, error) {
	if m.isStopped() {
		return nil, errors.New("mux manager closed")
	}
	if m.mediaPool == nil {
		return m.getOrConnectRole(ctx, "media")
	}
	best, shouldScale := m.mediaPool.PickBest()
	if best != nil && !shouldScale {
		return best, nil
	}
	if best == nil {
		sess, err := m.getOrConnectRole(ctx, "media")
		if err != nil {
			return nil, err
		}
		m.mediaPool.Add(sess)
		return sess, nil
	}
	if !m.mediaScaleMu.TryLock() {
		return best, nil
	}
	defer m.mediaScaleMu.Unlock()

	best2, shouldScale2 := m.mediaPool.PickBest()
	if best2 != nil && !shouldScale2 {
		return best2, nil
	}
	if best2 == nil {
		sess, err := m.getOrConnectRole(ctx, "media")
		if err != nil {
			return nil, err
		}
		m.mediaPool.Add(sess)
		return sess, nil
	}

	newSess, err := m.dialFreshMediaSession(ctx)
	if err != nil || newSess == nil {
		if !best2.IsClosed() {
			return best2, nil
		}
		return nil, err
	}
	m.mediaPool.Add(newSess)
	return newSess, nil
}

func (m *MuxManager) dialFreshMediaSession(ctx context.Context) (*ClientMuxSession, error) {
	m.mu.Lock()
	gen := m.connectGen.Load()
	candidates := m.selectCandidateNodesLocked("media")
	m.mu.Unlock()
	if len(candidates) == 0 {
		return nil, errors.New("no upstream nodes configured")
	}

	var lastErr error
	for _, node := range candidates {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if m.isStopped() {
			return nil, errors.New("mux manager closed")
		}
		if m.connectGen.Load() != gen {
			return nil, errors.New("mux connect superseded by wake")
		}
		t0 := time.Now()
		sess, utlsProf, err := m.dialSessionWithFallback(ctx, node)
		lat := time.Since(t0).Milliseconds()
		m.recordNodeProbe(node, err == nil, lat, sess)
		if err != nil {
			lastErr = err
			continue
		}
		if m.isStopped() || m.connectGen.Load() != gen {
			_ = sess.Close()
			return nil, errors.New("mux connect superseded by wake")
		}
		m.mu.Lock()
		if m.isStopped() || m.connectGen.Load() != gen {
			m.mu.Unlock()
			_ = sess.Close()
			return nil, errors.New("mux connect superseded by wake")
		}
		if m.sessions["media"] == nil || m.sessions["media"].IsClosed() {
			m.sessions["media"] = sess
		}
		if utlsProf != "" {
			m.utlsProfile = utlsProf
		}
		m.mu.Unlock()
		return sess, nil
	}
	if lastErr == nil {
		lastErr = errors.New("all media candidates failed")
	}
	return nil, lastErr
}

func (m *MuxManager) hasLiveAISession() bool {
	m.mu.Lock()
	s := m.sessions["ai"]
	m.mu.Unlock()
	return s != nil && !s.IsClosed()
}

// TriggerInstantWake closes stale sessions immediately, resets cached state, promotes/re-dials
// fresh tunnel + standby so resume from sleep has zero hung sockets.
// Serialized with wakeMu and deduplicated within a 2s window for simultaneous OS resume + clock jump signals.
func (m *MuxManager) TriggerInstantWake(reason string) (failoverMs int64, err error) {
	m.wakeMu.Lock()
	defer m.wakeMu.Unlock()

	if m.isStopped() {
		return 0, errors.New("mux manager closed")
	}
	if reason != "key_activated" && !m.lastWakeAt.IsZero() && time.Since(m.lastWakeAt) < 2*time.Second && m.hasLiveAISession() {
		return 0, nil
	}

	start := time.Now()
	m.connectGen.Add(1)
	m.instantWakeCount.Add(1)

	m.mu.Lock()
	m.lastWakeReason = reason
	m.lastWakeUnix = time.Now().Unix()
	m.lastPingSess = nil
	m.lastPingMs = 0
	var toClose []*ClientMuxSession
	for k, s := range m.sessions {
		if s != nil {
			toClose = append(toClose, s)
		}
		delete(m.sessions, k)
	}
	if m.standby != nil {
		toClose = append(toClose, m.standby)
		m.standby = nil
	}
	cb := m.onWakeCb
	m.mu.Unlock()

	for _, s := range toClose {
		_ = s.Close()
	}
	if m.mediaPool != nil {
		m.mediaPool.CloseAll()
	}

	baseCtx := m.stopCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	wctx, cancel := context.WithTimeout(baseCtx, 6*time.Second)
	defer cancel()
	_, err = m.getOrConnectRole(wctx, "ai")
	m.lastWakeAt = time.Now()
	failoverMs = time.Since(start).Milliseconds()
	if !m.isStopped() {
		go m.ensureStandby(baseCtx)
	}

	if cb != nil {
		cb(reason, failoverMs)
	}
	return failoverMs, err
}

func (m *MuxManager) failoverTimeoutMs() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg != nil && m.cfg.V2.FailoverTimeoutMs > 0 {
		return m.cfg.V2.FailoverTimeoutMs
	}
	return 1200
}

func (m *MuxManager) clearRoleSession(_ string, target *ClientMuxSession) {
	if target == nil {
		return
	}
	m.mu.Lock()
	for r, cur := range m.sessions {
		if cur == target {
			delete(m.sessions, r)
		}
	}
	if m.lastPingSess == target {
		m.lastPingSess = nil
		m.lastPingMs = 0
	}
	m.mu.Unlock()
}

func (m *MuxManager) recordPrimaryPing(sess *ClientMuxSession, rttMs int64) {
	if m == nil || sess == nil {
		return
	}
	if rttMs <= 0 {
		rttMs = 1
	}
	m.mu.Lock()
	if m.sessions["ai"] == sess {
		m.lastPingSess = sess
		m.lastPingMs = rttMs
	}
	m.mu.Unlock()
}

// SessionLatencyMs returns the latest measured ping RTT (or selector EWMA fallback) for sess.
func (m *MuxManager) SessionLatencyMs(sess *ClientMuxSession) int64 {
	if m == nil || sess == nil {
		return 0
	}
	m.mu.Lock()
	if m.lastPingSess == sess && m.lastPingMs > 0 {
		ms := m.lastPingMs
		m.mu.Unlock()
		return ms
	}
	sel := m.selector
	m.mu.Unlock()
	if sel != nil {
		return sel.NodeEWMA(sess.Node())
	}
	return 0
}

func (m *MuxManager) promoteStandbyLocked(role string) *ClientMuxSession {
	if m.standby != nil && !m.standby.IsClosed() {
		sb := m.standby
		m.standby = nil
		m.standbyNode = NodeConfig{}
		m.sessions[role] = sb
		if role != "ai" && (m.sessions["ai"] == nil || m.sessions["ai"].IsClosed()) {
			m.sessions["ai"] = sb
		}
		m.activeProto = sb.Protocol()
		return sb
	}
	return nil
}

func (m *MuxManager) promoteStandby(role string) *ClientMuxSession {
	m.mu.Lock()
	sb := m.promoteStandbyLocked(role)
	m.mu.Unlock()
	if sb != nil && m.selector != nil {
		m.selector.NotifyConnected(role, sb.Node())
	}
	return sb
}

func (m *MuxManager) hasRoleDedicatedCandidateLocked(role string) bool {
	if m.cfg == nil || role == "" || role == "ai" {
		return false
	}
	if m.cfg.ActiveNode.Host != "" && len(m.cfg.ActiveNode.Roles) > 0 && m.cfg.ActiveNode.HasRole(role) {
		return true
	}
	for _, n := range m.cfg.Nodes {
		if n.Host != "" && len(n.Roles) > 0 && n.HasRole(role) {
			return true
		}
	}
	return false
}

const happyEyeballsStagger = 650 * time.Millisecond

type pwpDialOutcome struct {
	idx      int
	node     NodeConfig
	sess     *ClientMuxSession
	utlsProf string
	err      error
	durMs    int64
}

func (m *MuxManager) isStopped() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

func isWSHost(node NodeConfig) bool {
	host := strings.ToLower(strings.TrimSpace(node.Host))
	sni := strings.ToLower(strings.TrimSpace(node.SNI))
	return strings.HasPrefix(host, "ws.") || strings.HasPrefix(sni, "ws.")
}

func findAlternateHostIndex(candidates []NodeConfig, primaryIdx int) int {
	primaryHost := strings.TrimSpace(candidates[primaryIdx].Host)
	for i := primaryIdx + 1; i < len(candidates); i++ {
		if !strings.EqualFold(strings.TrimSpace(candidates[i].Host), primaryHost) {
			return i
		}
	}
	if primaryIdx+1 < len(candidates) {
		return primaryIdx + 1
	}
	return -1
}

func extractLicenseErrorCode(err error) string {
	if err == nil || !errors.Is(err, ErrLicenseRejected) {
		return ""
	}
	up := strings.ToUpper(err.Error())
	switch {
	case strings.Contains(up, "DEVICE_LIMIT"):
		return "DEVICE_LIMIT"
	case strings.Contains(up, "KEY_EXPIRED"):
		return "KEY_EXPIRED"
	case strings.Contains(up, "RATE_LIMITED"):
		return "RATE_LIMITED"
	default:
		return "INVALID_KEY"
	}
}

func (m *MuxManager) recordDialFailure(err error) {
	if m == nil || err == nil {
		return
	}
	licCode := extractLicenseErrorCode(err)
	m.mu.Lock()
	m.lastConnectErr = err.Error()
	if licCode != "" {
		m.lastLicenseErr = licCode
	}
	m.mu.Unlock()
}

func (m *MuxManager) storeWinningSession(role string, gen uint64, sess *ClientMuxSession, utlsProf string) *ClientMuxSession {
	m.mu.Lock()
	if m.isStopped() {
		m.mu.Unlock()
		_ = sess.Close()
		return nil
	}
	// If Instant Wake bumped generation during dial, still keep an already healthy role session or replace cleanly
	if m.connectGen.Load() != gen && m.sessions[role] != nil && !m.sessions[role].IsClosed() {
		existing := m.sessions[role]
		m.lastLicenseErr = ""
		m.lastConnectErr = ""
		m.mu.Unlock()
		_ = sess.Close()
		return existing
	}
	m.sessions[role] = sess
	m.activeProto = sess.Protocol()
	if utlsProf != "" {
		m.utlsProfile = utlsProf
	}
	m.lastLicenseErr = ""
	m.lastConnectErr = ""
	m.mu.Unlock()
	if m.selector != nil {
		m.selector.NotifyConnected(role, sess.Node())
	}
	if strings.EqualFold(role, "media") && m.mediaPool != nil {
		m.mediaPool.Add(sess)
	}
	return sess
}

func (m *MuxManager) finishSecondRacer(resCh <-chan pwpDialOutcome, inflight int, gen uint64, finishWatcher func()) {
	defer finishWatcher()
	for i := 0; i < inflight; i++ {
		out := <-resCh
		m.recordNodeProbe(out.node, out.err == nil, out.durMs, out.sess)
		if out.err != nil || out.sess == nil {
			continue
		}
		stored := false
		m.mu.Lock()
		if !m.isStopped() && m.connectGen.Load() == gen && (m.standby == nil || m.standby.IsClosed()) {
			m.standby = out.sess
			m.standbyNode = out.node
			stored = true
		}
		m.mu.Unlock()
		if !stored {
			_ = out.sess.Close()
		}
	}
}

func (m *MuxManager) dialSequentialCandidates(ctx context.Context, role string, gen uint64, candidates []NodeConfig, tried []bool, lastErr error) (*ClientMuxSession, error) {
	if errors.Is(lastErr, ErrLicenseRejected) {
		m.recordDialFailure(lastErr)
		return nil, lastErr
	}
	for i, node := range candidates {
		if tried != nil && tried[i] {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if m.isStopped() {
			return nil, errors.New("mux manager closed")
		}
		t0 := time.Now()
		sess, utlsProf, err := m.dialSessionWithFallback(ctx, node)
		lat := time.Since(t0).Milliseconds()
		m.recordNodeProbe(node, err == nil, lat, sess)
		if err != nil {
			lastErr = err
			m.recordDialFailure(err)
			if errors.Is(err, ErrLicenseRejected) {
				return nil, err
			}
			continue
		}
		stored := m.storeWinningSession(role, gen, sess, utlsProf)
		if stored == nil {
			return nil, errors.New("mux manager closed")
		}
		return stored, nil
	}
	return nil, lastErr
}

func (m *MuxManager) getOrConnectRole(ctx context.Context, role string) (*ClientMuxSession, error) {
	if m.isStopped() {
		return nil, errors.New("mux manager closed")
	}

	m.mu.Lock()
	if cur := m.sessions[role]; cur != nil && !cur.IsClosed() {
		m.mu.Unlock()
		return cur, nil
	}
	// Share primary session if role is media and only general/ai session exists on single-node setup
	if role != "ai" {
		if aiSess := m.sessions["ai"]; aiSess != nil && !aiSess.IsClosed() && aiSess.Node().HasRole(role) {
			m.sessions[role] = aiSess
			m.mu.Unlock()
			return aiSess, nil
		}
	}
	// Promote pre-warmed standby immediately before cold-dialing if primary died or closed.
	if m.standby != nil && !m.standby.IsClosed() && (m.standby.Node().HasRole(role) || !m.hasRoleDedicatedCandidateLocked(role)) {
		if sb := m.promoteStandbyLocked(role); sb != nil {
			m.failoverCount.Add(1)
			m.mu.Unlock()
			if m.selector != nil {
				m.selector.NotifyConnected(role, sb.Node())
			}
			go m.ensureStandby(context.Background())
			return sb, nil
		}
	}
	candidates := m.selectCandidateNodesLocked(role)
	gen := m.connectGen.Load()
	m.mu.Unlock()

	if len(candidates) == 0 {
		return nil, errors.New("no upstream nodes configured")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(candidates) == 1 {
		return m.dialSequentialCandidates(ctx, role, gen, candidates, nil, nil)
	}

	idx1 := findAlternateHostIndex(candidates, 0)
	tried := make([]bool, len(candidates))

	// Decouple racer lifetime after a winner is returned so a slow secondary racer can still finish
	// and populate m.standby even if the caller's ctx is deferred-canceled on return, while still canceling
	// everything immediately if ctx cancels before winning or on m.Close().
	raceCtx, raceCancel := context.WithTimeout(context.Background(), 15*time.Second)
	stopWatcherDone := make(chan struct{})
	callerDone := make(chan struct{})
	var closeStopOnce sync.Once
	finishWatcher := func() {
		closeStopOnce.Do(func() {
			close(stopWatcherDone)
			raceCancel()
		})
	}
	go func() {
		select {
		case <-m.stopCh:
			raceCancel()
		case <-callerDone:
			select {
			case <-m.stopCh:
				raceCancel()
			case <-stopWatcherDone:
			}
		case <-ctx.Done():
			raceCancel()
		case <-stopWatcherDone:
		}
	}()

	resCh := make(chan pwpDialOutcome, 2)
	inflight := 0
	launch := func(idx int) {
		tried[idx] = true
		inflight++
		node := candidates[idx]
		go func() {
			t0 := time.Now()
			sess, utlsProf, err := m.dialSessionWithFallback(raceCtx, node)
			resCh <- pwpDialOutcome{
				idx:      idx,
				node:     node,
				sess:     sess,
				utlsProf: utlsProf,
				err:      err,
				durMs:    time.Since(t0).Milliseconds(),
			}
		}()
	}

	launch(0)
	staggerTimer := time.NewTimer(happyEyeballsStagger)
	staggerPending := true

	drainAbandoned := func() {
		if inflight == 0 {
			finishWatcher()
			return
		}
		raceCancel()
		pending := inflight
		go func() {
			defer finishWatcher()
			for i := 0; i < pending; i++ {
				out := <-resCh
				if out.sess != nil {
					_ = out.sess.Close()
				}
			}
		}()
	}

	var lastErr error
	for inflight > 0 || staggerPending {
		var timerCh <-chan time.Time
		if staggerPending {
			timerCh = staggerTimer.C
		}
		select {
		case <-m.stopCh:
			if staggerPending {
				staggerTimer.Stop()
				staggerPending = false
			}
			drainAbandoned()
			return nil, errors.New("mux manager closed")

		case <-ctx.Done():
			if staggerPending {
				staggerTimer.Stop()
				staggerPending = false
			}
			drainAbandoned()
			return nil, ctx.Err()

		case <-timerCh:
			staggerPending = false
			if idx1 >= 0 && !tried[idx1] {
				launch(idx1)
			}

		case out := <-resCh:
			inflight--
			m.recordNodeProbe(out.node, out.err == nil, out.durMs, out.sess)
			if out.err == nil && out.sess != nil {
				if staggerPending {
					staggerTimer.Stop()
					staggerPending = false
				}
				if inflight > 0 {
					close(callerDone)
					go m.finishSecondRacer(resCh, inflight, gen, finishWatcher)
				} else {
					finishWatcher()
				}
				stored := m.storeWinningSession(role, gen, out.sess, out.utlsProf)
				if stored == nil {
					return nil, errors.New("mux manager closed")
				}
				return stored, nil
			}
			lastErr = out.err
			m.recordDialFailure(out.err)
			if errors.Is(out.err, ErrLicenseRejected) {
				if staggerPending {
					staggerTimer.Stop()
					staggerPending = false
				}
				drainAbandoned()
				return nil, out.err
			}
			if staggerPending {
				staggerTimer.Stop()
				staggerPending = false
				if idx1 >= 0 && !tried[idx1] {
					launch(idx1)
				}
			}
		}
	}

	finishWatcher()
	return m.dialSequentialCandidates(ctx, role, gen, candidates, tried, lastErr)
}

func (m *MuxManager) ensureStandby(ctx context.Context) {
	if m.isStopped() {
		return
	}
	m.mu.Lock()
	if m.isStopped() {
		m.mu.Unlock()
		return
	}
	cfg := m.cfg
	if cfg != nil && !cfg.V2.StandbyEnabled {
		m.mu.Unlock()
		return
	}
	if m.standby != nil && !m.standby.IsClosed() {
		m.mu.Unlock()
		return
	}
	var primaryNode NodeConfig
	hasPrimary := false
	if primary := m.sessions["ai"]; primary != nil && !primary.IsClosed() {
		primaryNode = primary.Node()
		hasPrimary = true
	}
	candidates := m.selectCandidateNodesLocked("ai")
	m.mu.Unlock()

	if len(candidates) == 0 {
		return
	}
	var chosen NodeConfig
	foundAlt := false
	for _, c := range candidates {
		if !hasPrimary || !sameEndpoint(c, primaryNode) {
			chosen = c
			foundAlt = true
			break
		}
	}
	if !foundAlt {
		chosen = candidates[0]
	}

	dctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	doneDial := make(chan struct{})
	defer close(doneDial)
	go func() {
		select {
		case <-m.stopCh:
			cancel()
		case <-doneDial:
		}
	}()
	sess, _, err := m.dialSessionWithFallback(dctx, chosen)
	if err != nil {
		return
	}

	m.mu.Lock()
	if m.isStopped() || (m.standby != nil && !m.standby.IsClosed()) {
		m.mu.Unlock()
		_ = sess.Close()
		return
	}
	m.standby = sess
	m.standbyNode = chosen
	m.mu.Unlock()
}

func (m *MuxManager) selectCandidateNodesLocked(role string) []NodeConfig {
	if m.cfg == nil {
		return nil
	}
	var roleMatched, general []NodeConfig
	addUnique := func(list *[]NodeConfig, n NodeConfig) {
		for _, ex := range *list {
			if sameEndpoint(ex, n) {
				return
			}
		}
		*list = append(*list, n)
	}

	if m.cfg.ActiveNode.Host != "" {
		if m.cfg.ActiveNode.HasRole(role) {
			addUnique(&roleMatched, m.cfg.ActiveNode)
		} else {
			addUnique(&general, m.cfg.ActiveNode)
		}
	}
	for _, n := range m.cfg.Nodes {
		if n.Host == "" {
			continue
		}
		if n.HasRole(role) {
			addUnique(&roleMatched, n)
		} else {
			addUnique(&general, n)
		}
	}
	prefRegion := ""
	if m.cfg != nil {
		prefRegion = m.cfg.PreferredRegion
	}
	if m.selector != nil {
		if len(roleMatched) > 1 {
			roleMatched = m.selector.RankCandidates(role, prefRegion, roleMatched)
		}
		if len(general) > 1 {
			general = m.selector.RankCandidates(role, prefRegion, general)
		}
	}
	return append(roleMatched, general...)
}

func (m *MuxManager) dialSessionWithFallback(ctx context.Context, node NodeConfig) (*ClientMuxSession, string, error) {
	m.mu.Lock()
	override := m.dialNodeOverride
	cfg := m.cfg
	rootCAs := m.rootCAs
	insecure := m.insecureTest
	m.mu.Unlock()

	if override != nil {
		return override(ctx, node, isWSHost(node))
	}

	uuid := node.UUID
	if uuid == "" && cfg != nil {
		uuid = cfg.ClientUUID
	}
	hwid := ""
	if cfg != nil && cfg.DeviceHWID != "" {
		hwid = cfg.DeviceHWID
	} else {
		hwid = ComputeDeviceHWID()
	}
	preferPWP4 := true
	utlsProf := "chrome"
	dpiProf := DPIProfile(node.FragProfile)
	var pins []string
	var decoySNIs []string
	if cfg != nil {
		preferPWP4 = cfg.V2.PreferPWP4
		if cfg.V2.UTLSProfile != "" {
			utlsProf = cfg.V2.UTLSProfile
		}
		if cfg.V2.DPIProfile > 0 {
			dpiProf = DPIProfile(cfg.V2.DPIProfile)
		}
		pins = append(pins, cfg.PinnedSPKI...)
		decoySNIs = append(decoySNIs, cfg.DecoySNIs...)
	}

	// Resolve host strictly over DoH when node.Host is a domain name (zero ISP DNS fallback/leak).
	dialHost := node.Host
	if net.ParseIP(dialHost) == nil && m.resolver != nil {
		ips, rerr := m.resolver.LookupHost(ctx, dialHost)
		if rerr != nil || len(ips) == 0 {
			if rerr == nil {
				rerr = errors.New("no DNS A/AAAA records")
			}
			return nil, "", fmt.Errorf("doh lookup %s: %w", dialHost, rerr)
		}
		dialHost = ips[0].String()
	}
	port := node.Port
	if port <= 0 {
		port = 443
	}
	sni := node.SNI
	if sni == "" {
		sni = DefaultSNI
	}
	targetAddr := net.JoinHostPort(dialHost, strconv.Itoa(port))
	tuner := m.getAutoTuner()
	netFP := m.currentNetFingerprint()
	allowDecoy := !isWSHost(node) && len(pins) > 0 && !insecure

	dialOnceTLS := func() (*UTLSDialResult, error) {
		res, _, derr := tuner.DialAdaptiveTLS(ctx, AdaptiveDialOptions{
			Address:            targetAddr,
			SNI:                sni,
			BaseUTLSProfile:    utlsProf,
			BaseDPIProfile:     dpiProf,
			EnableSplit:        node.Frag || node.EnableDpiSplit,
			ExternalDesyncTool: DetectExternalPacketDesyncTool(),
			DecoySNIs:          decoySNIs,
			AllowDecoySNI:      allowDecoy,
			Pins:               pins,
			RequirePin:         len(pins) > 0 && rootCAs == nil && !insecure,
			RootCAs:            rootCAs,
			ForceHTTP1ALPN:     true,
			InsecureTestOnly:   insecure,
			NetFingerprint:     netFP,
			DialControl:        m.getDialControl(),
		})
		return res, derr
	}

	usePWP4 := preferPWP4 && node.Mux && !isWSHost(node)

	for attempt := 0; attempt < 2; attempt++ {
		if usePWP4 {
			dRes, err := dialOnceTLS()
			if err != nil {
				// Pre-HTTP TCP/TLS error cannot be recovered by switching PWP-4 -> PWP-3 on the same endpoint.
				return nil, "", err
			}
			sess, pErr := DialPWP4Mux(dRes, node, uuid, hwid, &m.clockOffset)
			if pErr == nil {
				return sess, dRes.Profile, nil
			}
			_ = dRes.Conn.Close()
			if errors.Is(pErr, ErrClockResynced) && attempt == 0 {
				continue
			}
			if !errors.Is(pErr, ErrPWP4Unsupported) {
				if !errors.Is(pErr, ErrLicenseRejected) && tuner != nil {
					tuner.Invalidate(netFP, targetAddr)
				}
				// Non-version-mismatch error (e.g. license error)
				return nil, "", pErr
			}
			// Fall back seamlessly to PWP-3 on this node (and stay on PWP-3 if clock resync retries).
			usePWP4 = false
		}

		dRes3, err := dialOnceTLS()
		if err != nil {
			return nil, "", err
		}
		sess3, pErr3 := DialPWP3Mux(dRes3, node, uuid, hwid, &m.clockOffset)
		if pErr3 == nil {
			return sess3, dRes3.Profile, nil
		}
		_ = dRes3.Conn.Close()
		if errors.Is(pErr3, ErrClockResynced) && attempt == 0 {
			continue
		}
		if !errors.Is(pErr3, ErrLicenseRejected) && tuner != nil {
			tuner.Invalidate(netFP, targetAddr)
		}
		return nil, "", pErr3
	}
	return nil, "", errors.New("mux connect attempts exhausted")
}

func (m *MuxManager) recordNodeProbe(node NodeConfig, online bool, latMs int64, sess *ClientMuxSession) {
	pwp4 := false
	if sess != nil && sess.Protocol() == "PWP-4" {
		pwp4 = true
	}
	m.mu.Lock()
	m.nodeStatuses[node.Name+"|"+node.Host] = NodeProbeStatus{
		Name:      node.Name,
		Region:    node.Region,
		Host:      node.Host,
		Port:      node.Port,
		Mux:       node.Mux,
		Online:    online,
		LatencyMs: latMs,
		Roles:     node.Roles,
		PWP4Ready: pwp4,
	}
	m.mu.Unlock()
	if m.selector != nil {
		m.selector.RecordProbe(node, online, latMs)
	}
}

// Snapshot returns current mux status metrics for telemetry and /__pixelcore/v4/status.
type MuxManagerSnapshot struct {
	Connected          bool
	Protocol           string
	UTLSProfile        string
	DPIStrategy        string
	AutoTunePromotions int64
	DoHUpstream        string
	ActiveNode         string
	StandbyNode        string
	StandbyReady       bool
	FailoverCount      int64
	InstantWakeCount   int64
	LastWakeReason     string
	LastWakeUnix       int64
	MuxStreams         int
	ClockOffsetSec     int64
	License            LicenseMetadata
	BytesUp            int64
	BytesDown          int64
	PingMs             int64
	StickyAINode       string
	AIMigrations       int64
	MediaPoolConns     int
	LastLicenseError   string
	LastConnectError   string
	Nodes              []NodeProbeStatus
}

func (m *MuxManager) Snapshot() MuxManagerSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := MuxManagerSnapshot{
		Protocol:         m.activeProto,
		UTLSProfile:      m.utlsProfile,
		FailoverCount:    m.failoverCount.Load(),
		InstantWakeCount: m.instantWakeCount.Load(),
		LastWakeReason:   m.lastWakeReason,
		LastWakeUnix:     m.lastWakeUnix,
		ClockOffsetSec:   m.clockOffset.Load(),
		LastLicenseError: m.lastLicenseErr,
		LastConnectError: m.lastConnectErr,
	}
	if m.autoTuner != nil {
		snap.DPIStrategy = m.autoTuner.ActiveStrategy()
		snap.AutoTunePromotions = m.autoTuner.Promotions()
	}
	if m.resolver != nil {
		snap.DoHUpstream = m.resolver.ActiveUpstream()
	}
	if s := m.sessions["ai"]; s != nil && !s.IsClosed() {
		snap.Connected = true
		snap.Protocol = s.Protocol()
		snap.ActiveNode = s.Node().Name
		snap.MuxStreams = s.ActiveStreamCount()
		snap.License = s.LicenseMeta()
		snap.BytesUp = s.bytesUp.Load()
		snap.BytesDown = s.bytesDown.Load()
		if m.lastPingSess == s && m.lastPingMs > 0 {
			snap.PingMs = m.lastPingMs
		} else if m.selector != nil {
			snap.PingMs = m.selector.NodeEWMA(s.Node())
		}
	}
	if m.standby != nil && !m.standby.IsClosed() {
		snap.StandbyReady = true
		snap.StandbyNode = m.standby.Node().Name
	} else {
		snap.StandbyNode = m.standbyNode.Name
	}
	if m.selector != nil {
		snap.StickyAINode = m.selector.StickyAINode()
		snap.AIMigrations = m.selector.AIMigrations()
	}
	if m.mediaPool != nil {
		snap.MediaPoolConns = m.mediaPool.Size()
	}
	for _, ns := range m.nodeStatuses {
		snap.Nodes = append(snap.Nodes, ns)
	}
	return snap
}

func (m *MuxManager) isInstantWakeEnabled() bool {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	return cfg.IsInstantWakeEnabled()
}

func (m *MuxManager) instantWakeWatchLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastWall := time.Now()
	lastIfFingerprint := computeLocalInterfaceFingerprint()

	for {
		select {
		case <-m.stopCh:
			return
		case now := <-ticker.C:
			if !m.isInstantWakeEnabled() {
				lastWall = now
				if curFP := computeLocalInterfaceFingerprint(); curFP != "" {
					lastIfFingerprint = curFP
				}
				continue
			}

			// Check clock jump (>3s between 1s ticks indicates OS sleep/hibernation resume)
			delta := now.Sub(lastWall)
			lastWall = now
			if delta > 3*time.Second || delta < -3*time.Second {
				fp := computeLocalInterfaceFingerprint()
				m.netFP.Store(fp)
				_, _ = m.TriggerInstantWake("clock_jump")
				lastIfFingerprint = fp
				continue
			}

			// Check active interface IP changes
			curFP := computeLocalInterfaceFingerprint()
			if curFP != "" && lastIfFingerprint != "" && curFP != lastIfFingerprint {
				m.netFP.Store(curFP)
				lastIfFingerprint = curFP
				_, _ = m.TriggerInstantWake("network_change")
				continue
			}
			if curFP != "" {
				m.netFP.Store(curFP)
			}
			lastIfFingerprint = curFP
		}
	}
}

func (m *MuxManager) standbyMaintenanceLoop() {
	// Keep standby session warm and probe health periodically via FramePing
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			sb := m.standby
			primary := m.sessions["ai"]
			m.mu.Unlock()

			if primary != nil && !primary.IsClosed() {
				tPing := time.Now()
				if rtt, err := primary.Ping(2 * time.Second); err != nil {
					m.recordNodeProbe(primary.Node(), false, time.Since(tPing).Milliseconds(), primary)
					_ = primary.Close()
					m.clearRoleSession("ai", primary)
					if newActive := m.promoteStandby("ai"); newActive != nil {
						m.failoverCount.Add(1)
					}
				} else {
					rttMs := rtt.Milliseconds()
					if rttMs <= 0 {
						rttMs = 1
					}
					m.recordPrimaryPing(primary, rttMs)
					m.recordNodeProbe(primary.Node(), true, rttMs, primary)
					if m.aiMigrateRunning.CompareAndSwap(false, true) {
						migCtx := m.stopCtx
						if migCtx == nil {
							migCtx = context.Background()
						}
						go func() {
							defer m.aiMigrateRunning.Store(false)
							m.checkAndMigrateAI(migCtx)
						}()
					}
				}
			}

			m.mu.Lock()
			sb = m.standby
			m.mu.Unlock()
			if sb == nil || sb.IsClosed() {
				m.ensureStandby(context.Background())
			} else {
				tSb := time.Now()
				if _, err := sb.Ping(2 * time.Second); err != nil {
					m.recordNodeProbe(sb.Node(), false, time.Since(tSb).Milliseconds(), sb)
					_ = sb.Close()
					m.mu.Lock()
					if m.standby == sb {
						m.standby = nil
					}
					m.mu.Unlock()
					m.ensureStandby(context.Background())
				} else {
					m.recordNodeProbe(sb.Node(), true, time.Since(tSb).Milliseconds(), sb)
				}
			}
		}
	}
}

func (m *MuxManager) checkAndMigrateAI(ctx context.Context) {
	if m.selector == nil || m.isStopped() {
		return
	}
	m.mu.Lock()
	primary := m.sessions["ai"]
	sb := m.standby
	cfg := m.cfg
	rootCAs := m.rootCAs
	insecure := m.insecureTest
	candidates := m.selectCandidateNodesLocked("ai")
	gen := m.connectGen.Load()
	m.mu.Unlock()

	if primary == nil || primary.IsClosed() || len(candidates) <= 1 {
		return
	}
	m.selector.SetTransportDeps(m.resolver, rootCAs, insecure, &m.clockOffset)

	pctx, pcancel := context.WithTimeout(ctx, 4*time.Second)
	_, _ = m.selector.ProbeSessionAIPulse(pctx, primary, primary.Node(), cfg)
	pcancel()

	if !m.selector.ShouldMigrateAI(candidates) {
		return
	}

	if sb != nil && !sb.IsClosed() && !sameEndpoint(sb.Node(), primary.Node()) {
		sctx, scancel := context.WithTimeout(ctx, 4*time.Second)
		sbPulse, sbErr := m.selector.ProbeSessionAIPulse(sctx, sb, sb.Node(), cfg)
		scancel()
		if sbErr == nil && !isAIPulseDegraded(sbPulse) {
			var promoted *ClientMuxSession
			m.mu.Lock()
			if !m.isStopped() && m.connectGen.Load() == gen && m.sessions["ai"] == primary && m.standby == sb && !sb.IsClosed() {
				promoted = m.promoteStandbyLocked("ai")
			}
			m.mu.Unlock()
			if promoted != nil {
				m.selector.NotifyConnected("ai", promoted.Node())
				_ = primary.Close()
				if !m.isStopped() {
					go m.ensureStandby(context.Background())
				}
				return
			}
		}
	}

	prefRegion := ""
	if cfg != nil {
		prefRegion = cfg.PreferredRegion
	}
	ranked := m.selector.RankCandidates("ai", prefRegion, candidates)
	for _, cand := range ranked {
		if m.isStopped() || ctx.Err() != nil {
			return
		}
		if sameEndpoint(cand, primary.Node()) {
			continue
		}
		dctx, dcancel := context.WithTimeout(ctx, 6*time.Second)
		t0 := time.Now()
		newSess, utlsProf, err := m.dialSessionWithFallback(dctx, cand)
		dcancel()
		m.recordNodeProbe(cand, err == nil, time.Since(t0).Milliseconds(), newSess)
		if err != nil || newSess == nil {
			continue
		}
		pctx2, pcancel2 := context.WithTimeout(ctx, 4*time.Second)
		pulse2, perr2 := m.selector.ProbeSessionAIPulse(pctx2, newSess, cand, cfg)
		pcancel2()
		if perr2 == nil && isAIPulseDegraded(pulse2) {
			_ = newSess.Close()
			continue
		}

		var replaced bool
		m.mu.Lock()
		if !m.isStopped() && m.connectGen.Load() == gen && m.sessions["ai"] == primary {
			m.sessions["ai"] = newSess
			m.activeProto = newSess.Protocol()
			if utlsProf != "" {
				m.utlsProfile = utlsProf
			}
			replaced = true
		}
		m.mu.Unlock()
		if !replaced {
			_ = newSess.Close()
			return
		}
		m.selector.NotifyConnected("ai", newSess.Node())
		_ = primary.Close()
		if !m.isStopped() {
			go m.ensureStandby(context.Background())
		}
		return
	}
}

func computeLocalInterfaceFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP != nil && !ipNet.IP.IsLoopback() {
				b.WriteString(iface.Name)
				b.WriteByte('=')
				b.WriteString(ipNet.IP.String())
				b.WriteByte(';')
			}
		}
	}
	return b.String()
}
