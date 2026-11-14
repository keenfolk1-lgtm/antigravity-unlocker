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
	rootCAs      *x509.CertPool
	insecureTest bool
	clockOffset  atomic.Int64

	sessions    map[string]*ClientMuxSession // role -> primary active session
	standby     *ClientMuxSession            // pre-warmed backup session
	standbyNode NodeConfig

	nodeStatuses map[string]NodeProbeStatus
	activeProto  string
	utlsProfile  string

	failoverCount    atomic.Int64
	instantWakeCount atomic.Int64
	lastWakeReason   string
	lastWakeUnix     int64
	connectGen       atomic.Uint64

	// Optional hook to customize dialing in unit tests without live network.
	dialNodeOverride func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error)

	stopCh   chan struct{}
	stopOnce sync.Once
	onWakeCb func(reason string, failoverMs int64)
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
	m := &MuxManager{
		cfg:          cfg,
		resolver:     resolver,
		sessions:     make(map[string]*ClientMuxSession),
		nodeStatuses: make(map[string]NodeProbeStatus),
		activeProto:  "PWP-4",
		utlsProfile:  "HelloChrome_Auto",
		stopCh:       make(chan struct{}),
	}
	if cfg != nil && strings.EqualFold(cfg.V2.UTLSProfile, "firefox") {
		m.utlsProfile = "HelloFirefox_Auto"
	}
	return m
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
	m.mu.Unlock()
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
	if err == nil {
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
	sess, err := m.getOrConnectRole(ctx, role)
	if err != nil {
		if sb := m.promoteStandby(role); sb != nil {
			m.failoverCount.Add(1)
			if st, serr := sb.OpenTCPStream(targetHost, targetPort, 3*time.Second); serr == nil {
				go m.ensureStandby(context.Background())
				return st, sb.Node().Name, nil
			}
		}
		return nil, "", err
	}

	failoverBudget := time.Duration(m.failoverTimeoutMs()) * time.Millisecond
	if failoverBudget <= 0 || failoverBudget > 140*time.Millisecond {
		failoverBudget = 130 * time.Millisecond
	}
	halfWait := failoverBudget / 2

	type openRes struct {
		st  *ClientMuxStream
		err error
	}
	resCh := make(chan openRes, 1)
	go func() {
		st, oerr := sess.OpenTCPStream(targetHost, targetPort, 4*time.Second)
		resCh <- openRes{st: st, err: oerr}
	}()

	var st *ClientMuxStream
	var serr error
	timer := time.NewTimer(halfWait)
	select {
	case r := <-resCh:
		timer.Stop()
		st, serr = r.st, r.err
	case <-timer.C:
		// If SynAck did not arrive quickly and standby is ready, probe link with Ping inside remaining budget.
		if m.hasStandby() {
			pingCh := make(chan error, 1)
			go func() {
				_, perr := sess.Ping(halfWait)
				pingCh <- perr
			}()
			select {
			case r := <-resCh:
				st, serr = r.st, r.err
			case perr := <-pingCh:
				if perr != nil {
					serr = fmt.Errorf("primary mux stalled (SynAck+Ping): %w", perr)
				} else {
					r := <-resCh
					st, serr = r.st, r.err
				}
			}
		} else {
			r := <-resCh
			st, serr = r.st, r.err
		}
	}

	if serr == nil && st != nil {
		return st, sess.Node().Name, nil
	}

	// If session died / SynAck+Ping stalled, promote pre-warmed standby immediately
	_ = sess.Close()
	m.clearRoleSession(role, sess)
	if sb := m.promoteStandby(role); sb != nil {
		m.failoverCount.Add(1)
		st2, serr2 := sb.OpenTCPStream(targetHost, targetPort, 4*time.Second)
		if serr2 == nil {
			go m.ensureStandby(context.Background())
			return st2, sb.Node().Name, nil
		}
	}

	// Re-dial primary pool as final fallback
	sess2, derr := m.getOrConnectRole(ctx, role)
	if derr != nil {
		return nil, "", derr
	}
	m.failoverCount.Add(1)
	st3, serr3 := sess2.OpenTCPStream(targetHost, targetPort, 4*time.Second)
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
	return m.getOrConnectRole(ctx, role)
}

// TriggerInstantWake closes stale sessions immediately, resets cached state, promotes/re-dials
// fresh tunnel + standby so resume from sleep has zero hung sockets.
func (m *MuxManager) TriggerInstantWake(reason string) (failoverMs int64, err error) {
	start := time.Now()
	m.connectGen.Add(1)
	m.instantWakeCount.Add(1)

	m.mu.Lock()
	m.lastWakeReason = reason
	m.lastWakeUnix = time.Now().Unix()
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

	wctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, err = m.getOrConnectRole(wctx, "ai")
	failoverMs = time.Since(start).Milliseconds()
	go m.ensureStandby(context.Background())

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
	return 150
}

func (m *MuxManager) clearRoleSession(role string, target *ClientMuxSession) {
	m.mu.Lock()
	if cur := m.sessions[role]; cur == target {
		delete(m.sessions, role)
	}
	m.mu.Unlock()
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
	defer m.mu.Unlock()
	return m.promoteStandbyLocked(role)
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
		m.mu.Unlock()
		_ = sess.Close()
		return existing
	}
	m.sessions[role] = sess
	m.activeProto = sess.Protocol()
	if utlsProf != "" {
		m.utlsProfile = utlsProf
	}
	m.mu.Unlock()
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
	m.mu.Lock()
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
	sess, _, err := m.dialSessionWithFallback(dctx, chosen)
	if err != nil {
		return
	}

	m.mu.Lock()
	if m.standby != nil && !m.standby.IsClosed() {
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
	hwid := DefaultHost
	if cfg != nil && cfg.DeviceHWID != "" {
		hwid = cfg.DeviceHWID
	}
	preferPWP4 := true
	utlsProf := "chrome"
	dpiProf := DPIProfile(node.FragProfile)
	var pins []string
	if cfg != nil {
		preferPWP4 = cfg.V2.PreferPWP4
		if cfg.V2.UTLSProfile != "" {
			utlsProf = cfg.V2.UTLSProfile
		}
		if cfg.V2.DPIProfile > 0 {
			dpiProf = DPIProfile(cfg.V2.DPIProfile)
		}
		pins = append(pins, cfg.PinnedSPKI...)
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
	maskedDecoy := net.ParseIP(node.Host) != nil && !strings.EqualFold(sni, DefaultSNI) && !strings.HasSuffix(strings.ToLower(sni), ".pixelstore.space")

	dialOnceTLS := func() (*UTLSDialResult, error) {
		return DialUTLS(ctx, UTLSDialOptions{
			Address:          net.JoinHostPort(dialHost, strconv.Itoa(port)),
			SNI:              sni,
			Profile:          utlsProf,
			DPIProfile:       dpiProf,
			EnableSplit:      node.Frag || node.EnableDpiSplit,
			MaskedDecoySNI:   maskedDecoy,
			Pins:             pins,
			RequirePin:       len(pins) > 0 && rootCAs == nil && !insecure,
			RootCAs:          rootCAs,
			ForceHTTP1ALPN:   true,
			InsecureTestOnly: insecure,
		})
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
}

// Snapshot returns current mux status metrics for telemetry and /__pixelcore/v4/status.
type MuxManagerSnapshot struct {
	Connected        bool
	Protocol         string
	UTLSProfile      string
	ActiveNode       string
	StandbyNode      string
	StandbyReady     bool
	FailoverCount    int64
	InstantWakeCount int64
	LastWakeReason   string
	LastWakeUnix     int64
	MuxStreams       int
	ClockOffsetSec   int64
	License          LicenseMetadata
	BytesUp          int64
	BytesDown        int64
	Nodes            []NodeProbeStatus
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
	}
	if s := m.sessions["ai"]; s != nil && !s.IsClosed() {
		snap.Connected = true
		snap.Protocol = s.Protocol()
		snap.ActiveNode = s.Node().Name
		snap.MuxStreams = s.ActiveStreamCount()
		snap.License = s.LicenseMeta()
		snap.BytesUp = s.bytesUp.Load()
		snap.BytesDown = s.bytesDown.Load()
	}
	if m.standby != nil && !m.standby.IsClosed() {
		snap.StandbyReady = true
		snap.StandbyNode = m.standby.Node().Name
	} else {
		snap.StandbyNode = m.standbyNode.Name
	}
	for _, ns := range m.nodeStatuses {
		snap.Nodes = append(snap.Nodes, ns)
	}
	return snap
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
			// Check clock jump (>3s between 1s ticks indicates OS sleep/hibernation resume)
			delta := now.Sub(lastWall)
			lastWall = now
			if delta > 3*time.Second || delta < -3*time.Second {
				_, _ = m.TriggerInstantWake("clock_jump")
				lastIfFingerprint = computeLocalInterfaceFingerprint()
				continue
			}

			// Check active interface IP changes
			curFP := computeLocalInterfaceFingerprint()
			if curFP != "" && lastIfFingerprint != "" && curFP != lastIfFingerprint {
				lastIfFingerprint = curFP
				_, _ = m.TriggerInstantWake("network_change")
				continue
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
				if _, err := primary.Ping(2 * time.Second); err != nil {
					_ = primary.Close()
					m.clearRoleSession("ai", primary)
					if newActive := m.promoteStandby("ai"); newActive != nil {
						m.failoverCount.Add(1)
					}
				}
			}

			if sb == nil || sb.IsClosed() {
				m.ensureStandby(context.Background())
			} else if _, err := sb.Ping(2 * time.Second); err != nil {
				_ = sb.Close()
				m.mu.Lock()
				if m.standby == sb {
					m.standby = nil
				}
				m.mu.Unlock()
				m.ensureStandby(context.Background())
			}
		}
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
