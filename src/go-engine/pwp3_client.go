package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	FrameSynTCP    byte = 0x01
	FrameData      byte = 0x02
	FrameFin       byte = 0x03
	FrameRst       byte = 0x04
	FrameWinUpdate byte = 0x05
	FramePing      byte = 0x06
	FramePong      byte = 0x07
	FrameUDPData   byte = 0x08
	FrameSynAck    byte = 0x09

	MaxMuxChunkSize           = 32768
	InitialStreamWindow       = 262144
	maxClientStreamQueueBytes = 2 * InitialStreamWindow
	WindowUpdateStep          = 65536
	HardBlockLimit            = uint64(0xE0000000)
)

// PixelStreamCipher implements PixelCore v2/v3 SHA-256 CTR XOR cipher (blockLen=32).
type PixelStreamCipher struct {
	keySalt []byte
	counter uint32
	block   [32]byte
	offset  int
}

// NewPixelStreamCipher constructs a PixelStreamCipher initialized to counter=0.
func NewPixelStreamCipher(secret, salt string) *PixelStreamCipher {
	c := &PixelStreamCipher{
		keySalt: []byte(secret + salt),
		offset:  32,
	}
	return c
}

func (c *PixelStreamCipher) nextBlock() error {
	if uint64(c.counter) >= HardBlockLimit {
		return errors.New("pixel stream cipher block limit reached")
	}
	var tail [4]byte
	binary.BigEndian.PutUint32(tail[:], c.counter)
	h := sha256.New()
	_, _ = h.Write(c.keySalt)
	_, _ = h.Write(tail[:])
	sum := h.Sum(nil)
	copy(c.block[:], sum)
	c.counter++
	c.offset = 0
	return nil
}

// Transform encrypts or decrypts src in place (XOR keystream).
func (c *PixelStreamCipher) Transform(dst, src []byte) error {
	for i := range src {
		if c.offset >= 32 {
			if err := c.nextBlock(); err != nil {
				return err
			}
		}
		dst[i] = src[i] ^ c.block[c.offset]
		c.offset++
	}
	return nil
}

// MuxCodec abstracts PWP-3 XOR mux framing and PWP-4 AEAD mux framing over a connected stream.
type MuxCodec interface {
	ProtocolName() string
	WriteFrame(w io.Writer, frameType byte, streamID uint32, flags byte, payload []byte, randomPadMax int) error
	ReadFrame(r io.Reader) (frameType byte, streamID uint32, payload []byte, err error)
}

type pwp3Codec struct {
	rx            *PixelStreamCipher
	tx            *PixelStreamCipher
	nativeTLSBulk bool
	rxScratch     []byte
}

func (c *pwp3Codec) ProtocolName() string {
	return "PWP-3"
}

func (c *pwp3Codec) WriteFrame(w io.Writer, frameType byte, streamID uint32, flags byte, payload []byte, randomPadMax int) error {
	if len(payload) > MaxMuxChunkSize {
		return fmt.Errorf("pwp3 payload too large: %d", len(payload))
	}
	padLen := 0
	if randomPadMax > 0 {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(randomPadMax+1)))
		if err == nil {
			padLen = int(nBig.Int64())
		}
	}
	if padLen > 255 {
		padLen = 255
	}

	frame := make([]byte, 9+len(payload)+padLen)
	frame[0] = frameType
	binary.BigEndian.PutUint32(frame[1:5], streamID)
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(payload)))
	frame[7] = flags
	frame[8] = byte(padLen)
	if len(payload) > 0 {
		copy(frame[9:], payload)
	}
	if padLen > 0 {
		_, _ = rand.Read(frame[9+len(payload):])
	}

	if c.nativeTLSBulk {
		if err := c.tx.Transform(frame[:9], frame[:9]); err != nil {
			return err
		}
	} else {
		if err := c.tx.Transform(frame, frame); err != nil {
			return err
		}
	}
	return writeFull(w, frame)
}

func (c *pwp3Codec) ReadFrame(r io.Reader) (byte, uint32, []byte, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	if err := c.rx.Transform(hdr[:], hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	fType := hdr[0]
	streamID := binary.BigEndian.Uint32(hdr[1:5])
	pLen := int(binary.BigEndian.Uint16(hdr[5:7]))
	padLen := int(hdr[8])
	if pLen > MaxMuxChunkSize {
		return 0, 0, nil, errors.New("pwp3 frame payload exceeds limit")
	}
	bodyLen := pLen + padLen
	if bodyLen == 0 {
		return fType, streamID, nil, nil
	}
	if cap(c.rxScratch) < bodyLen {
		c.rxScratch = make([]byte, bodyLen)
	}
	body := c.rxScratch[:bodyLen]
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	if !c.nativeTLSBulk {
		if err := c.rx.Transform(body, body); err != nil {
			return 0, 0, nil, err
		}
	}
	out := make([]byte, pLen)
	copy(out, body[:pLen])
	return fType, streamID, out, nil
}

// LicenseMetadata holds X-Edge-Telemetry server feedback parsed during handshake.
type LicenseMetadata struct {
	Tier        string
	DaysLeft    int
	HoursLeft   int
	DevicesUsed int
	DevicesMax  int
	NodeName    string
	Proto       string
}

var (
	ErrClockResynced   = errors.New("clock drift compensated from server date")
	ErrLicenseRejected = errors.New("license rejected by edge server")
	ErrPWP4Unsupported = errors.New("node does not support PWP-4")
)

// ClientMuxSession multiplexes client TCP and UDP streams over either PWP-4 or PWP-3.
type ClientMuxSession struct {
	conn        net.Conn
	br          *bufio.Reader
	codec       MuxCodec
	node        NodeConfig
	proto       string
	meta        LicenseMetadata
	writeMu     sync.Mutex
	streamsMu   sync.RWMutex
	streams     map[uint32]*ClientMuxStream
	udpMu       sync.RWMutex
	udpHandlers map[uint32]func(srcHost string, srcPort int, payload []byte)
	nextID      atomic.Uint32
	closed      atomic.Bool
	doneCh      chan struct{}

	pongMu     sync.Mutex
	pongWaiter map[uint32]chan struct{}

	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	lastRxTs  atomic.Int64
}

// NewClientMuxSession initializes and starts the read loop on an authenticated tunnel connection.
func NewClientMuxSession(conn net.Conn, br *bufio.Reader, codec MuxCodec, node NodeConfig, meta LicenseMetadata) *ClientMuxSession {
	s := &ClientMuxSession{
		conn:        conn,
		br:          br,
		codec:       codec,
		node:        node,
		proto:       codec.ProtocolName(),
		meta:        meta,
		streams:     make(map[uint32]*ClientMuxStream),
		udpHandlers: make(map[uint32]func(string, int, []byte)),
		doneCh:      make(chan struct{}),
		pongWaiter:  make(map[uint32]chan struct{}),
	}
	s.nextID.Store(1)
	s.lastRxTs.Store(time.Now().UnixNano())
	go s.readLoop()
	return s
}

func (s *ClientMuxSession) Protocol() string             { return s.proto }
func (s *ClientMuxSession) Node() NodeConfig             { return s.node }
func (s *ClientMuxSession) LicenseMeta() LicenseMetadata { return s.meta }
func (s *ClientMuxSession) IsClosed() bool               { return s.closed.Load() }
func (s *ClientMuxSession) Done() <-chan struct{}        { return s.doneCh }
func (s *ClientMuxSession) ActiveStreamCount() int {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return len(s.streams)
}

// Close closes the mux session and all active streams.
func (s *ClientMuxSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.doneCh)
	err := s.conn.Close()

	s.streamsMu.Lock()
	for id, st := range s.streams {
		st.closeWithError(io.ErrClosedPipe)
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()

	s.pongMu.Lock()
	for id, ch := range s.pongWaiter {
		close(ch)
		delete(s.pongWaiter, id)
	}
	s.pongMu.Unlock()
	return err
}

func (s *ClientMuxSession) writeFrame(frameType byte, streamID uint32, flags byte, payload []byte, randomPadMax int) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	err := s.codec.WriteFrame(s.conn, frameType, streamID, flags, payload, randomPadMax)
	_ = s.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		go s.Close()
	}
	return err
}

// Ping measures round-trip ping latency over the mux control plane.
func (s *ClientMuxSession) Ping(timeout time.Duration) (time.Duration, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	pingID := s.nextID.Add(2)
	ch := make(chan struct{})
	s.pongMu.Lock()
	s.pongWaiter[pingID] = ch
	s.pongMu.Unlock()

	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	start := time.Now()
	if err := s.writeFrame(FramePing, pingID, 0, nonce[:], 16); err != nil {
		s.pongMu.Lock()
		delete(s.pongWaiter, pingID)
		s.pongMu.Unlock()
		return 0, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return time.Since(start), nil
	case <-s.doneCh:
		return 0, io.ErrClosedPipe
	case <-timer.C:
		s.pongMu.Lock()
		delete(s.pongWaiter, pingID)
		s.pongMu.Unlock()
		return 0, errors.New("mux ping timeout")
	}
}

// OpenTCPStream opens a multiplexed stream to targetHost:targetPort and waits up to synAckTimeout for FrameSynAck.
func (s *ClientMuxSession) OpenTCPStream(targetHost string, targetPort int, synAckTimeout time.Duration) (*ClientMuxStream, error) {
	if s.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	if len(targetHost) == 0 || len(targetHost) > 255 || targetPort <= 0 || targetPort > 65535 {
		return nil, errors.New("invalid mux target host/port")
	}
	if synAckTimeout <= 0 {
		synAckTimeout = 4 * time.Second
	}

	streamID := s.nextID.Add(2)
	st := newClientMuxStream(streamID, s)

	s.streamsMu.Lock()
	s.streams[streamID] = st
	s.streamsMu.Unlock()

	synPayload := make([]byte, 1+len(targetHost)+2)
	synPayload[0] = byte(len(targetHost))
	copy(synPayload[1:1+len(targetHost)], targetHost)
	binary.BigEndian.PutUint16(synPayload[1+len(targetHost):], uint16(targetPort))

	if err := s.writeFrame(FrameSynTCP, streamID, 0, synPayload, 0); err != nil {
		s.removeStream(streamID, err)
		return nil, err
	}

	timer := time.NewTimer(synAckTimeout)
	defer timer.Stop()
	select {
	case err := <-st.synAckCh:
		if err != nil {
			s.removeStream(streamID, err)
			return nil, err
		}
		return st, nil
	case <-s.doneCh:
		s.removeStream(streamID, io.ErrClosedPipe)
		return nil, io.ErrClosedPipe
	case <-timer.C:
		_ = s.writeFrame(FrameRst, streamID, 0, nil, 0)
		s.removeStream(streamID, errors.New("mux SynAck timeout"))
		return nil, errors.New("mux SynAck timeout")
	}
}

// RegisterUDPHandler reserves a stream ID and receives server inbound UDP packets for SOCKS5 UDP ASSOCIATE.
func (s *ClientMuxSession) RegisterUDPHandler(handler func(srcHost string, srcPort int, payload []byte)) uint32 {
	id := s.nextID.Add(2)
	s.udpMu.Lock()
	s.udpHandlers[id] = handler
	s.udpMu.Unlock()
	return id
}

// UnregisterUDPHandler releases a UDP association ID and notifies server with FrameRst.
func (s *ClientMuxSession) UnregisterUDPHandler(assocID uint32) {
	s.udpMu.Lock()
	delete(s.udpHandlers, assocID)
	s.udpMu.Unlock()
	_ = s.writeFrame(FrameRst, assocID, 0, nil, 0)
}

// SendUDP sends one datagram via FrameUDPData on assocID.
func (s *ClientMuxSession) SendUDP(assocID uint32, dstHost string, dstPort int, dgram []byte) error {
	if len(dstHost) == 0 || len(dstHost) > 255 || dstPort <= 0 || dstPort > 65535 {
		return errors.New("invalid udp target")
	}
	pkt := make([]byte, 1+len(dstHost)+2+len(dgram))
	pkt[0] = byte(len(dstHost))
	copy(pkt[1:1+len(dstHost)], dstHost)
	binary.BigEndian.PutUint16(pkt[1+len(dstHost):1+len(dstHost)+2], uint16(dstPort))
	copy(pkt[1+len(dstHost)+2:], dgram)
	s.bytesUp.Add(int64(len(dgram)))
	return s.writeFrame(FrameUDPData, assocID, 0, pkt, 0)
}

func (s *ClientMuxSession) removeStream(id uint32, err error) {
	s.streamsMu.Lock()
	st, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
	if st != nil {
		st.closeWithError(err)
	}
}

func (s *ClientMuxSession) readLoop() {
	defer func() { _ = s.Close() }()
	for !s.closed.Load() {
		fType, streamID, payload, err := s.codec.ReadFrame(s.br)
		if err != nil {
			return
		}
		s.lastRxTs.Store(time.Now().UnixNano())

		switch fType {
		case FrameSynAck:
			s.streamsMu.RLock()
			st := s.streams[streamID]
			s.streamsMu.RUnlock()
			if st != nil {
				st.notifySynAck(nil)
			}

		case FrameData:
			if len(payload) > 0 {
				s.bytesDown.Add(int64(len(payload)))
			}
			s.streamsMu.RLock()
			st := s.streams[streamID]
			s.streamsMu.RUnlock()
			if st != nil {
				if overflow := st.pushData(payload); overflow {
					_ = s.writeFrame(FrameRst, streamID, 0, nil, 0)
					s.removeStream(streamID, errors.New("stream rx buffer overflow"))
				}
			}

		case FrameFin:
			s.streamsMu.RLock()
			st := s.streams[streamID]
			s.streamsMu.RUnlock()
			if st != nil {
				st.pushEOF()
			}

		case FrameRst:
			s.streamsMu.RLock()
			st := s.streams[streamID]
			s.streamsMu.RUnlock()
			if st != nil {
				st.peerClosed.Store(true)
			}
			s.removeStream(streamID, io.ErrUnexpectedEOF)

		case FrameWinUpdate:
			if len(payload) >= 4 {
				delta := binary.BigEndian.Uint32(payload[:4])
				s.streamsMu.RLock()
				st := s.streams[streamID]
				s.streamsMu.RUnlock()
				if st != nil {
					st.addSendWindow(delta)
				}
			}

		case FramePing:
			_ = s.writeFrame(FramePong, streamID, 0, payload, 0)

		case FramePong:
			s.pongMu.Lock()
			if ch, ok := s.pongWaiter[streamID]; ok {
				delete(s.pongWaiter, streamID)
				close(ch)
			}
			s.pongMu.Unlock()

		case FrameUDPData:
			if len(payload) >= 4 {
				hl := int(payload[0])
				if hl > 0 && 1+hl+2 <= len(payload) {
					host := string(payload[1 : 1+hl])
					port := int(binary.BigEndian.Uint16(payload[1+hl : 1+hl+2]))
					dgram := payload[1+hl+2:]
					s.bytesDown.Add(int64(len(dgram)))
					s.udpMu.RLock()
					handler := s.udpHandlers[streamID]
					s.udpMu.RUnlock()
					if handler != nil {
						handler(host, port, dgram)
					}
				}
			}

		case FrameRekey:
			p4, ok := s.codec.(*pwp4ClientCodec)
			if !ok {
				return
			}
			if err := p4.rx.Rekey(payload); err != nil {
				return
			}

		case FramePad:
			// Ignored decoy traffic padding

		default:
			return
		}
	}
}

// ClientMuxStream implements net.Conn over one PWP-3 or PWP-4 mux stream ID.
type ClientMuxStream struct {
	id         uint32
	session    *ClientMuxSession
	synAckOnce sync.Once
	synAckCh   chan error

	rxMu         sync.Mutex
	rxChunks     [][]byte
	rxQueueBytes int64
	rxNotify     chan struct{}
	rxEOF        bool
	rxErr        error
	closedCh     chan struct{}
	closeOnce    sync.Once

	peerClosed  atomic.Bool
	localClosed atomic.Bool
	finSent     atomic.Bool
	rstSent     atomic.Bool

	winMu      sync.Mutex
	winCond    *sync.Cond
	sendWindow int64

	drainedMu sync.Mutex
	drained   int64
}

func newClientMuxStream(id uint32, s *ClientMuxSession) *ClientMuxStream {
	st := &ClientMuxStream{
		id:         id,
		session:    s,
		synAckCh:   make(chan error, 1),
		rxNotify:   make(chan struct{}, 1),
		closedCh:   make(chan struct{}),
		sendWindow: InitialStreamWindow,
	}
	st.winCond = sync.NewCond(&st.winMu)
	return st
}

func (st *ClientMuxStream) notifySynAck(err error) {
	st.synAckOnce.Do(func() {
		select {
		case st.synAckCh <- err:
		default:
		}
	})
}

func (st *ClientMuxStream) signalRx() {
	select {
	case st.rxNotify <- struct{}{}:
	default:
	}
}

// pushData appends payload into a byte-bounded per-stream queue without ever blocking readLoop.
// Returns true if buffering would exceed maxClientStreamQueueBytes (caller resets the stalled stream).
func (st *ClientMuxStream) pushData(data []byte) (overflow bool) {
	if len(data) == 0 {
		return false
	}
	cp := make([]byte, len(data))
	copy(cp, data)

	st.rxMu.Lock()
	if st.rxEOF || st.rxErr != nil {
		st.rxMu.Unlock()
		return false
	}
	if st.rxQueueBytes+int64(len(cp)) > maxClientStreamQueueBytes {
		st.rxMu.Unlock()
		return true
	}
	st.rxChunks = append(st.rxChunks, cp)
	st.rxQueueBytes += int64(len(cp))
	st.rxMu.Unlock()
	st.signalRx()
	return false
}

func (st *ClientMuxStream) pushEOF() {
	st.peerClosed.Store(true)
	st.rxMu.Lock()
	st.rxEOF = true
	st.rxMu.Unlock()
	st.signalRx()
}

func (st *ClientMuxStream) closeWithError(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	st.notifySynAck(err)
	st.closeOnce.Do(func() {
		st.rxMu.Lock()
		if st.rxErr == nil {
			st.rxErr = err
		}
		st.rxMu.Unlock()
		close(st.closedCh)
		st.signalRx()
		st.winMu.Lock()
		st.winCond.Broadcast()
		st.winMu.Unlock()
	})
}

func (st *ClientMuxStream) addSendWindow(delta uint32) {
	if delta == 0 {
		return
	}
	st.winMu.Lock()
	st.sendWindow += int64(delta)
	st.winCond.Broadcast()
	st.winMu.Unlock()
}

func (st *ClientMuxStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		st.rxMu.Lock()
		if len(st.rxChunks) > 0 {
			front := st.rxChunks[0]
			n := copy(p, front)
			st.rxQueueBytes -= int64(n)
			if n < len(front) {
				st.rxChunks[0] = front[n:]
			} else {
				st.rxChunks[0] = nil
				st.rxChunks = st.rxChunks[1:]
				if len(st.rxChunks) == 0 {
					st.rxChunks = nil
				}
			}
			hasMore := len(st.rxChunks) > 0 || st.rxEOF || st.rxErr != nil
			st.rxMu.Unlock()
			if hasMore {
				st.signalRx()
			}
			st.recordDrained(n)
			return n, nil
		}
		if st.rxEOF {
			st.rxMu.Unlock()
			return 0, io.EOF
		}
		if st.rxErr != nil {
			err := st.rxErr
			st.rxMu.Unlock()
			return 0, err
		}
		st.rxMu.Unlock()

		select {
		case <-st.rxNotify:
		case <-st.closedCh:
		}
	}
}

func (st *ClientMuxStream) recordDrained(n int) {
	if n <= 0 {
		return
	}
	var delta uint32
	st.drainedMu.Lock()
	st.drained += int64(n)
	if st.drained >= WindowUpdateStep {
		delta = uint32(st.drained)
		st.drained = 0
	}
	st.drainedMu.Unlock()
	if delta > 0 {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], delta)
		_ = st.session.writeFrame(FrameWinUpdate, st.id, 0, buf[:], 0)
	}
}

func (st *ClientMuxStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for total < len(p) {
		want := len(p) - total
		if want > MaxMuxChunkSize {
			want = MaxMuxChunkSize
		}

		st.winMu.Lock()
		for st.sendWindow <= 0 {
			select {
			case <-st.closedCh:
				st.winMu.Unlock()
				return total, io.ErrClosedPipe
			default:
			}
			st.winCond.Wait()
		}
		grant := want
		if int64(grant) > st.sendWindow {
			grant = int(st.sendWindow)
		}
		st.sendWindow -= int64(grant)
		st.winMu.Unlock()

		chunk := p[total : total+grant]
		if err := st.session.writeFrame(FrameData, st.id, 0, chunk, 0); err != nil {
			return total, err
		}
		st.session.bytesUp.Add(int64(grant))
		total += grant
	}
	return total, nil
}

// CloseWrite sends FrameFin to gracefully close the write half.
func (st *ClientMuxStream) CloseWrite() error {
	if st.localClosed.Load() || st.rstSent.Load() {
		return io.ErrClosedPipe
	}
	if st.finSent.CompareAndSwap(false, true) {
		return st.session.writeFrame(FrameFin, st.id, 0, nil, 0)
	}
	return nil
}

// Close closes the stream; if the peer has not sent FrameFin/FrameRst yet, sends FrameRst
// so server Pump 2 immediately unblocks its send window wait and releases its socket FD.
func (st *ClientMuxStream) Close() error {
	if st.localClosed.CompareAndSwap(false, true) {
		if !st.peerClosed.Load() && st.rstSent.CompareAndSwap(false, true) {
			_ = st.session.writeFrame(FrameRst, st.id, 0, nil, 0)
		}
		st.session.removeStream(st.id, io.ErrClosedPipe)
	}
	return nil
}

func (st *ClientMuxStream) LocalAddr() net.Addr                { return st.session.conn.LocalAddr() }
func (st *ClientMuxStream) RemoteAddr() net.Addr               { return st.session.conn.RemoteAddr() }
func (st *ClientMuxStream) SetDeadline(t time.Time) error      { return nil }
func (st *ClientMuxStream) SetReadDeadline(t time.Time) error  { return nil }
func (st *ClientMuxStream) SetWriteDeadline(t time.Time) error { return nil }

// DialPWP3Mux establishes a PWP-3 WebSocket+XOR mux session (backward compat with v1.9.0 nodes).
func DialPWP3Mux(
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
	ts := time.Now().Unix() + offset
	tsStr := strconv.FormatInt(ts, 10)

	var wsKeyRaw [16]byte
	var junk [18]byte
	_, _ = rand.Read(wsKeyRaw[:])
	_, _ = rand.Read(junk[:])
	wsKey := base64.StdEncoding.EncodeToString(wsKeyRaw[:])
	junkToken := base64.RawURLEncoding.EncodeToString(junk[:])

	mac := hmac.New(sha256.New, []byte(node.Secret))
	_, _ = mac.Write([]byte(tsStr + ":" + wsKey + ":" + clientUUID + ":" + hwid))
	sigHex32 := hex.EncodeToString(mac.Sum(nil)[:16])

	reqPath := node.Path
	if reqPath == "" {
		reqPath = DefaultPWP3Path
	}

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Cookie: _cfuvid=%s.%s.%s; __cf_bm=%s.%s\r\n\r\n",
		reqPath, sniHost, wsKey, tsStr, hwid, clientUUID, sigHex32, junkToken,
	)

	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := writeFull(conn, []byte(req)); err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(conn, 32*1024)
	statusLine, hdrs, err := readHTTPResponseHeaders(br)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("pwp3 read response: %w", err)
	}

	resynced := syncClockFromHTTPDate(hdrs.Get("Date"), offset, clockOffset)

	if strings.Contains(statusLine, " 403 ") {
		edgeStatus := strings.TrimSpace(hdrs.Get("X-Edge-Status"))
		if resynced && (edgeStatus == "" || strings.Contains(strings.ToUpper(edgeStatus), "TIME") || strings.Contains(strings.ToUpper(edgeStatus), "SIG")) {
			return nil, ErrClockResynced
		}
		return nil, fmt.Errorf("%w: %s", ErrLicenseRejected, edgeStatus)
	}
	if !strings.Contains(statusLine, " 101 ") {
		if resynced {
			return nil, ErrClockResynced
		}
		return nil, fmt.Errorf("pwp3 handshake rejected (%s)", statusLine)
	}

	meta := parseEdgeTelemetryHeader(hdrs.Get("X-Edge-Telemetry"))
	meta.Proto = "PWP-3"

	serverSalt, nativeTLSBulk := extractPWP3Salt(hdrs.Values("Set-Cookie"), hdrs.Get("X-Pixel-Salt"), node.TLS)
	if serverSalt == "" {
		return nil, errors.New("pwp3 response missing server salt")
	}

	tx := NewPixelStreamCipher(node.Secret, wsKey+":c2s")
	rx := NewPixelStreamCipher(node.Secret, serverSalt+":s2c")
	codec := &pwp3Codec{
		rx:            rx,
		tx:            tx,
		nativeTLSBulk: nativeTLSBulk,
	}
	return NewClientMuxSession(conn, br, codec, node, meta), nil
}

func extractPWP3Salt(setCookies []string, xPixelSalt string, nodeTLS bool) (string, bool) {
	for _, sc := range setCookies {
		for _, part := range strings.Split(sc, ";") {
			p := strings.TrimSpace(part)
			if !strings.HasPrefix(p, "__cfruid=") {
				continue
			}
			val := strings.TrimPrefix(p, "__cfruid=")
			segs := strings.Split(val, ".")
			if len(segs) >= 3 && segs[1] == "m3" {
				return segs[0], (segs[2] == "n") && nodeTLS
			}
			if len(segs) >= 2 {
				return segs[0], (segs[1] == "n") && nodeTLS
			}
		}
	}
	return strings.TrimSpace(xPixelSalt), false
}

func readHTTPResponseHeaders(br *bufio.Reader) (string, http.Header, error) {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	hdrs := make(http.Header)
	for i := 0; i < 64; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return statusLine, hdrs, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return statusLine, hdrs, nil
		}
		if colon := strings.IndexByte(line, ':'); colon > 0 {
			k := strings.TrimSpace(line[:colon])
			v := strings.TrimSpace(line[colon+1:])
			hdrs.Add(k, v)
		}
	}
	return statusLine, hdrs, errors.New("too many http response headers")
}

func syncClockFromHTTPDate(dateHdr string, prevOffset int64, clockOffset *atomic.Int64) bool {
	if dateHdr == "" || clockOffset == nil {
		return false
	}
	srvTime, err := http.ParseTime(strings.TrimSpace(dateHdr))
	if err != nil {
		return false
	}
	newOffset := srvTime.Unix() - time.Now().Unix()
	if absInt64(newOffset-prevOffset) >= 90 {
		clockOffset.Store(newOffset)
		return true
	}
	return false
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func parseEdgeTelemetryHeader(raw string) LicenseMetadata {
	meta := LicenseMetadata{Tier: "free"}
	if raw == "" {
		return meta
	}
	for _, part := range strings.Split(raw, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "t":
			meta.Tier = strings.ToLower(v)
		case "d":
			meta.DaysLeft, _ = strconv.Atoi(v)
		case "h":
			meta.HoursLeft, _ = strconv.Atoi(v)
		case "u":
			meta.DevicesUsed, _ = strconv.Atoi(v)
		case "m":
			meta.DevicesMax, _ = strconv.Atoi(v)
		case "n":
			meta.NodeName = v
		case "p":
			meta.Proto = strings.ToUpper(v)
		}
	}
	return meta
}

func writeFull(w io.Writer, buf []byte) error {
	off := 0
	for off < len(buf) {
		n, err := w.Write(buf[off:])
		if n > 0 {
			off += n
		}
		if err != nil {
			return err
		}
	}
	return nil
}
