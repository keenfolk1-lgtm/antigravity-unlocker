package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pacedWriteConn struct {
	net.Conn
	paceThreshold int
	paceDelay     time.Duration
}

func (c *pacedWriteConn) Write(p []byte) (int, error) {
	if c.paceDelay > 0 && len(p) > c.paceThreshold {
		time.Sleep(c.paceDelay)
	}
	return c.Conn.Write(p)
}

func TestQoSLaneClassificationAndBulkSliceSize(t *testing.T) {
	fastTypes := []byte{
		FrameSynTCP, FrameSynAck, FrameWinUpdate,
		FramePing, FramePong, FrameFin, FrameRst,
		FrameRekey, FrameUDPData, FramePad,
	}
	for _, ft := range fastTypes {
		if !isFastLaneFrame(ft, 0) || !isFastLaneFrame(ft, 4096) {
			t.Fatalf("expected non-FrameData type 0x%02x to always be fast lane", ft)
		}
	}
	if !isFastLaneFrame(FrameData, 0) || !isFastLaneFrame(FrameData, 511) || !isFastLaneFrame(FrameData, QoSSmallDataThreshold) {
		t.Fatalf("expected small FrameData <= %d to be fast lane", QoSSmallDataThreshold)
	}
	if isFastLaneFrame(FrameData, QoSSmallDataThreshold+1) || isFastLaneFrame(FrameData, QoSBulkSliceSize) {
		t.Fatalf("expected FrameData > %d to be bulk lane", QoSSmallDataThreshold)
	}
	if QoSBulkSliceSize != 16384 || QoSBulkSliceSize > MaxMuxChunkSize {
		t.Fatalf("unexpected QoSBulkSliceSize=%d (MaxMuxChunkSize=%d)", QoSBulkSliceSize, MaxMuxChunkSize)
	}

	pCli, pSrv := net.Pipe()
	defer pCli.Close()
	defer pSrv.Close()

	mat, err := DerivePWP4KeyMaterial("qos-slice-secret", "cli", "srv")
	if err != nil {
		t.Fatalf("DerivePWP4KeyMaterial: %v", err)
	}
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	sTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	dataSizesCh := make(chan int, 16)
	var srvWriteMu sync.Mutex
	go func() {
		br := bufio.NewReader(pSrv)
		for {
			ft, sid, payload, _, rErr := sRx.OpenFrame(br, nil)
			if rErr != nil {
				return
			}
			switch ft {
			case FrameSynTCP:
				f, _ := sTx.SealFrame(FrameSynAck, sid, nil)
				srvWriteMu.Lock()
				_, _ = pSrv.Write(f)
				srvWriteMu.Unlock()
			case FrameData:
				dataSizesCh <- len(payload)
			}
		}
	}()

	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: "SliceNode", Host: "10.0.0.1", Port: 443}, LicenseMetadata{Proto: "PWP-4"})
	defer sess.Close()

	st, err := sess.OpenTCPStream("slice.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenTCPStream: %v", err)
	}
	defer st.Close()

	// Write 40960 bytes (16384 + 16384 + 8192) -> 3 bulk frames, none > QoSBulkSliceSize.
	buf := bytes.Repeat([]byte{0x5A}, 40960)
	n, err := st.Write(buf)
	if err != nil || n != len(buf) {
		t.Fatalf("bulk Write: n=%d err=%v", n, err)
	}
	// Write 400 bytes -> 1 fast-lane FrameData frame.
	if _, err := st.Write(bytes.Repeat([]byte{0x3C}, 400)); err != nil {
		t.Fatalf("small Write: %v", err)
	}

	var gotSizes []int
	for i := 0; i < 4; i++ {
		select {
		case sz := <-dataSizesCh:
			if sz > QoSBulkSliceSize {
				t.Fatalf("frame size %d exceeded QoSBulkSliceSize %d", sz, QoSBulkSliceSize)
			}
			gotSizes = append(gotSizes, sz)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for frame %d", i)
		}
	}
	wantSizes := []int{16384, 16384, 8192, 400}
	for i, w := range wantSizes {
		if gotSizes[i] != w {
			t.Fatalf("frame[%d] size=%d, want %d (all=%v)", i, gotSizes[i], w, gotSizes)
		}
	}
	if sess.BulkLaneFrames() != 3 {
		t.Fatalf("BulkLaneFrames=%d, want 3", sess.BulkLaneFrames())
	}
	// FrameSynTCP (1) + small FrameData (1) = 2 fast-lane frames
	if sess.FastLaneFrames() != 2 {
		t.Fatalf("FastLaneFrames=%d, want 2", sess.FastLaneFrames())
	}
}

func TestQoSFastLanePreemptionAndPWP4Integrity(t *testing.T) {
	baseGoroutines := runtime.NumGoroutine()

	rawCli, pSrv := net.Pipe()
	pacedCli := &pacedWriteConn{
		Conn:          rawCli,
		paceThreshold: 2500,
		paceDelay:     3 * time.Millisecond,
	}

	mat, err := DerivePWP4KeyMaterial("qos-preempt-secret", "c1", "s1")
	if err != nil {
		t.Fatalf("DerivePWP4KeyMaterial: %v", err)
	}
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
	// Force mid-stream PWP-4 epoch rekey under concurrent fast/bulk load to verify nonce sync.
	cTx.SetRekeyLimits(32, 0)

	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	sTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	var srvWriteMu sync.Mutex
	sendSrvFrame := func(ft byte, sid uint32, pl []byte) {
		wire, serr := sTx.SealFrame(ft, sid, pl)
		if serr != nil {
			return
		}
		srvWriteMu.Lock()
		_, _ = pSrv.Write(wire)
		srvWriteMu.Unlock()
	}

	var bulkFramesSeen atomic.Int64
	var smallDataSeen atomic.Int64
	var udpSeen atomic.Int64
	var rekeySeen atomic.Int64
	var srvDecodeErr atomic.Value

	var recvMu sync.Mutex
	streamRecv := make(map[uint32]*bytes.Buffer)
	udpPayloads := make([]string, 0, 8)
	srvDone := make(chan struct{})

	go func() {
		defer close(srvDone)
		br := bufio.NewReaderSize(pSrv, 64*1024)
		for {
			ft, sid, payload, _, rErr := sRx.OpenFrame(br, nil)
			if rErr != nil {
				if !errors.Is(rErr, io.EOF) && !errors.Is(rErr, io.ErrClosedPipe) && !errors.Is(rErr, net.ErrClosed) {
					srvDecodeErr.CompareAndSwap("", fmt.Sprintf("OpenFrame error: %v", rErr))
				}
				return
			}
			switch ft {
			case FrameRekey:
				if err := sRx.Rekey(payload); err != nil {
					srvDecodeErr.CompareAndSwap("", fmt.Sprintf("Rekey error: %v", err))
					return
				}
				rekeySeen.Add(1)
			case FrameSynTCP:
				sendSrvFrame(FrameSynAck, sid, nil)
			case FramePing:
				sendSrvFrame(FramePong, sid, payload)
			case FrameData:
				recvMu.Lock()
				buf := streamRecv[sid]
				if buf == nil {
					buf = &bytes.Buffer{}
					streamRecv[sid] = buf
				}
				buf.Write(payload)
				recvMu.Unlock()
				if len(payload) > QoSSmallDataThreshold {
					bulkFramesSeen.Add(1)
				} else {
					smallDataSeen.Add(1)
				}
			case FrameUDPData:
				if len(payload) >= 4 {
					hl := int(payload[0])
					if 1+hl+2 <= len(payload) {
						dgram := string(payload[1+hl+2:])
						recvMu.Lock()
						udpPayloads = append(udpPayloads, dgram)
						recvMu.Unlock()
					}
				}
				udpSeen.Add(1)
			case FrameFin:
				// Normal stream finish
			}
		}
	}()

	sess := NewClientMuxSession(pacedCli, bufio.NewReaderSize(pacedCli, 64*1024), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: "QoS-P4", Host: "10.0.0.1", Port: 443}, LicenseMetadata{Proto: "PWP-4"})

	const numBulkWriters = 4
	const bulkSize = 256 * 1024 // 16 frames of 16KB per writer => 64 bulk frames total
	expectedBulkTotal := int64(numBulkWriters * (bulkSize / QoSBulkSliceSize))

	bulkStreams := make([]*ClientMuxStream, numBulkWriters)
	bulkPayloads := make([][]byte, numBulkWriters)
	for i := 0; i < numBulkWriters; i++ {
		st, oErr := sess.OpenTCPStream(fmt.Sprintf("bulk-%d.example", i), 443, 2*time.Second)
		if oErr != nil {
			t.Fatalf("OpenTCPStream bulk-%d: %v", i, oErr)
		}
		bulkStreams[i] = st
		data := make([]byte, bulkSize)
		for j := range data {
			data[j] = byte((j*31 + i*17 + 7) & 0xFF)
		}
		bulkPayloads[i] = data
	}

	smallSt, err := sess.OpenTCPStream("interactive.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenTCPStream interactive: %v", err)
	}
	udpAssoc := sess.RegisterUDPHandler(func(string, int, []byte) {})

	var bulkWG sync.WaitGroup
	bulkErrCh := make(chan error, numBulkWriters)
	for i := 0; i < numBulkWriters; i++ {
		bulkWG.Add(1)
		go func(idx int) {
			defer bulkWG.Done()
			n, wErr := bulkStreams[idx].Write(bulkPayloads[idx])
			if wErr != nil {
				bulkErrCh <- fmt.Errorf("bulk writer %d err: %w", idx, wErr)
				return
			}
			if n != len(bulkPayloads[idx]) {
				bulkErrCh <- fmt.Errorf("bulk writer %d short write: %d != %d", idx, n, len(bulkPayloads[idx]))
			}
		}(i)
	}

	// Wait until bulk writers are actively saturating the paced connection.
	deadlineWait := time.Now().Add(2 * time.Second)
	for bulkFramesSeen.Load() < 4 {
		if time.Now().After(deadlineWait) {
			t.Fatalf("bulk writers never started within 2s (seen=%d)", bulkFramesSeen.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Fire fast-lane Ping + small <512B FrameData + FrameUDPData while bulk is mid-flight.
	const fastBurstCount = 6
	fastStart := time.Now()
	var fastWG sync.WaitGroup
	fastErrCh := make(chan error, fastBurstCount*3)
	smallExpected := make([]byte, 0, fastBurstCount*320)
	var smallExpectedMu sync.Mutex

	for i := 0; i < fastBurstCount; i++ {
		fastWG.Add(3)
		go func(idx int) {
			defer fastWG.Done()
			if _, pErr := sess.Ping(2 * time.Second); pErr != nil {
				fastErrCh <- fmt.Errorf("ping %d: %w", idx, pErr)
			}
		}(i)
		go func(idx int) {
			defer fastWG.Done()
			msg := bytes.Repeat([]byte{byte('a' + idx)}, 300)
			if _, wErr := smallSt.Write(msg); wErr != nil {
				fastErrCh <- fmt.Errorf("small Write %d: %w", idx, wErr)
				return
			}
			smallExpectedMu.Lock()
			smallExpected = append(smallExpected, msg...)
			smallExpectedMu.Unlock()
		}(i)
		go func(idx int) {
			defer fastWG.Done()
			pkt := []byte(fmt.Sprintf("rtp-voice-%02d", idx))
			if uErr := sess.SendUDP(udpAssoc, "voice.discord.gg", 50001, pkt); uErr != nil {
				fastErrCh <- fmt.Errorf("SendUDP %d: %w", idx, uErr)
			}
		}(i)
	}

	fastWG.Wait()
	fastElapsed := time.Since(fastStart)
	bulkSeenAtFastDone := bulkFramesSeen.Load()

	close(fastErrCh)
	for ferr := range fastErrCh {
		t.Fatalf("fast-lane error: %v", ferr)
	}

	// Fast-lane burst must finish before all 64 paced bulk frames drain (proving preemption).
	if bulkSeenAtFastDone >= expectedBulkTotal {
		t.Fatalf("fast-lane waited for all %d bulk frames to finish (bulkSeenAtFastDone=%d, fastElapsed=%v)", expectedBulkTotal, bulkSeenAtFastDone, fastElapsed)
	}
	if fastElapsed > 150*time.Millisecond {
		t.Fatalf("fast-lane preemption took too long: %v (bulkSeenAtFastDone=%d/%d)", fastElapsed, bulkSeenAtFastDone, expectedBulkTotal)
	}

	bulkWG.Wait()
	close(bulkErrCh)
	for berr := range bulkErrCh {
		t.Fatalf("bulk error: %v", berr)
	}

	// Wait briefly for server reader to process final buffered frames.
	waitSrv := time.Now().Add(2 * time.Second)
	for bulkFramesSeen.Load() < expectedBulkTotal || smallDataSeen.Load() < fastBurstCount || udpSeen.Load() < fastBurstCount {
		if time.Now().After(waitSrv) {
			t.Fatalf("server missing frames: bulk=%d/%d small=%d/%d udp=%d/%d",
				bulkFramesSeen.Load(), expectedBulkTotal, smallDataSeen.Load(), fastBurstCount, udpSeen.Load(), fastBurstCount)
		}
		time.Sleep(2 * time.Millisecond)
	}

	if v := srvDecodeErr.Load(); v != nil {
		t.Fatalf("server decode failure (possible cipher nonce desync): %v", v)
	}
	if rekeySeen.Load() == 0 {
		t.Fatalf("expected at least 1 mid-flight PWP-4 FrameRekey to verify nonce sync across rekey")
	}

	recvMu.Lock()
	for i := 0; i < numBulkWriters; i++ {
		gotBuf := streamRecv[bulkStreams[i].id]
		if gotBuf == nil {
			recvMu.Unlock()
			t.Fatalf("missing received data for bulk stream %d", i)
		}
		gotHash := sha256.Sum256(gotBuf.Bytes())
		wantHash := sha256.Sum256(bulkPayloads[i])
		if gotHash != wantHash {
			recvMu.Unlock()
			t.Fatalf("bulk stream %d SHA-256 mismatch: got %s want %s (len %d vs %d)",
				i, hex.EncodeToString(gotHash[:]), hex.EncodeToString(wantHash[:]), gotBuf.Len(), len(bulkPayloads[i]))
		}
	}
	smallGot := streamRecv[smallSt.id]
	if smallGot == nil || smallGot.Len() != fastBurstCount*300 {
		recvMu.Unlock()
		t.Fatalf("small interactive stream bytes mismatch: got %v", smallGot)
	}
	if len(udpPayloads) != fastBurstCount {
		recvMu.Unlock()
		t.Fatalf("udp payloads count=%d, want %d", len(udpPayloads), fastBurstCount)
	}
	recvMu.Unlock()

	if sess.BulkLaneFrames() != expectedBulkTotal {
		t.Fatalf("BulkLaneFrames=%d, want %d", sess.BulkLaneFrames(), expectedBulkTotal)
	}
	if sess.FastLaneFrames() < int64(5+fastBurstCount*3) {
		t.Fatalf("FastLaneFrames=%d unexpectedly low", sess.FastLaneFrames())
	}

	_ = sess.Close()
	_ = pSrv.Close()
	<-srvDone

	// Verify no goroutine leaks after session + server teardown.
	leakDeadline := time.Now().Add(500 * time.Millisecond)
	for runtime.NumGoroutine() > baseGoroutines+1 && time.Now().Before(leakDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > baseGoroutines+2 {
		t.Fatalf("potential goroutine leak: before=%d after=%d", baseGoroutines, after)
	}
}

func TestQoSStarvationGuardEightToOneAndCloseWakeup(t *testing.T) {
	sched := newMuxPriorityScheduler()

	// Hold the write slot so 1 bulk caller and 20 fast callers queue simultaneously.
	if !sched.acquire(false) {
		t.Fatal("initial acquire failed")
	}

	var mu sync.Mutex
	order := make([]string, 0, 21)
	var wg sync.WaitGroup

	// Queue 1 bulk caller.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !sched.acquire(false) {
			return
		}
		mu.Lock()
		order = append(order, "B")
		mu.Unlock()
		sched.release()
	}()

	// Queue 16 fast callers; each yields 1ms inside write so waiting fast queue drains sequentially.
	const fastCount = 16
	for i := 0; i < fastCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !sched.acquire(true) {
				return
			}
			mu.Lock()
			order = append(order, "F")
			mu.Unlock()
			time.Sleep(200 * time.Microsecond)
			sched.release()
		}()
	}

	// Wait until all 17 waiters are parked on the scheduler conditions.
	waitQueued := time.Now().Add(time.Second)
	for {
		sched.mu.Lock()
		fw, bw := sched.fastWaiting, sched.bulkWaiting
		sched.mu.Unlock()
		if fw == fastCount && bw == 1 {
			break
		}
		if time.Now().After(waitQueued) {
			t.Fatalf("waiters did not queue: fastWaiting=%d bulkWaiting=%d", fw, bw)
		}
		time.Sleep(time.Millisecond)
	}

	// Release initial hold and verify "B" runs after <= QoSMaxConsecutiveFast (8) fast writes.
	sched.release()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(order) != fastCount+1 {
		t.Fatalf("order length=%d, want %d (%v)", len(order), fastCount+1, order)
	}
	bulkIdx := -1
	for i, tag := range order {
		if tag == "B" {
			bulkIdx = i
			break
		}
	}
	if bulkIdx < 0 || bulkIdx > QoSMaxConsecutiveFast {
		t.Fatalf("starvation guard violated: bulk ran at index %d (max consecutive fast=%d), order=%v", bulkIdx, QoSMaxConsecutiveFast, order)
	}

	// Test clean wakeup on Close() when waiters are blocked.
	if !sched.acquire(true) {
		t.Fatal("acquire before close test failed")
	}
	unblocked := make(chan bool, 6)
	for i := 0; i < 3; i++ {
		go func() { unblocked <- sched.acquire(true) }()
		go func() { unblocked <- sched.acquire(false) }()
	}
	waitParked := time.Now().Add(time.Second)
	for {
		sched.mu.Lock()
		fw, bw := sched.fastWaiting, sched.bulkWaiting
		sched.mu.Unlock()
		if fw == 3 && bw == 3 {
			break
		}
		if time.Now().After(waitParked) {
			t.Fatalf("close-test waiters did not park: fw=%d bw=%d", fw, bw)
		}
		time.Sleep(time.Millisecond)
	}
	sched.close()
	sched.release()
	for i := 0; i < 6; i++ {
		select {
		case ok := <-unblocked:
			if ok {
				t.Fatal("expected blocked waiter to return false after scheduler.close()")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("timed out waiting for blocked waiter wakeup on close")
		}
	}
}

func newTestPoolSession(t *testing.T, name string) (*ClientMuxSession, func()) {
	t.Helper()
	pCli, pSrv := net.Pipe()
	mat, err := DerivePWP4KeyMaterial("pool-secret-"+name, "cli", "srv")
	if err != nil {
		t.Fatalf("DerivePWP4KeyMaterial: %v", err)
	}
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	sTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	go func() {
		br := bufio.NewReader(pSrv)
		for {
			ft, sid, _, _, rErr := sRx.OpenFrame(br, nil)
			if rErr != nil {
				return
			}
			if ft == FrameSynTCP {
				wire, _ := sTx.SealFrame(FrameSynAck, sid, nil)
				_, _ = pSrv.Write(wire)
			}
		}
	}()

	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: name, Host: "10.0.0.1", Port: 443}, LicenseMetadata{Proto: "PWP-4"})
	cleanup := func() {
		_ = sess.Close()
		_ = pSrv.Close()
	}
	return sess, cleanup
}

func TestMediaSessionPoolLeastStreamsScaleAndCloseAll(t *testing.T) {
	pool := NewMediaSessionPool()
	if pool.Size() != 0 || pool.TotalStreams() != 0 {
		t.Fatalf("new pool not empty: size=%d streams=%d", pool.Size(), pool.TotalStreams())
	}
	if sess, scale := pool.PickBest(); sess != nil || !scale {
		t.Fatalf("empty pool PickBest=(%v,%v), want (nil,true)", sess, scale)
	}

	s1, c1 := newTestPoolSession(t, "media-1")
	defer c1()
	s2, c2 := newTestPoolSession(t, "media-2")
	defer c2()
	s3, c3 := newTestPoolSession(t, "media-3")
	defer c3()
	s4, c4 := newTestPoolSession(t, "media-4")
	defer c4()

	pool.Add(nil)
	pool.Add(s1)
	pool.Add(s1) // duplicate ignored
	if pool.Size() != 1 {
		t.Fatalf("Size=%d, want 1", pool.Size())
	}

	// Open 3 streams on s1 -> below threshold 4, shouldScale must be false.
	for i := 0; i < 3; i++ {
		if _, err := s1.OpenTCPStream("cdn.example", 443, time.Second); err != nil {
			t.Fatalf("s1 OpenTCPStream %d: %v", i, err)
		}
	}
	best, scale := pool.PickBest()
	if best != s1 || scale {
		t.Fatalf("at 3 streams: best=%v scale=%v, want (s1,false)", best, scale)
	}

	// 4th stream on s1 hits MediaPoolScaleThreshold (4) -> shouldScale=true!
	if _, err := s1.OpenTCPStream("cdn.example", 443, time.Second); err != nil {
		t.Fatalf("s1 OpenTCPStream 4th: %v", err)
	}
	best, scale = pool.PickBest()
	if best != s1 || !scale {
		t.Fatalf("at 4 streams: best=%v scale=%v, want (s1,true)", best, scale)
	}

	// Add s2 (0 streams) -> PickBest picks s2 (least streams) and shouldScale=false.
	pool.Add(s2)
	if pool.Size() != 2 || pool.TotalStreams() != 4 {
		t.Fatalf("pool size=%d totalStreams=%d, want (2,4)", pool.Size(), pool.TotalStreams())
	}
	best, scale = pool.PickBest()
	if best != s2 || scale {
		t.Fatalf("with s2(0) and s1(4): best=%v scale=%v, want (s2,false)", best, scale)
	}

	// Load s2 to 4 streams -> all live sessions >= 4 and len=2 < 3 => shouldScale=true.
	for i := 0; i < 4; i++ {
		if _, err := s2.OpenTCPStream("cdn.example", 443, time.Second); err != nil {
			t.Fatalf("s2 OpenTCPStream %d: %v", i, err)
		}
	}
	if _, scale = pool.PickBest(); !scale {
		t.Fatal("expected shouldScale=true when s1(4) and s2(4) with Size=2 < 3")
	}

	// Add s3 (0 streams) and load to 4 streams -> Size=3 == MaxMediaPoolConns => shouldScale=false.
	pool.Add(s3)
	for i := 0; i < 4; i++ {
		if _, err := s3.OpenTCPStream("cdn.example", 443, time.Second); err != nil {
			t.Fatalf("s3 OpenTCPStream %d: %v", i, err)
		}
	}
	if pool.Size() != 3 || pool.TotalStreams() != 12 {
		t.Fatalf("pool size=%d totalStreams=%d, want (3,12)", pool.Size(), pool.TotalStreams())
	}
	if best, scale = pool.PickBest(); best == nil || scale {
		t.Fatalf("at MaxMediaPoolConns=3: best=%v scale=%v, want non-nil, false", best, scale)
	}

	// Adding s4 while 3 live sessions exist is capped at MaxMediaPoolConns.
	pool.Add(s4)
	if pool.Size() != 3 {
		t.Fatalf("pool exceeded MaxMediaPoolConns: size=%d", pool.Size())
	}

	// Closing s2 and calling PruneClosed removes s2 and allows scaling again.
	_ = s2.Close()
	pool.PruneClosed()
	if pool.Size() != 2 || pool.TotalStreams() != 8 {
		t.Fatalf("after closing s2: size=%d totalStreams=%d, want (2,8)", pool.Size(), pool.TotalStreams())
	}
	if _, scale = pool.PickBest(); !scale {
		t.Fatal("expected shouldScale=true after pruning s2 down to 2 live sessions with 4 streams each")
	}

	// CloseAll closes all remaining sessions and empties the pool.
	pool.CloseAll()
	if pool.Size() != 0 || pool.TotalStreams() != 0 {
		t.Fatalf("after CloseAll: size=%d totalStreams=%d, want (0,0)", pool.Size(), pool.TotalStreams())
	}
	if !s1.IsClosed() || !s3.IsClosed() {
		t.Fatalf("expected s1 and s3 to be closed after CloseAll (s1=%v s3=%v)", s1.IsClosed(), s3.IsClosed())
	}
}

func TestQoSPWP3IntegrityAndSessionCloseUnblocksWriters(t *testing.T) {
	// 1. Verify PWP-3 stream cipher stays synchronized across concurrent fast & bulk writes.
	pCli, pSrv := net.Pipe()
	secret := "pwp3-qos-secret"
	cCodec := &pwp3Codec{
		tx: NewPixelStreamCipher(secret, "c2s"),
		rx: NewPixelStreamCipher(secret, "s2c"),
	}
	sCodec := &pwp3Codec{
		rx: NewPixelStreamCipher(secret, "c2s"),
		tx: NewPixelStreamCipher(secret, "s2c"),
	}

	gotCh := make(chan []byte, 4)
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		br := bufio.NewReaderSize(pSrv, 64*1024)
		recv := make(map[uint32]*bytes.Buffer)
		for {
			ft, sid, payload, rErr := sCodec.ReadFrame(br)
			if rErr != nil {
				return
			}
			switch ft {
			case FrameSynTCP:
				_ = sCodec.WriteFrame(pSrv, FrameSynAck, sid, 0, nil, 0)
			case FramePing:
				_ = sCodec.WriteFrame(pSrv, FramePong, sid, 0, payload, 0)
			case FrameData:
				b := recv[sid]
				if b == nil {
					b = &bytes.Buffer{}
					recv[sid] = b
				}
				b.Write(payload)
			case FrameFin:
				if b := recv[sid]; b != nil {
					gotCh <- b.Bytes()
				}
			}
		}
	}()

	sess := NewClientMuxSession(pCli, bufio.NewReaderSize(pCli, 64*1024), cCodec, NodeConfig{Name: "PWP3-QoS", Host: "10.0.0.1", Port: 443}, LicenseMetadata{Proto: "PWP-3"})
	stBulk, err := sess.OpenTCPStream("bulk3.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenTCPStream PWP-3: %v", err)
	}

	payload := bytes.Repeat([]byte{0x7E}, 48*1024)
	var wg sync.WaitGroup
	wg.Add(2)
	var pingErr, bulkErr error
	go func() {
		defer wg.Done()
		_, bulkErr = stBulk.Write(payload)
		if bulkErr == nil {
			bulkErr = stBulk.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, pingErr = sess.Ping(2 * time.Second)
	}()
	wg.Wait()
	if bulkErr != nil || pingErr != nil {
		t.Fatalf("PWP-3 concurrent write/ping failed: bulkErr=%v pingErr=%v", bulkErr, pingErr)
	}

	select {
	case got := <-gotCh:
		if !bytes.Equal(got, payload) {
			t.Fatalf("PWP-3 payload corrupted: got %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PWP-3 stream payload")
	}
	_ = sess.Close()
	_ = pSrv.Close()
	<-srvDone

	// 2. Verify ClientMuxSession.Close unblocks stalled active + queued writeFrame callers cleanly.
	sCli, sSrv := net.Pipe()
	defer sSrv.Close()
	stalled := NewClientMuxSession(sCli, bufio.NewReader(sCli), &pwp3Codec{
		tx: NewPixelStreamCipher("close", "c2s"),
		rx: NewPixelStreamCipher("close", "s2c"),
	}, NodeConfig{Name: "StallClose", Host: "10.0.0.2", Port: 443}, LicenseMetadata{Proto: "PWP-3"})

	errCh := make(chan error, 4)
	bulkFrame := bytes.Repeat([]byte{0x11}, 8192)
	for i := 0; i < 4; i++ {
		go func(idx int) {
			if idx%2 == 0 {
				errCh <- stalled.writeFrame(FrameData, uint32(idx+1), 0, bulkFrame, 0)
			} else {
				errCh <- stalled.writeFrame(FramePing, uint32(idx+1), 0, []byte("p"), 0)
			}
		}(i)
	}
	time.Sleep(25 * time.Millisecond)
	_ = stalled.Close()

	for i := 0; i < 4; i++ {
		select {
		case wErr := <-errCh:
			if wErr == nil {
				t.Fatal("expected writeFrame error after Close() on stalled pipe")
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for stalled writeFrame caller to unblock on Close()")
		}
	}
}

