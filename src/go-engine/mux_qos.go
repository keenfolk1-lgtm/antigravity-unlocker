package main

import (
	"sync"
	"sync/atomic"
)

const (
	// QoSSmallDataThreshold is the max payload length (bytes) for FrameData to ride the fast lane.
	QoSSmallDataThreshold = 2048
	// QoSBulkSliceSize caps per-frame FrameData payload size in ClientMuxStream.Write so fast-lane
	// control, UDP, and small interactive frames preempt between 16 KB bulk slices.
	QoSBulkSliceSize = 16384
	// QoSMaxConsecutiveFast limits consecutive fast-lane writes while bulk callers are waiting.
	QoSMaxConsecutiveFast = 8

	// MaxMediaPoolConns caps parallel PWP-4/PWP-3 mux connections for the media role.
	MaxMediaPoolConns = 3
	// MediaPoolScaleThreshold triggers scaling a new media pool connection once all live
	// sessions reach at least this many active streams.
	MediaPoolScaleThreshold = 4
)

func isFastLaneFrame(frameType byte, payloadLen int) bool {
	if frameType != FrameData {
		return true
	}
	return payloadLen <= QoSSmallDataThreshold
}

// muxPriorityScheduler coordinates two-lane (fast vs bulk) exclusive frame writes
// with a bounded starvation guard so bulk writers cannot be starved indefinitely.
type muxPriorityScheduler struct {
	mu              sync.Mutex
	fastCond        *sync.Cond
	bulkCond        *sync.Cond
	writing         bool
	closed          bool
	fastWaiting     int
	bulkWaiting     int
	consecutiveFast int
	fastFrames      atomic.Int64
	bulkFrames      atomic.Int64
}

func newMuxPriorityScheduler() *muxPriorityScheduler {
	s := &muxPriorityScheduler{}
	s.fastCond = sync.NewCond(&s.mu)
	s.bulkCond = sync.NewCond(&s.mu)
	return s
}

func (s *muxPriorityScheduler) canRunLocked(fast bool) bool {
	if s.writing {
		return false
	}
	if fast {
		return s.bulkWaiting == 0 || s.consecutiveFast < QoSMaxConsecutiveFast
	}
	return s.fastWaiting == 0 || s.consecutiveFast >= QoSMaxConsecutiveFast
}

func (s *muxPriorityScheduler) acquire(fast bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false
	}
	if s.canRunLocked(fast) {
		s.writing = true
		if fast {
			if s.consecutiveFast < QoSMaxConsecutiveFast {
				s.consecutiveFast++
			}
		} else {
			s.consecutiveFast = 0
		}
		return true
	}

	if fast {
		s.fastWaiting++
	} else {
		s.bulkWaiting++
	}
	for !s.closed && !s.canRunLocked(fast) {
		if fast {
			s.fastCond.Wait()
		} else {
			s.bulkCond.Wait()
		}
	}
	if fast {
		s.fastWaiting--
	} else {
		s.bulkWaiting--
	}
	if s.closed {
		return false
	}
	s.writing = true
	if fast {
		if s.consecutiveFast < QoSMaxConsecutiveFast {
			s.consecutiveFast++
		}
	} else {
		s.consecutiveFast = 0
	}
	return true
}

func (s *muxPriorityScheduler) release() {
	s.mu.Lock()
	s.writing = false
	if s.closed {
		s.fastCond.Broadcast()
		s.bulkCond.Broadcast()
		s.mu.Unlock()
		return
	}
	if s.bulkWaiting > 0 && (s.fastWaiting == 0 || s.consecutiveFast >= QoSMaxConsecutiveFast) {
		s.bulkCond.Signal()
	} else if s.fastWaiting > 0 {
		s.fastCond.Signal()
	}
	s.mu.Unlock()
}

func (s *muxPriorityScheduler) close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.fastCond.Broadcast()
		s.bulkCond.Broadcast()
	}
	s.mu.Unlock()
}

func (s *muxPriorityScheduler) recordSent(fast bool) {
	if fast {
		s.fastFrames.Add(1)
	} else {
		s.bulkFrames.Add(1)
	}
}

// MediaSessionPool balances media streams across up to MaxMediaPoolConns live mux sessions
// using least-active-streams selection and automatic scale-up signaling.
type MediaSessionPool struct {
	mu       sync.Mutex
	sessions []*ClientMuxSession
}

// NewMediaSessionPool creates an empty MediaSessionPool.
func NewMediaSessionPool() *MediaSessionPool {
	return &MediaSessionPool{}
}

func (p *MediaSessionPool) pruneLocked() {
	n := 0
	for _, s := range p.sessions {
		if s != nil && !s.IsClosed() {
			p.sessions[n] = s
			n++
		}
	}
	for i := n; i < len(p.sessions); i++ {
		p.sessions[i] = nil
	}
	p.sessions = p.sessions[:n]
}

// PickBest selects the live non-closed session with the fewest active streams.
// It returns shouldScale=true when the pool has 0 live sessions, or when all live
// sessions have at least MediaPoolScaleThreshold active streams while Size() < MaxMediaPoolConns.
func (p *MediaSessionPool) PickBest() (sess *ClientMuxSession, shouldScale bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneLocked()
	if len(p.sessions) == 0 {
		return nil, true
	}

	best := p.sessions[0]
	bestStreams := best.ActiveStreamCount()
	for _, s := range p.sessions[1:] {
		if cnt := s.ActiveStreamCount(); cnt < bestStreams {
			best = s
			bestStreams = cnt
		}
	}
	shouldScale = bestStreams >= MediaPoolScaleThreshold && len(p.sessions) < MaxMediaPoolConns
	return best, shouldScale
}

// Add registers a live session in the pool after pruning closed entries, ignoring duplicates
// and capping live entries at MaxMediaPoolConns.
func (p *MediaSessionPool) Add(sess *ClientMuxSession) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneLocked()
	if sess == nil || sess.IsClosed() {
		return
	}
	for _, existing := range p.sessions {
		if existing == sess {
			return
		}
	}
	if len(p.sessions) >= MaxMediaPoolConns {
		return
	}
	p.sessions = append(p.sessions, sess)
}

// PruneClosed removes any nil or closed sessions from the pool.
func (p *MediaSessionPool) PruneClosed() {
	p.mu.Lock()
	p.pruneLocked()
	p.mu.Unlock()
}

// CloseAll closes every session currently held in the pool and empties it.
func (p *MediaSessionPool) CloseAll() {
	p.mu.Lock()
	toClose := make([]*ClientMuxSession, len(p.sessions))
	copy(toClose, p.sessions)
	for i := range p.sessions {
		p.sessions[i] = nil
	}
	p.sessions = nil
	p.mu.Unlock()

	for _, s := range toClose {
		if s != nil {
			_ = s.Close()
		}
	}
}

// Size returns the number of live non-closed sessions currently in the pool.
func (p *MediaSessionPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneLocked()
	return len(p.sessions)
}

// TotalStreams returns the sum of ActiveStreamCount across all live sessions in the pool.
func (p *MediaSessionPool) TotalStreams() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneLocked()
	total := 0
	for _, s := range p.sessions {
		total += s.ActiveStreamCount()
	}
	return total
}
