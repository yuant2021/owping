package owamp

import (
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// spinWindow is how long before a scheduled send the sender stops
	// sleeping and busy-waits, absorbing nanosleep wake-up latency.
	spinWindow = 250 * time.Microsecond
	// maxSleep bounds each sleep so a stop request is noticed promptly.
	maxSleep = 100 * time.Millisecond
)

// sender transmits the packets of one OWAMP-Test session.
type sender struct {
	conn        *net.UDPConn
	dst         netip.AddrPort
	req         *TestRequest
	codec       *packetCodec
	endDelay    time.Duration
	zeroPadding bool
	release     func() // called once the sender is finished or discarded
	closeOnce   sync.Once

	stopped atomic.Bool
	done    chan struct{}

	// Valid once done is closed.
	nextSeqno uint32
	skips     []SkipRange
}

func newSender(conn *net.UDPConn, dst netip.AddrPort, req *TestRequest, mode Mode, keys *testKeys, opts EndpointOptions) *sender {
	return &sender{
		conn:        conn,
		dst:         dst,
		req:         req,
		codec:       newPacketCodec(mode, keys),
		endDelay:    opts.EndDelay,
		zeroPadding: opts.ZeroPadding,
		done:        make(chan struct{}),
	}
}

func (s *sender) start() { go s.run() }

// stop ends the session early; the sender reports how far it got.
func (s *sender) stop() { s.stopped.Store(true) }

// close releases the sender's socket and resources; run calls it when it
// returns, and a session that never starts calls it directly.
func (s *sender) close() {
	s.closeOnce.Do(func() {
		s.conn.Close()
		if s.release != nil {
			s.release()
		}
	})
}

func (s *sender) run() {
	defer close(s.done)
	defer s.close()

	// Sleeping with nanosleep on a dedicated thread with minimal timer
	// slack keeps send times within microseconds of the schedule. The
	// thread is discarded when the goroutine exits still locked.
	runtime.LockOSThread()
	setTimerSlack()

	pkt := make([]byte, testPacketSize(s.codec.mode, s.req.Padding))
	padding := pkt[testPacketSize(s.codec.mode, 0):]
	rng := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	timeout := s.req.Timeout.Duration()
	sched := NewSchedule(s.req.SID, s.req.Slots)

	at := s.req.Start
	seq := uint32(0)
	for ; seq < s.req.Packets; seq++ {
		at += sched.Next()
		target := at.Time()
		if !s.zeroPadding {
			fillRandom(rng, padding) // RFC 4656 §4.1.2: padding SHOULD be pseudo-random
		}
		s.codec.sealSeq(pkt, seq)
		if !s.sleepUntil(target) {
			break
		}
		if !s.send(pkt, target.Add(timeout)) {
			s.skip(seq)
		}
	}
	s.nextSeqno = seq
	if seq == s.req.Packets {
		// Hold Stop-Sessions until the receiver has had Timeout to
		// collect the last packet (RFC 4656 §3.8).
		s.sleepUntil(at.Time().Add(timeout + s.endDelay))
	}
}

// send timestamps and transmits pkt unless it is already later than
// deadline, in which case the packet must not be sent (RFC 4656 §4.1.1).
func (s *sender) send(pkt []byte, deadline time.Time) bool {
	for {
		now, est := Now()
		if now.After(deadline) {
			return false
		}
		s.codec.sealTime(pkt, TimestampFromTime(now), est)
		_, err := s.conn.WriteToUDPAddrPort(pkt, s.dst)
		if !errors.Is(err, syscall.ENOBUFS) {
			// Other errors leave the packet to be counted as lost.
			return true
		}
		nanosleep(10 * time.Microsecond)
	}
}

// sleepUntil waits until the wall-clock time t and reports false if the
// session was stopped first.
func (s *sender) sleepUntil(t time.Time) bool {
	for !s.stopped.Load() {
		d := time.Until(t)
		if d <= 0 {
			return true
		}
		if d > spinWindow {
			nanosleep(min(d-spinWindow, maxSleep))
			continue
		}
		for time.Now().Before(t) {
		}
		return true
	}
	return false
}

func (s *sender) skip(seq uint32) {
	if n := len(s.skips); n > 0 && s.skips[n-1].Last+1 == seq {
		s.skips[n-1].Last = seq
		return
	}
	s.skips = append(s.skips, SkipRange{First: seq, Last: seq})
}

func fillRandom(rng *rand.Rand, b []byte) {
	for len(b) >= 8 {
		putUint64(b, rng.Uint64())
		b = b[8:]
	}
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
}
