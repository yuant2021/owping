// Package stats summarizes OWAMP session data the way owping reports it.
package stats

import (
	"math"
	"net/netip"
	"sort"

	"github.com/yuant2021/owping/internal/owamp"
)

// Endpoint is one side of a session as displayed.
type Endpoint struct {
	Host string         // shown in brackets: a host name or address
	Addr netip.AddrPort // the address and port actually used
}

// Summary holds the statistics of one test session.
type Summary struct {
	Data     *owamp.SessionData
	From, To Endpoint

	Sent, Lost, Dups uint32
	Sync             bool    // every timestamp came from a synchronized clock
	MaxErr           float64 // largest send+receive error estimate, seconds

	// Scheduled send times of the first and last packet considered.
	First, Last owamp.Timestamp

	// Over all arrivals including duplicates, seconds; NaN without data.
	MinDelay, MaxDelay float64

	delays []float64   // first arrival of each packet, sorted
	TTLs   [256]uint32 // TTL / hop limit of first arrivals
	reord  []uint32    // reord[j]: arrivals that were (j+1)-reordered
	nArriv uint32      // arrivals considered for reordering
}

// Summarize computes the statistics of d. Packets inside skip ranges and
// records inconsistent with earlier ones are ignored, as owping does.
func Summarize(d *owamp.SessionData, from, to Endpoint) *Summary {
	req := &d.Request
	n := req.Packets
	s := &Summary{
		Data:     d,
		From:     from,
		To:       to,
		Sync:     true,
		MinDelay: math.NaN(),
		MaxDelay: math.NaN(),
	}
	seen := make([]uint32, n)
	lost := make([]bool, n)
	window := reorderWindow(req)
	ring := make([]uint32, window)
	s.reord = make([]uint32, window)
	ri := 0
	last := uint32(0)

	for i := range d.Records {
		r := &d.Records[i]
		if r.Seq >= n || skipped(d.Skips, r.Seq) {
			continue
		}
		last = max(last, r.Seq)
		if r.Lost() {
			if lost[r.Seq] || seen[r.Seq] > 0 {
				continue
			}
			lost[r.Seq] = true
			s.Sent++
			s.Lost++
			if !r.RecvErr.Synchronized() {
				s.Sync = false
			}
			s.MaxErr = max(s.MaxErr, r.RecvErr.Seconds())
			continue
		}
		if lost[r.Seq] {
			continue
		}
		seen[r.Seq]++
		if seen[r.Seq] == 1 {
			s.Sent++
		} else {
			s.Dups++
		}

		// n-reordering (RFC 4737 §5.3): an arrival is j-reordered if its
		// sequence number is below those of the j previous arrivals.
		for j := 0; j < min(int(s.nArriv), window) && r.Seq < ring[(ri-j-1+window)%window]; j++ {
			s.reord[j]++
		}
		ring[ri] = r.Seq
		ri = (ri + 1) % window
		s.nArriv++

		if !r.SendErr.Synchronized() || !r.RecvErr.Synchronized() {
			s.Sync = false
		}
		s.MaxErr = max(s.MaxErr, r.SendErr.Seconds()+r.RecvErr.Seconds())
		delay := Delay(r)
		if !(delay >= s.MinDelay) {
			s.MinDelay = delay
		}
		if !(delay <= s.MaxDelay) {
			s.MaxDelay = delay
		}
		if seen[r.Seq] == 1 {
			s.delays = append(s.delays, delay)
			s.TTLs[r.TTL]++
		}
	}
	sort.Float64s(s.delays)
	if n > 0 {
		times := owamp.NewSendTimes(req.Start, req.SID, req.Slots)
		s.First = times.At(0)
		s.Last = times.At(last)
	}
	return s
}

// Delay returns the one-way delay of a received packet in seconds,
// computed in fixed point so no precision is lost to the large absolute
// timestamps.
func Delay(r *owamp.Record) float64 {
	return float64(int64(r.Recv-r.Send)) / (1 << 32)
}

// Percentile returns the p-quantile (0 < p <= 1) of the first-arrival
// delays using the nearest-rank method.
func (s *Summary) Percentile(p float64) (float64, bool) {
	if len(s.delays) == 0 {
		return 0, false
	}
	i := int(math.Ceil(p*float64(len(s.delays)))) - 1
	return s.delays[max(0, min(i, len(s.delays)-1))], true
}

// Jitter returns the delay variation P95-P50 owping reports.
func (s *Summary) Jitter() (float64, bool) {
	p95, ok := s.Percentile(0.95)
	if !ok {
		return 0, false
	}
	p50, _ := s.Percentile(0.5)
	return p95 - p50, true
}

// ttlRange returns the number of distinct TTL values and their extremes.
func (s *Summary) ttlRange() (count int, lo, hi uint8) {
	lo, hi = 255, 0
	for ttl, c := range s.TTLs {
		if c == 0 {
			continue
		}
		count++
		lo = min(lo, uint8(ttl))
		hi = max(hi, uint8(ttl))
	}
	return count, lo, hi
}

// reorderWindow is owping's reordering history length: the number of
// packets expected within one Timeout (times a safety factor of 3.5), at
// least 10 and at most the session size.
func reorderWindow(req *owamp.TestRequest) int {
	w := 0.0
	if mean := owamp.MeanInterval(req.Slots); mean > 0 {
		w = req.Timeout.Seconds() / mean * 3.5
	}
	return max(10, int(min(w, float64(max(req.Packets, 10)))))
}

func skipped(skips []owamp.SkipRange, seq uint32) bool {
	for _, r := range skips {
		if seq >= r.First && seq <= r.Last {
			return true
		}
	}
	return false
}
