package owamp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// SlotType is the kind of a send-schedule slot (RFC 4656 §3.6).
type SlotType uint8

const (
	SlotExponential SlotType = 0 // exponentially distributed wait with the given mean
	SlotFixed       SlotType = 1 // fixed wait
)

// Slot is one entry of a cyclic send schedule.
type Slot struct {
	Type  SlotType
	Value Timestamp // mean (exponential) or wait time (fixed)
}

// q holds the constants Q[1..11] of RFC 4656 §5.2 scaled by 2^32; index 0 is
// a placeholder so indices match the RFC.
var q = [12]uint64{
	0,
	0xB17217F8, 0xEEF193F7, 0xFD271862, 0xFF9D6DD0, 0xFFF4CFD0, 0xFFFEE819,
	0xFFFFE7FF, 0xFFFFFE2B, 0xFFFFFFE0, 0xFFFFFFFE, 0xFFFFFFFF,
}

const ln2 = 0xB17217F8 // Q[1]

// expRand produces the reproducible exponential deviates of RFC 4656 §5:
// algorithm Unif (AES-128 in counter mode keyed with the SID) feeding
// Knuth's algorithm 3.4.1.S. Every implementation must produce exactly the
// same sequence, or receivers will discard packets as off-schedule.
type expRand struct {
	block   cipher.Block
	counter [16]byte
	out     [16]byte
}

func newExpRand(seed SID) *expRand {
	block, err := aes.NewCipher(seed[:])
	if err != nil {
		panic(err) // unreachable: the key is always 16 bytes
	}
	return &expRand{block: block}
}

// uniform returns the next 32-bit uniform value (steps U2–U4).
func (r *expRand) uniform() uint64 {
	i := r.counter[15] & 3
	if i == 0 {
		r.block.Encrypt(r.out[:], r.counter[:])
	}
	for j := 15; j >= 0; j-- {
		r.counter[j]++
		if r.counter[j] != 0 {
			break
		}
	}
	return uint64(binary.BigEndian.Uint32(r.out[4*i:]))
}

// next returns an exponential deviate with mean 1 (algorithm S).
func (r *expRand) next() Timestamp {
	// S1: locate the first zero bit and shift it off.
	u := r.uniform()
	var j uint64
	for u&0x80000000 != 0 && j < 32 {
		u <<= 1
		j++
	}
	u = (u << 1) & 0xffffffff
	bigJ := Timestamp(j << 32)

	// S2: immediate acceptance.
	if u < ln2 {
		return mul(bigJ, ln2) + Timestamp(u)
	}

	// S3: minimize over k new uniforms.
	k := 2
	for ; k < len(q); k++ {
		if u < q[k] {
			break
		}
	}
	v := r.uniform()
	for i := 2; i <= k; i++ {
		if t := r.uniform(); t < v {
			v = t
		}
	}

	// S4.
	return mul(bigJ+Timestamp(v), ln2)
}

// Schedule yields the waits between consecutive test packets.
type Schedule struct {
	slots []Slot
	rng   *expRand
	i     int
}

// NewSchedule returns the schedule of a session; slots must not be empty.
func NewSchedule(sid SID, slots []Slot) *Schedule {
	return &Schedule{slots: slots, rng: newExpRand(sid)}
}

// Next returns the wait before the next packet.
func (s *Schedule) Next() Timestamp {
	slot := s.slots[s.i%len(s.slots)]
	s.i++
	if slot.Type == SlotExponential {
		return mul(s.rng.next(), slot.Value)
	}
	return slot.Value
}

// SendTimes lazily materializes the absolute scheduled send times of a
// session: packet n is sent after the waits of slots 0..n (RFC 4656 §3.6).
type SendTimes struct {
	sched *Schedule
	last  Timestamp
	times []Timestamp
}

// NewSendTimes returns the send-time table of a session.
func NewSendTimes(start Timestamp, sid SID, slots []Slot) *SendTimes {
	return &SendTimes{sched: NewSchedule(sid, slots), last: start}
}

// At returns the scheduled send time of packet seq.
func (t *SendTimes) At(seq uint32) Timestamp {
	for uint32(len(t.times)) <= seq {
		t.last += t.sched.Next()
		t.times = append(t.times, t.last)
	}
	return t.times[seq]
}

// MeanInterval returns the average wait over one schedule cycle.
func MeanInterval(slots []Slot) float64 {
	if len(slots) == 0 {
		return 0
	}
	var sum float64
	for _, s := range slots {
		sum += s.Value.Seconds()
	}
	return sum / float64(len(slots))
}
