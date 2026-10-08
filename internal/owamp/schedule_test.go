package owamp

import (
	"encoding/hex"
	"testing"
)

// TestExpRandVectors checks the exponential deviates against RFC 4656
// Appendix B: every implementation must produce exactly these sums, or
// receivers discard the sender's packets as off-schedule.
func TestExpRandVectors(t *testing.T) {
	vectors := []struct {
		sid string
		sum uint64
	}{
		{"2872979303ab47eeac028dab3829dab2", 0x000f4479bd317381},
		{"0102030405060708090a0b0c0d0e0f00", 0x000f433686466a62},
		{"deadbeefdeadbeefdeadbeefdeadbeef", 0x000f416c8884d2d3},
		{"feed0feed1feed2feed3feed4feed5ab", 0x000f3f0b4b416ec8},
	}
	for _, v := range vectors {
		var sid SID
		if _, err := hex.Decode(sid[:], []byte(v.sid)); err != nil {
			t.Fatal(err)
		}
		r := newExpRand(sid)
		var sum Timestamp
		for range 1000000 {
			sum += r.next()
		}
		if uint64(sum) != v.sum {
			t.Errorf("SID %s: sum = %#016x, want %#016x", v.sid, uint64(sum), v.sum)
		}
	}
}

// TestSendTimesFollowSlots checks that slots are used cyclically and that
// packet n is sent after the waits of slots 0..n.
func TestSendTimesFollowSlots(t *testing.T) {
	var sid SID
	start := FromSeconds(1000)
	slots := []Slot{{SlotFixed, FromSeconds(1)}, {SlotFixed, FromSeconds(0.5)}}
	times := NewSendTimes(start, sid, slots)
	want := []float64{1001, 1001.5, 1002.5, 1003}
	for i, w := range want {
		if got := times.At(uint32(i)).Seconds(); got != w {
			t.Errorf("packet %d at %v, want %v", i, got, w)
		}
	}
}
