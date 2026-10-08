package owamp

import (
	"testing"
	"time"
)

// TestWithinSpan checks the server's session length limit against the
// actual schedule: a long first slot must not hide behind many short slots
// that are never used.
func TestWithinSpan(t *testing.T) {
	now := TimestampFromTime(time.Now())
	day := FromDuration(24 * time.Hour)
	unused := make([]Slot, 29) // fixed zero waits after the first slot
	for i := range unused {
		unused[i] = Slot{SlotFixed, 0}
	}
	cases := []struct {
		name string
		req  TestRequest
		want bool
	}{
		{"owping defaults", TestRequest{Packets: 100, Start: now + FromSeconds(1), Timeout: FromSeconds(2),
			Slots: []Slot{{SlotExponential, FromSeconds(0.1)}}}, true},
		{"first slot of 30 days behind unused slots", TestRequest{Packets: 1, Start: now,
			Slots: append([]Slot{{SlotFixed, 30 * day}}, unused...)}, false},
		{"schedule plus timeout too long", TestRequest{Packets: 2, Start: now, Timeout: day / 2,
			Slots: []Slot{{SlotFixed, day / 3}}}, false},
		{"start too far ahead", TestRequest{Packets: 1, Start: now + 2*day,
			Slots: []Slot{{SlotFixed, 0}}}, false},
	}
	for _, c := range cases {
		if got := withinSpan(&c.req, now); got != c.want {
			t.Errorf("%s: withinSpan = %v, want %v", c.name, got, c.want)
		}
	}
}
