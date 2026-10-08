package stats

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"owping/internal/owamp"
)

// TestSummarize checks loss, duplicate, reordering, delay and TTL
// accounting on a hand-built session: packet 1 arrives after 2 and is
// duplicated, packet 3 is lost, and packets 4-5 were skipped by the sender
// so their records must not count.
func TestSummarize(t *testing.T) {
	start := owamp.FromSeconds(3_900_000_000)
	sec := owamp.FromSeconds(1)
	ms := func(v float64) owamp.Timestamp { return owamp.FromSeconds(v / 1000) }
	synced := owamp.NewErrorEstimate(1, true)
	rx := func(seq uint32, delay owamp.Timestamp, ttl uint8) owamp.Record {
		send := start + owamp.Timestamp(seq+1)*sec
		return owamp.Record{Seq: seq, SendErr: synced, RecvErr: synced, Send: send, Recv: send + delay, TTL: ttl}
	}
	lost := func(seq uint32) owamp.Record {
		return owamp.Record{Seq: seq, SendErr: 1, RecvErr: synced, Send: start + owamp.Timestamp(seq+1)*sec, TTL: 255}
	}
	d := &owamp.SessionData{
		Request: owamp.TestRequest{
			Packets: 10,
			Start:   start,
			Timeout: 2 * sec,
			Slots:   []owamp.Slot{{Type: owamp.SlotFixed, Value: sec}},
		},
		Finished:  true,
		NextSeqno: 10,
		Skips:     []owamp.SkipRange{{First: 4, Last: 5}},
		Records: []owamp.Record{
			rx(0, ms(1), 250), rx(2, ms(3), 250), rx(1, ms(2), 250), rx(1, ms(5), 250),
			lost(3), lost(4), rx(5, ms(9), 250),
			rx(6, ms(4), 249), rx(7, ms(4), 250), rx(8, ms(4), 250), rx(9, ms(4), 250),
		},
	}
	s := Summarize(d, Endpoint{Host: "a"}, Endpoint{Host: "b"})

	if s.Sent != 8 || s.Lost != 1 || s.Dups != 1 {
		t.Errorf("sent/lost/dups = %d/%d/%d, want 8/1/1", s.Sent, s.Lost, s.Dups)
	}
	near := func(got, want float64) bool { return math.Abs(got-want) < 1e-9 }
	if !near(s.MinDelay, 0.001) || !near(s.MaxDelay, 0.005) {
		t.Errorf("min/max delay = %v/%v, want 0.001/0.005 (duplicates included)", s.MinDelay, s.MaxDelay)
	}
	if m, _ := s.Percentile(0.5); !near(m, 0.004) {
		t.Errorf("median = %v, want 0.004 (first arrivals only)", m)
	}
	if s.reord[0] != 1 || s.reord[1] != 0 || s.nArriv != 8 {
		t.Errorf("reordering = %v over %d arrivals, want one 1-reordered of 8", s.reord[:2], s.nArriv)
	}

	var out bytes.Buffer
	units, _ := ParseUnits("m")
	if err := s.WriteSummary(&out, units, nil); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"8 sent, 1 lost (12.500%), 1 duplicates",
		"one-way delay min/median/max = 1/4/5 ms, (err=0.00201 ms)",
		"hops takes 2 values; min hops = 5, max hops = 6",
		"1-reordering = 12.500000%",
		"no 2-reordering",
	} {
		if !strings.Contains(out.String(), line+"\n") {
			t.Errorf("summary lacks %q:\n%s", line, out.String())
		}
	}
}
