package stats

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/yuant2021/owping/internal/owamp"
)

// Units selects the time unit of printed delays.
type Units struct {
	Factor float64 // multiplier from seconds
	Abbrev string
}

// ParseUnits parses owping's -n argument: n, u, m or s.
func ParseUnits(s string) (Units, error) {
	switch s {
	case "n":
		return Units{1e9, "ns"}, nil
	case "u":
		return Units{1e6, "us"}, nil
	case "m":
		return Units{1e3, "ms"}, nil
	case "s":
		return Units{1, "s"}, nil
	}
	return Units{}, fmt.Errorf("invalid unit %q (use n, u, m or s)", s)
}

// g formats like C's %.Ng and prints "nan" for missing values.
func g(v float64, prec int) string {
	if math.IsNaN(v) {
		return "nan"
	}
	return fmt.Sprintf("%.*g", prec, v)
}

// WriteSummary prints the human-readable summary in owping's format.
func (s *Summary) WriteSummary(w io.Writer, u Units, percentiles []float64) error {
	b := bufio.NewWriter(w)
	fmt.Fprintf(b, "\n--- owping statistics from [%s]:%d to [%s]:%d ---\n",
		s.From.Host, s.From.Addr.Port(), s.To.Host, s.To.Addr.Port())
	fmt.Fprintf(b, "SID:\t%s\n", s.Data.Request.SID)
	fmt.Fprintf(b, "first:\t%s\nlast:\t%s\n", localTime(s.First), localTime(s.Last))

	loss := 0.0
	if s.Sent > 0 {
		loss = 100 * float64(s.Lost) / float64(s.Sent)
	}
	fmt.Fprintf(b, "%d sent, %d lost (%.3f%%), %d duplicates\n", s.Sent, s.Lost, loss, s.Dups)

	median := math.NaN()
	if v, ok := s.Percentile(0.5); ok {
		median = v
	}
	fmt.Fprintf(b, "one-way delay min/median/max = %s/%s/%s %s, ",
		g(s.MinDelay*u.Factor, 3), g(median*u.Factor, 3), g(s.MaxDelay*u.Factor, 3), u.Abbrev)
	if s.Sync {
		fmt.Fprintf(b, "(err=%s %s)\n", g(s.MaxErr*u.Factor, 3), u.Abbrev)
	} else {
		fmt.Fprint(b, "(unsync)\n")
	}

	jitter := math.NaN()
	if v, ok := s.Jitter(); ok {
		jitter = v
	}
	fmt.Fprintf(b, "one-way jitter = %s %s (P95-P50)\n", g(jitter*u.Factor, 3), u.Abbrev)

	if len(percentiles) > 0 {
		fmt.Fprint(b, "Percentiles:\n")
		for _, p := range percentiles {
			v := math.NaN()
			if d, ok := s.Percentile(p / 100); ok {
				v = d
			}
			fmt.Fprintf(b, "\t%.1f: %s %s\n", p, g(v*u.Factor, 3), u.Abbrev)
		}
	}

	switch n, lo, hi := s.ttlRange(); {
	case n == 0:
		fmt.Fprint(b, "TTL not reported\n")
	case n == 1:
		fmt.Fprintf(b, "hops = %d (consistently)\n", 255-int(lo))
	default:
		fmt.Fprintf(b, "hops takes %d values; min hops = %d, max hops = %d\n", n, 255-int(hi), 255-int(lo))
	}

	j := 0
	for ; j < len(s.reord) && s.reord[j] != 0; j++ {
		fmt.Fprintf(b, "%d-reordering = %f%%\n", j+1, 100*float64(s.reord[j])/float64(s.nArriv))
	}
	switch {
	case j == 0:
		fmt.Fprint(b, "no reordering\n")
	case j < len(s.reord):
		fmt.Fprintf(b, "no %d-reordering\n", j+1)
	default:
		fmt.Fprintf(b, "%d-reordering not handled\n", len(s.reord)+1)
	}
	fmt.Fprint(b, "\n")
	return b.Flush()
}

// localTime formats a timestamp like owping: local time with milliseconds.
func localTime(ts owamp.Timestamp) string {
	t := ts.Time()
	return fmt.Sprintf("%s.%03.0f", t.Format("2006-01-02T15:04:05"), float64(t.Nanosecond())/1e6)
}

// WriteRecords prints one line per packet record, as owping -v does.
func WriteRecords(w io.Writer, d *owamp.SessionData, u Units) error {
	b := bufio.NewWriter(w)
	for i := range d.Records {
		r := &d.Records[i]
		if r.Seq >= d.Request.Packets || skipped(d.Skips, r.Seq) {
			continue
		}
		switch {
		case r.Lost():
			fmt.Fprintf(b, "seq_no=%-10d *LOST*\n", r.Seq)
		case r.SendErr.Synchronized() && r.RecvErr.Synchronized():
			fmt.Fprintf(b, "seq_no=%-10d delay=%s %s\t(sync, err=%s %s)\n", r.Seq,
				g(Delay(r)*u.Factor, 3), u.Abbrev, g((r.SendErr.Seconds()+r.RecvErr.Seconds())*u.Factor, 3), u.Abbrev)
		default:
			fmt.Fprintf(b, "seq_no=%-10d delay=%s %s\t(unsync)\n", r.Seq, g(Delay(r)*u.Factor, 3), u.Abbrev)
		}
	}
	return b.Flush()
}

// WriteRaw prints every record in owping -R format:
// SEQ STIME SSYNC SERR RTIME RSYNC RERR TTL, with timestamps as raw 64-bit
// OWAMP values and errors in seconds.
func WriteRaw(w io.Writer, d *owamp.SessionData) error {
	b := bufio.NewWriter(w)
	for _, r := range d.Records {
		fmt.Fprintf(b, "%d %020d %d %s %020d %d %s %d\n", r.Seq,
			uint64(r.Send), boolInt(r.SendErr.Synchronized()), g(r.SendErr.Seconds(), 6),
			uint64(r.Recv), boolInt(r.RecvErr.Synchronized()), g(r.RecvErr.Seconds(), 6), r.TTL)
	}
	return b.Flush()
}

// WriteMachine prints the machine-readable summary of owping -M
// (summary format version 3.0). Delays are in seconds; the histogram uses
// buckets of bucketWidth seconds.
func (s *Summary) WriteMachine(w io.Writer, bucketWidth float64) error {
	b := bufio.NewWriter(w)
	req := &s.Data.Request
	fmt.Fprintf(b, "SUMMARY\t%.2f\n", 3.0)
	fmt.Fprintf(b, "SID\t%s\n", req.SID)
	fmt.Fprintf(b, "FROM_HOST\t%s\nFROM_ADDR\t%s\nFROM_PORT\t%d\n", s.From.Host, s.From.Addr.Addr(), s.From.Addr.Port())
	fmt.Fprintf(b, "TO_HOST\t%s\nTO_ADDR\t%s\nTO_PORT\t%d\n", s.To.Host, s.To.Addr.Addr(), s.To.Addr.Port())
	fmt.Fprintf(b, "START_TIME\t%020d\nEND_TIME\t%020d\n", uint64(s.First), uint64(s.Last))
	if req.TypeP&^0x3f000000 == 0 {
		fmt.Fprintf(b, "DSCP\t0x%02x\n", req.TypeP>>24)
	}
	fmt.Fprintf(b, "LOSS_TIMEOUT\t%d\n", uint64(req.Timeout))
	fmt.Fprintf(b, "PACKET_PADDING\t%d\n", req.Padding)
	fmt.Fprintf(b, "SESSION_PACKET_COUNT\t%d\n", req.Packets)
	fmt.Fprintf(b, "SAMPLE_PACKET_COUNT\t%d\n", req.Packets)
	fmt.Fprintf(b, "BUCKET_WIDTH\t%s\n", g(bucketWidth, 6))
	fmt.Fprintf(b, "SESSION_FINISHED\t%d\n", boolInt(s.Data.Finished))
	fmt.Fprintf(b, "SENT\t%d\nSYNC\t%d\nMAXERR\t%s\n", s.Sent, boolInt(s.Sync), g(s.MaxErr, 6))
	fmt.Fprintf(b, "DUPS\t%d\nLOST\t%d\n", s.Dups, s.Lost)
	if !math.IsNaN(s.MinDelay) {
		fmt.Fprintf(b, "MIN\t%s\n", g(s.MinDelay, 6))
	}
	if v, ok := s.Percentile(0.5); ok {
		fmt.Fprintf(b, "MEDIAN\t%s\n", g(v, 6))
	}
	if !math.IsNaN(s.MaxDelay) {
		fmt.Fprintf(b, "MAX\t%s\n", g(s.MaxDelay, 6))
	}
	if v, ok := s.Jitter(); ok {
		fmt.Fprintf(b, "PDV\t%s\n", g(v, 6))
	}

	if s.Sent > s.Lost {
		buckets := make(map[int64]uint32)
		for _, d := range s.delays {
			buckets[bucketIndex(d, bucketWidth)]++
		}
		keys := make([]int64, 0, len(buckets))
		for k := range buckets {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		fmt.Fprint(b, "<BUCKETS>\n")
		for _, k := range keys {
			fmt.Fprintf(b, "\t%d\t%d\n", k, buckets[k])
		}
		fmt.Fprint(b, "</BUCKETS>\n")
	}

	n, lo, hi := s.ttlRange()
	fmt.Fprintf(b, "MINTTL\t%d\nMAXTTL\t%d\n", lo, hi)
	if n > 0 {
		fmt.Fprint(b, "<TTLBUCKETS>\n")
		for ttl, c := range s.TTLs {
			if c != 0 {
				fmt.Fprintf(b, "\t%d\t%d\n", ttl, c)
			}
		}
		fmt.Fprint(b, "</TTLBUCKETS>\n")
	}
	fmt.Fprint(b, "\n")

	fmt.Fprint(b, "<NREORDERING>\n")
	j := 0
	for ; j < len(s.reord) && s.reord[j] != 0; j++ {
		fmt.Fprintf(b, "\t%d\t%d\n", j+1, s.reord[j])
	}
	if j == 0 || j >= len(s.reord) {
		fmt.Fprintf(b, "\t%d\t0\n", j+1)
	}
	fmt.Fprint(b, "</NREORDERING>\n")
	return b.Flush()
}

// bucketIndex rounds away from zero like owping's histogram.
func bucketIndex(delay, width float64) int64 {
	d := delay / width
	if d < 0 {
		return int64(math.Floor(d))
	}
	return int64(math.Ceil(d))
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
