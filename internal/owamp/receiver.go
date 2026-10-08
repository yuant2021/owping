package owamp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// receiver collects the packets of one OWAMP-Test session (RFC 4656 §4.2).
// Records are kept in arrival order; a packet is recorded as lost as soon
// as Timeout has passed since its scheduled send time, which is also when
// it stops being accepted.
type receiver struct {
	conn  *net.UDPConn
	peer  netip.AddrPort // the sender's address and port
	req   *TestRequest
	codec *packetCodec
	times *SendTimes
	size  int

	stopped atomic.Bool
	done    chan struct{}

	// Owned by run until done is closed.
	hit     []bool
	begin   uint32 // packets below begin are final: received or recorded lost
	records []Record
}

func newReceiver(conn *net.UDPConn, peer netip.AddrPort, req *TestRequest, mode Mode, keys *testKeys) *receiver {
	return &receiver{
		conn:  conn,
		peer:  peer,
		req:   req,
		codec: newPacketCodec(mode, keys),
		times: NewSendTimes(req.Start, req.SID, req.Slots),
		size:  testPacketSize(mode, req.Padding),
		done:  make(chan struct{}),
		hit:   make([]bool, req.Packets),
	}
}

func (r *receiver) start() { go r.run() }

// stop interrupts the receiver; finish completes the session afterwards.
func (r *receiver) stop() {
	r.stopped.Store(true)
	r.conn.SetReadDeadline(time.Now())
}

func (r *receiver) run() {
	defer close(r.done)
	defer r.conn.Close()

	buf := make([]byte, r.size+1) // one spare byte detects oversized packets
	oob := make([]byte, oobSize)
	for r.begin < r.req.Packets && !r.stopped.Load() {
		// Wake up when the oldest outstanding packet is due to be lost.
		due := (r.times.At(r.begin) + r.req.Timeout).Time()
		r.conn.SetReadDeadline(due.Add(time.Millisecond))
		if r.stopped.Load() {
			break // stop raced with the deadline update
		}

		n, oobn, flags, from, err := r.conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				now, est := Now()
				r.flush(TimestampFromTime(now), est)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(time.Millisecond) // e.g. a queued ICMP error; keep receiving
			continue
		}

		rt, ok, ttl := parseRxControl(oob[:oobn])
		if !ok {
			rt = time.Now()
		}
		recv, est := TimestampFromTime(rt), sysClock.estimate(rt)
		r.flush(recv, est)

		if n != r.size || flags&syscall.MSG_TRUNC != 0 || !sameEndpoint(from, r.peer) {
			continue
		}
		seq, send, sendErr, valid := r.codec.open(buf[:n])
		if !valid || !sendErr.Valid() || seq >= r.req.Packets || seq < r.begin {
			continue
		}
		// RFC 4656 §4.2: discard packets whose send timestamp is more
		// than Timeout away from the receive time or from the schedule.
		if absDiff(send, recv) > r.req.Timeout || absDiff(send, r.times.At(seq)) > r.req.Timeout {
			continue
		}
		if r.hit[seq] && len(r.records) >= r.maxRecords() {
			continue // bound memory under a flood of duplicates
		}
		r.hit[seq] = true
		r.records = append(r.records, Record{
			Seq: seq, SendErr: sendErr, RecvErr: est, Send: send, Recv: recv, TTL: ttl,
		})
	}
}

// flush records every outstanding packet whose Timeout expired by now as
// lost, unless it was received.
func (r *receiver) flush(now Timestamp, est ErrorEstimate) {
	for r.begin < r.req.Packets {
		sched := r.times.At(r.begin)
		if sched+r.req.Timeout >= now {
			return
		}
		if !r.hit[r.begin] {
			r.records = append(r.records, lostRecord(r.begin, sched, est))
		}
		r.begin++
	}
}

func lostRecord(seq uint32, sched Timestamp, est ErrorEstimate) Record {
	return Record{Seq: seq, SendErr: lostSendError, RecvErr: est, Send: sched, TTL: 255}
}

// maxRecords caps duplicates at three copies per packet on average.
func (r *receiver) maxRecords() int { return 4*int(r.req.Packets) + 1024 }

// finish completes the session from the sender's Stop-Sessions report
// (RFC 4656 §3.8): packets from nextSeqno on were never sent, and records
// whose send time is within Timeout of the stop time are discarded so that
// loss is not overstated when the session ends early. It must be called
// after run has returned.
func (r *receiver) finish(nextSeqno uint32, skips []SkipRange, stop Timestamp) (*SessionData, error) {
	if nextSeqno > r.req.Packets {
		return nil, fmt.Errorf("sender reported next sequence number %d for a %d-packet session", nextSeqno, r.req.Packets)
	}
	// Every packet not yet final is now known to be lost (or never sent,
	// which the filter below sorts out).
	_, est := Now()
	for ; r.begin < r.req.Packets; r.begin++ {
		if !r.hit[r.begin] {
			r.records = append(r.records, lostRecord(r.begin, r.times.At(r.begin), est))
		}
	}
	threshold := stop - r.req.Timeout
	if r.req.Timeout > stop {
		threshold = 0
	}
	kept := r.records[:0]
	for _, rec := range r.records {
		if rec.Seq >= nextSeqno {
			if !rec.Lost() {
				return nil, fmt.Errorf("received packet %d, beyond the sender's last sequence number %d", rec.Seq, nextSeqno)
			}
			continue
		}
		if rec.Send <= threshold {
			kept = append(kept, rec)
		}
	}
	return &SessionData{
		Request:   *r.req,
		Finished:  true,
		NextSeqno: nextSeqno,
		Skips:     skips,
		Records:   kept,
	}, nil
}

// sameEndpoint compares addresses ignoring IPv6 zones and IPv4 mapping.
func sameEndpoint(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap().WithZone("") == b.Addr().Unmap().WithZone("")
}
