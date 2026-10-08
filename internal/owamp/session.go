package owamp

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// EndpointOptions tune the local OWAMP-Test endpoints.
type EndpointOptions struct {
	PortRange   PortRange     // UDP ports for test sessions; zero value means ephemeral
	EndDelay    time.Duration // extra wait after the last packet + Timeout before a sender completes
	ZeroPadding bool          // send all-zero packet padding instead of pseudo-random octets
}

// DefaultEndDelay is the reference implementation's extra sender delay; it
// absorbs small clock offsets so receivers have completed when
// Stop-Sessions arrives.
const DefaultEndDelay = time.Second

// session is a test session negotiated on a control connection. Exactly one
// of snd and rcv is set: the local endpoint.
type session struct {
	req *TestRequest
	snd *sender
	rcv *receiver

	// Receive side, after Stop-Sessions.
	data *SessionData
	err  error
}

func (s *session) start() {
	if s.snd != nil {
		s.snd.start()
	} else {
		s.rcv.start()
	}
}

func (s *session) stop() {
	if s.snd != nil {
		s.snd.stop()
	} else {
		s.rcv.stop()
	}
}

func (s *session) done() <-chan struct{} {
	if s.snd != nil {
		return s.snd.done
	}
	return s.rcv.done
}

// close releases the socket of a session that was never started.
func (s *session) close() {
	if s.snd != nil {
		s.snd.close()
	} else {
		s.rcv.conn.Close()
	}
}

// stopWaitSlack is how long to wait for the peer's Stop-Sessions beyond the
// longest session Timeout once the local endpoints have completed.
const stopWaitSlack = time.Minute

type recvResult struct {
	b   []byte
	err error
	at  time.Time // arrival, the reference point for discarding late records
}

// runSessions drives started test sessions to their end and performs the
// Stop-Sessions exchange (RFC 4656 §3.8). Each side sends Stop-Sessions once
// its own endpoints have completed, unless the peer's Stop-Sessions arrives
// first; cancelling ctx stops the sessions early.
func (c *controlConn) runSessions(ctx context.Context, sessions []*session) error {
	peer := make(chan recvResult, 1)
	c.deadline(0)
	go func() {
		b, err := c.recv(blockSize)
		peer <- recvResult{b, err, time.Now()}
	}()

	allDone := make(chan struct{})
	go func() {
		for _, s := range sessions {
			<-s.done()
		}
		close(allDone)
	}()

	var timeout Timestamp
	for _, s := range sessions {
		timeout = max(timeout, s.req.Timeout)
	}
	waitPeer := func() (recvResult, error) {
		select {
		case m := <-peer:
			return m, nil
		case <-time.After(timeout.Duration() + stopWaitSlack):
			return recvResult{}, errors.New("timed out waiting for Stop-Sessions from peer")
		}
	}

	select {
	case <-allDone:
		if err := c.writeStop(AcceptOK, sessions); err != nil {
			return err
		}
		m, err := waitPeer()
		if err != nil {
			return err
		}
		return c.readStop(m, sessions)

	case m := <-peer:
		for _, s := range sessions {
			s.stop()
		}
		<-allDone
		if err := c.readStop(m, sessions); err != nil {
			return err
		}
		return c.writeStop(AcceptOK, sessions)

	case <-ctx.Done():
		// Like the reference OWPStopSessions: stop sending, report, and
		// keep receiving until the peer's reply, which sets the cut-off
		// for the received data (RFC 4656 §3.8).
		for _, s := range sessions {
			if s.snd != nil {
				s.snd.stop()
			}
		}
		err := c.writeStop(AcceptOK, sessions)
		var m recvResult
		if err == nil {
			m, err = waitPeer()
		}
		for _, s := range sessions {
			s.stop()
		}
		<-allDone
		if err != nil {
			return err
		}
		return c.readStop(m, sessions)
	}
}

// writeStop sends Stop-Sessions describing the local send sessions, which
// must have completed.
func (c *controlConn) writeStop(accept Accept, sessions []*session) error {
	var status []sessionStatus
	for _, s := range sessions {
		if s.snd != nil {
			<-s.snd.done
			status = append(status, sessionStatus{sid: s.req.SID, nextSeqno: s.snd.nextSeqno, skips: s.snd.skips})
		}
	}
	return c.sendMessage(marshalStop(accept, status))
}

// readStop reads the rest of the peer's Stop-Sessions, whose first block is
// in m, and completes the local receive sessions with it. The local
// endpoints must have completed.
func (c *controlConn) readStop(m recvResult, sessions []*session) error {
	if m.err != nil {
		return m.err
	}
	c.deadline(responseTimeout) // the peer must send the rest promptly
	stop := TimestampFromTime(m.at)
	if m.b[0] != cmdStopSessions {
		return protocolError("expected Stop-Sessions, got command %d", m.b[0])
	}
	accept := Accept(m.b[1])
	count := getUint32(m.b[4:])

	recv := make(map[SID]*session)
	for _, s := range sessions {
		if s.rcv != nil {
			recv[s.req.SID] = s
		}
	}
	if int(count) != len(recv) {
		return protocolError("Stop-Sessions describes %d sessions, expected %d", count, len(recv))
	}
	status := make(map[SID]sessionStatus, count)
	for range count {
		b, err := c.recv(2 * blockSize)
		if err != nil {
			return err
		}
		sid := SID(b[:16])
		s, ok := recv[sid]
		if !ok {
			return protocolError("Stop-Sessions for unknown session %s", sid)
		}
		if _, dup := status[sid]; dup {
			return protocolError("Stop-Sessions repeats session %s", sid)
		}
		next, nskips := getUint32(b[16:]), getUint32(b[20:])
		if nskips > s.req.Packets {
			return protocolError("Stop-Sessions reports %d skip ranges for %d packets", nskips, s.req.Packets)
		}
		skipBytes := b[24:]
		if more := roundBlocks(8+8*int(nskips)) - blockSize; more > 0 {
			rest, err := c.recv(more)
			if err != nil {
				return err
			}
			skipBytes = append(skipBytes, rest...)
		}
		skips, err := parseSkips(skipBytes, int(nskips))
		if err != nil {
			return err
		}
		status[sid] = sessionStatus{sid: sid, nextSeqno: next, skips: skips}
	}
	if err := c.recvHMAC(); err != nil {
		return err
	}

	for sid, s := range recv {
		if accept != AcceptOK {
			s.err = &AcceptError{Op: "test session", Accept: accept}
			continue
		}
		st := status[sid]
		if s.data, s.err = s.rcv.finish(st.nextSeqno, st.skips, stop); s.err != nil {
			s.err = fmt.Errorf("session %s: %w", sid, s.err)
		}
	}
	if accept != AcceptOK {
		return &AcceptError{Op: "test sessions", Accept: accept}
	}
	return nil
}
