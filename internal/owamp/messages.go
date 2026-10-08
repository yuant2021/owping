package owamp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// DefaultPort is the IANA-assigned OWAMP-Control port.
const DefaultPort = 861

// Command numbers: the first octet of client commands (RFC 4656 §3.4).
const (
	cmdRequestSession = 1
	cmdStartSessions  = 2
	cmdStopSessions   = 3
	cmdFetchSession   = 4
)

// Accept is the value of an Accept field (RFC 4656 §3.3).
type Accept uint8

const (
	AcceptOK          Accept = 0
	AcceptFailure     Accept = 1
	AcceptInternal    Accept = 2
	AcceptUnsupported Accept = 3
	AcceptPermLimit   Accept = 4
	AcceptTempLimit   Accept = 5
)

func (a Accept) String() string {
	switch a {
	case AcceptOK:
		return "ok"
	case AcceptFailure:
		return "failure"
	case AcceptInternal:
		return "internal error"
	case AcceptUnsupported:
		return "not supported"
	case AcceptPermLimit:
		return "permanent resource limitation"
	case AcceptTempLimit:
		return "temporary resource limitation"
	}
	return fmt.Sprintf("failure (code %d)", uint8(a))
}

// AcceptError reports a request the peer refused.
type AcceptError struct {
	Op     string
	Accept Accept
}

func (e *AcceptError) Error() string { return fmt.Sprintf("%s rejected: %s", e.Op, e.Accept) }

// errProtocol marks malformed or unexpected peer messages.
var errProtocol = errors.New("owamp: protocol error")

func protocolError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errProtocol, fmt.Sprintf(format, args...))
}

// SID identifies a test session.
type SID [16]byte

func (s SID) String() string { return hex.EncodeToString(s[:]) }

// newSID builds a SID from the receiver address, the current time and random
// octets (RFC 4656 §3.5). IPv6 receivers contribute their last four octets,
// as the reference implementation does.
func newSID(receiver netip.Addr) SID {
	var sid SID
	a := receiver.As16()
	copy(sid[:4], a[12:])
	putUint64(sid[4:], uint64(TimestampFromTime(time.Now())))
	if _, err := rand.Read(sid[12:]); err != nil {
		panic(err)
	}
	return sid
}

func putUint16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }
func putUint32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func putUint64(b []byte, v uint64) { binary.BigEndian.PutUint64(b, v) }
func getUint16(b []byte) uint16    { return binary.BigEndian.Uint16(b) }
func getUint32(b []byte) uint32    { return binary.BigEndian.Uint32(b) }
func getUint64(b []byte) uint64    { return binary.BigEndian.Uint64(b) }

// roundBlocks rounds n up to a whole number of AES blocks.
func roundBlocks(n int) int { return (n + blockSize - 1) / blockSize * blockSize }

// Connection setup messages (RFC 4656 §3.1).

const (
	greetingSize    = 64
	setupSize       = 164
	serverStartSize = 48
	keyIDSize       = 80
)

type serverGreeting struct {
	modes     Mode
	challenge [16]byte
	salt      [16]byte
	count     uint32
}

func (g *serverGreeting) marshal() []byte {
	b := make([]byte, greetingSize)
	putUint32(b[12:], uint32(g.modes))
	copy(b[16:32], g.challenge[:])
	copy(b[32:48], g.salt[:])
	putUint32(b[48:], g.count)
	return b
}

func parseServerGreeting(b []byte) serverGreeting {
	var g serverGreeting
	g.modes = Mode(getUint32(b[12:])) & modeMask // other bits are reserved
	copy(g.challenge[:], b[16:32])
	copy(g.salt[:], b[32:48])
	g.count = getUint32(b[48:])
	return g
}

type setupResponse struct {
	mode     Mode
	keyID    [keyIDSize]byte
	token    [tokenSize]byte
	clientIV [blockSize]byte
}

func (s *setupResponse) marshal() []byte {
	b := make([]byte, setupSize)
	putUint32(b[0:], uint32(s.mode))
	copy(b[4:84], s.keyID[:])
	copy(b[84:148], s.token[:])
	copy(b[148:164], s.clientIV[:])
	return b
}

func parseSetupResponse(b []byte) setupResponse {
	var s setupResponse
	s.mode = Mode(getUint32(b[0:]))
	copy(s.keyID[:], b[4:84])
	copy(s.token[:], b[84:148])
	copy(s.clientIV[:], b[148:164])
	return s
}

// keyIDString returns the KeyID with its zero padding removed.
func keyIDString(k []byte) string {
	for i, c := range k {
		if c == 0 {
			return string(k[:i])
		}
	}
	return string(k)
}

// TestRequest is a Request-Session command (RFC 4656 §3.5). Fetch-Session
// replies reproduce it with the actual ports and SID filled in.
type TestRequest struct {
	ConfSender   bool // the server configures the sender
	ConfReceiver bool // the server configures the receiver
	Packets      uint32
	Sender       netip.AddrPort
	Receiver     netip.AddrPort
	SID          SID
	Padding      uint32
	Start        Timestamp
	Timeout      Timestamp
	TypeP        uint32
	Slots        []Slot
}

// requestPreambleSize is the fixed part of Request-Session without its HMAC.
const requestPreambleSize = 96

func (r *TestRequest) marshalPreamble() []byte {
	b := make([]byte, requestPreambleSize)
	b[0] = cmdRequestSession
	b[1] = 4
	if r.Sender.Addr().Is6() {
		b[1] = 6
	}
	b[2] = boolByte(r.ConfSender)
	b[3] = boolByte(r.ConfReceiver)
	putUint32(b[4:], uint32(len(r.Slots)))
	putUint32(b[8:], r.Packets)
	putUint16(b[12:], r.Sender.Port())
	putUint16(b[14:], r.Receiver.Port())
	putAddr(b[16:32], r.Sender.Addr())
	putAddr(b[32:48], r.Receiver.Addr())
	copy(b[48:64], r.SID[:])
	putUint32(b[64:], r.Padding)
	putUint64(b[68:], uint64(r.Start))
	putUint64(b[76:], uint64(r.Timeout))
	putUint32(b[84:], r.TypeP)
	return b
}

func (r *TestRequest) marshalSlots() []byte {
	b := make([]byte, blockSize*len(r.Slots))
	for i, s := range r.Slots {
		b[i*blockSize] = byte(s.Type)
		putUint64(b[i*blockSize+8:], uint64(s.Value))
	}
	return b
}

// parsePreamble decodes the fixed part of Request-Session and returns the
// number of slot blocks that follow it, even when the request is refused.
func parsePreamble(b []byte) (*TestRequest, uint32, error) {
	if b[0] != cmdRequestSession {
		return nil, 0, protocolError("expected Request-Session, got command %d", b[0])
	}
	nslots := getUint32(b[4:])
	r := &TestRequest{
		ConfSender:   b[2] != 0,
		ConfReceiver: b[3] != 0,
		Packets:      getUint32(b[8:]),
		Padding:      getUint32(b[64:]),
		Start:        Timestamp(getUint64(b[68:])),
		Timeout:      Timestamp(getUint64(b[76:])),
		TypeP:        getUint32(b[84:]),
	}
	var snd, rcv netip.Addr
	switch ipvn := b[1] & 0x0f; ipvn {
	case 4:
		snd = netip.AddrFrom4([4]byte(b[16:20]))
		rcv = netip.AddrFrom4([4]byte(b[32:36]))
	case 6:
		snd = netip.AddrFrom16([16]byte(b[16:32]))
		rcv = netip.AddrFrom16([16]byte(b[32:48]))
	default:
		return nil, nslots, &AcceptError{Op: "Request-Session", Accept: AcceptUnsupported}
	}
	r.Sender = netip.AddrPortFrom(snd.Unmap(), getUint16(b[12:]))
	r.Receiver = netip.AddrPortFrom(rcv.Unmap(), getUint16(b[14:]))
	copy(r.SID[:], b[48:64])
	return r, nslots, nil
}

func parseSlot(b []byte) (Slot, error) {
	s := Slot{Type: SlotType(b[0]), Value: Timestamp(getUint64(b[8:]))}
	if s.Type != SlotExponential && s.Type != SlotFixed {
		return s, fmt.Errorf("unknown slot type %d", b[0])
	}
	return s, nil
}

func putAddr(b []byte, a netip.Addr) {
	if a.Is4() {
		v := a.As4()
		copy(b, v[:])
		return
	}
	v := a.As16()
	copy(b, v[:])
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// SkipRange is an inclusive range of sequence numbers a sender never sent.
type SkipRange struct {
	First, Last uint32
}

// marshalSkips encodes skip ranges padded to whole blocks.
func marshalSkips(skips []SkipRange) []byte {
	b := make([]byte, roundBlocks(8*len(skips)))
	for i, s := range skips {
		putUint32(b[8*i:], s.First)
		putUint32(b[8*i+4:], s.Last)
	}
	return b
}

// parseSkips decodes n skip ranges and checks that they are ordered and do
// not overlap (RFC 4656 §3.8, §3.9).
func parseSkips(b []byte, n int) ([]SkipRange, error) {
	skips := make([]SkipRange, n)
	for i := range skips {
		s := SkipRange{First: getUint32(b[8*i:]), Last: getUint32(b[8*i+4:])}
		if s.Last < s.First || (i > 0 && s.First <= skips[i-1].Last) {
			return nil, protocolError("invalid skip ranges")
		}
		skips[i] = s
	}
	return skips, nil
}

// sessionStatus is a Stop-Sessions session description: how far a sender
// got and which packets it skipped.
type sessionStatus struct {
	sid       SID
	nextSeqno uint32
	skips     []SkipRange
}

// marshalStop encodes Stop-Sessions without its trailing HMAC block.
func marshalStop(accept Accept, sessions []sessionStatus) []byte {
	b := make([]byte, blockSize)
	b[0] = cmdStopSessions
	b[1] = byte(accept)
	putUint32(b[4:], uint32(len(sessions)))
	for _, s := range sessions {
		rec := make([]byte, blockSize+roundBlocks(8+8*len(s.skips)))
		copy(rec, s.sid[:])
		putUint32(rec[16:], s.nextSeqno)
		putUint32(rec[20:], uint32(len(s.skips)))
		for i, r := range s.skips {
			putUint32(rec[24+8*i:], r.First)
			putUint32(rec[28+8*i:], r.Last)
		}
		b = append(b, rec...)
	}
	return b
}

// Record is a packet record of session data (RFC 4656 §3.9).
type Record struct {
	Seq     uint32
	SendErr ErrorEstimate
	RecvErr ErrorEstimate
	Send    Timestamp
	Recv    Timestamp // zero for lost packets
	TTL     uint8
}

const recordSize = 25

// Lost reports whether the record marks a lost packet.
func (r *Record) Lost() bool { return r.Recv == 0 }

func (r *Record) marshal(b []byte) {
	putUint32(b[0:], r.Seq)
	putUint16(b[4:], uint16(r.SendErr))
	putUint16(b[6:], uint16(r.RecvErr))
	putUint64(b[8:], uint64(r.Send))
	putUint64(b[16:], uint64(r.Recv))
	b[24] = r.TTL
}

func parseRecord(b []byte) Record {
	return Record{
		Seq:     getUint32(b[0:]),
		SendErr: ErrorEstimate(getUint16(b[4:])),
		RecvErr: ErrorEstimate(getUint16(b[6:])),
		Send:    Timestamp(getUint64(b[8:])),
		Recv:    Timestamp(getUint64(b[16:])),
		TTL:     b[24],
	}
}

// SessionData is the result set of one test session: the request that
// created it, what the sender reported, and the packet records in arrival
// order.
type SessionData struct {
	Request   TestRequest
	Finished  bool
	NextSeqno uint32
	Skips     []SkipRange
	Records   []Record
}
