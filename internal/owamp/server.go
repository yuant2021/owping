package owamp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Server defaults and limits.
const (
	DefaultMaxPackets   = 100000
	DefaultMaxConns     = 64
	DefaultPBKDF2Count  = 2048
	setupTimeout        = time.Minute
	idleTimeout         = 30 * time.Minute // RFC 4656 §3 suggests 30 minutes
	maxPendingSessions  = 16               // each sender holds an OS thread while running
	maxFinishedSessions = 64
	maxRunningSenders   = 256 // server-wide, bounds the OS threads senders pin
	maxSessionSpan      = 24 * time.Hour
	maxPacketSize       = 65000 // owping's padding limit; fits any UDP datagram
)

// ServerConfig configures an OWAMP server.
type ServerConfig struct {
	EndpointOptions
	Modes       Mode              // offered modes; zero means open only
	Keys        map[string][]byte // pass-phrases by KeyID, for authenticated and encrypted modes
	MaxPackets  uint32            // per-session packet limit; zero means DefaultMaxPackets
	MaxConns    int               // concurrent control connections; zero means DefaultMaxConns
	PBKDF2Count uint32            // key derivation iterations; zero means DefaultPBKDF2Count
	Logf        func(format string, args ...any)
}

// Server accepts OWAMP-Control connections and runs the test endpoints
// clients request; it plays the role of owampd.
type Server struct {
	cfg     ServerConfig
	start   Timestamp
	slots   chan struct{} // control connections
	senders chan struct{} // sender sessions set up and not yet finished
}

// NewServer validates cfg and returns a server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Modes == 0 {
		cfg.Modes = ModeOpen
	}
	if cfg.Modes&^modeMask != 0 {
		return nil, fmt.Errorf("invalid modes %d", cfg.Modes)
	}
	if cfg.Modes.secure() && len(cfg.Keys) == 0 {
		return nil, errors.New("authenticated and encrypted modes need pass-phrases")
	}
	for id := range cfg.Keys {
		if len(id) > keyIDSize {
			return nil, fmt.Errorf("identity %q is longer than %d octets", id, keyIDSize)
		}
	}
	if cfg.MaxPackets == 0 {
		cfg.MaxPackets = DefaultMaxPackets
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.PBKDF2Count == 0 {
		cfg.PBKDF2Count = DefaultPBKDF2Count
	}
	if cfg.PBKDF2Count < MinPBKDF2Count || cfg.PBKDF2Count&(cfg.PBKDF2Count-1) != 0 || cfg.PBKDF2Count > maxPBKDF2Count {
		return nil, fmt.Errorf("PBKDF2 count must be a power of two between %d and %d", MinPBKDF2Count, maxPBKDF2Count)
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Server{
		cfg:     cfg,
		start:   TimestampFromTime(time.Now()),
		slots:   make(chan struct{}, cfg.MaxConns),
		senders: make(chan struct{}, maxRunningSenders),
	}, nil
}

// Serve accepts control connections on ln until ctx is cancelled, then
// closes ln and the open connections and waits for their handlers.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.cfg.Logf("accept: %v", err)
			time.Sleep(100 * time.Millisecond) // e.g. out of file descriptors
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.cfg.Logf("%s: refused: too many control connections", nc.RemoteAddr())
			go refuse(nc)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.slots }()
			s.handle(ctx, nc)
		}()
	}
}

// refuse sends a greeting offering no modes, which tells the client the
// server does not wish to communicate (RFC 4656 §3.1).
func refuse(nc net.Conn) {
	defer nc.Close()
	nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	g := serverGreeting{}
	nc.Write(g.marshal())
}

// serverConn is the state of one control connection.
type serverConn struct {
	srv      *Server
	cc       *controlConn
	local    netip.Addr
	remote   netip.AddrPort
	name     string
	pending  []*session // requested, not yet started
	finished []*session // completed receive sessions, available to Fetch-Session
}

func (s *Server) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()

	la := nc.LocalAddr().(*net.TCPAddr).AddrPort()
	ra := nc.RemoteAddr().(*net.TCPAddr).AddrPort()
	sc := &serverConn{
		srv:    s,
		cc:     newControlConn(nc),
		local:  la.Addr().Unmap(),
		remote: netip.AddrPortFrom(ra.Addr().Unmap(), ra.Port()),
	}
	sc.name = sc.remote.String()
	defer func() {
		for _, p := range sc.pending {
			p.close()
		}
	}()

	id, err := sc.setup()
	if err != nil {
		s.cfg.Logf("%s: connection refused: %v", sc.name, err)
		return
	}
	if id != "" {
		sc.name += " (" + id + ")"
	}
	s.cfg.Logf("%s: connected, %s mode", sc.name, sc.cc.mode)
	err = sc.serve()
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		s.cfg.Logf("%s: disconnected", sc.name)
	default:
		s.cfg.Logf("%s: disconnected: %v", sc.name, err)
	}
}

// unknownIdentity stands in for the pass-phrase of unknown identities so
// that they take as long to reject as wrong pass-phrases.
var unknownIdentity = []byte("\x00unknown identity")

// setup performs the server side of connection setup (RFC 4656 §3.1) and
// returns the client's identity in authenticated and encrypted modes.
func (sc *serverConn) setup() (string, error) {
	cfg := &sc.srv.cfg
	cc := sc.cc
	g := serverGreeting{modes: cfg.Modes, count: cfg.PBKDF2Count}
	mustRandom(g.challenge[:])
	mustRandom(g.salt[:])
	cc.nc.SetWriteDeadline(time.Now().Add(setupTimeout))
	defer cc.nc.SetWriteDeadline(time.Time{})
	if _, err := cc.nc.Write(g.marshal()); err != nil {
		return "", err
	}
	cc.deadline(setupTimeout)
	b, err := cc.readRaw(setupSize)
	if err != nil {
		return "", fmt.Errorf("reading Set-Up-Response: %w", err)
	}
	sr := parseSetupResponse(b)
	mode := sr.mode & modeMask
	if mode == 0 {
		return "", errors.New("client accepts none of the offered modes")
	}
	if mode&(mode-1) != 0 || mode&cfg.Modes == 0 {
		sc.writeServerStart(AcceptFailure, 0, sessionKeys{}, nil)
		return "", fmt.Errorf("client chose mode %d, which was not offered", sr.mode)
	}

	var keys sessionKeys
	var id string
	if mode.secure() {
		id = keyIDString(sr.keyID[:])
		pass, known := cfg.Keys[id]
		if !known {
			pass = unknownIdentity
		}
		token := sr.token
		if err := tokenCrypt(pass, g.salt[:], g.count, token[:], false); err != nil {
			return "", err
		}
		if !known || subtle.ConstantTimeCompare(token[:16], g.challenge[:]) != 1 {
			sc.writeServerStart(AcceptFailure, 0, sessionKeys{}, nil)
			return "", fmt.Errorf("authentication failed for identity %q", id)
		}
		copy(keys.aes[:], token[16:32])
		copy(keys.hmac[:], token[32:64])
	}
	if err := sc.writeServerStart(AcceptOK, mode, keys, sr.clientIV[:]); err != nil {
		return "", err
	}
	return id, nil
}

// writeServerStart sends Server-Start. On acceptance it switches the
// connection to the negotiated mode; Start-Time is the first block of the
// server's encrypted stream (RFC 4656 §3.1).
func (sc *serverConn) writeServerStart(accept Accept, mode Mode, keys sessionKeys, clientIV []byte) error {
	cc := sc.cc
	b := make([]byte, serverStartSize)
	b[15] = byte(accept)
	if accept != AcceptOK {
		cc.w.Write(b)
		return cc.flush()
	}
	iv := b[16:32]
	mustRandom(iv)
	if _, err := cc.w.Write(b[:32]); err != nil {
		return err
	}
	if mode.secure() {
		cc.startCipher(mode, keys, iv, clientIV)
	} else {
		cc.mode = ModeOpen
	}
	putUint64(b[32:], uint64(sc.srv.start))
	if err := cc.send(b[32:]); err != nil {
		return err
	}
	return cc.flush()
}

// serve handles commands until the client disconnects.
func (sc *serverConn) serve() error {
	for {
		sc.cc.deadline(idleTimeout)
		first, err := sc.cc.recv(blockSize)
		if err != nil {
			return err
		}
		switch first[0] {
		case cmdRequestSession:
			err = sc.requestSession(first)
		case cmdStartSessions:
			err = sc.startSessions()
		case cmdFetchSession:
			err = sc.fetchSession(first)
		default:
			err = protocolError("unexpected command %d", first[0])
		}
		if err != nil {
			return err
		}
	}
}

func (sc *serverConn) requestSession(first []byte) error {
	req, err := sc.cc.readTestRequest(first, sc.srv.cfg.MaxPackets)
	var refused *AcceptError
	if errors.As(err, &refused) {
		sc.srv.cfg.Logf("%s: session refused: malformed request", sc.name)
		return sc.writeAcceptSession(refused.Accept, 0, SID{})
	}
	if err != nil {
		return err
	}
	s, accept, err := sc.newSession(req)
	if err != nil {
		sc.srv.cfg.Logf("%s: session refused: %v", sc.name, err)
		return sc.writeAcceptSession(accept, 0, SID{})
	}
	sc.pending = append(sc.pending, s)
	if s.rcv != nil {
		sc.srv.cfg.Logf("%s: session %s: receiving %d packets at %s from %s", sc.name, req.SID, req.Packets, req.Receiver, req.Sender)
		return sc.writeAcceptSession(AcceptOK, req.Receiver.Port(), req.SID)
	}
	sc.srv.cfg.Logf("%s: session %s: sending %d packets from %s to %s", sc.name, req.SID, req.Packets, req.Sender, req.Receiver)
	return sc.writeAcceptSession(AcceptOK, req.Sender.Port(), req.SID)
}

func (sc *serverConn) writeAcceptSession(accept Accept, port uint16, sid SID) error {
	b := make([]byte, 2*blockSize)
	b[0] = byte(accept)
	putUint16(b[2:], port)
	copy(b[4:20], sid[:])
	return sc.cc.sendMessage(b)
}

// newSession validates a request and sets up the local endpoint.
func (sc *serverConn) newSession(req *TestRequest) (*session, Accept, error) {
	cfg := &sc.srv.cfg
	mode := sc.cc.mode
	switch {
	case req.ConfSender == req.ConfReceiver:
		return nil, AcceptUnsupported, errors.New("server must configure exactly one endpoint")
	case req.Sender.Addr().Is4() != req.Receiver.Addr().Is4():
		return nil, AcceptUnsupported, errors.New("sender and receiver address families differ")
	case req.Packets == 0:
		return nil, AcceptFailure, errors.New("no packets requested")
	case req.Packets > cfg.MaxPackets:
		return nil, AcceptPermLimit, fmt.Errorf("%d packets requested, limit is %d", req.Packets, cfg.MaxPackets)
	case len(sc.pending) >= maxPendingSessions:
		return nil, AcceptTempLimit, errors.New("too many pending sessions")
	case req.Padding > maxPacketSize || testPacketSize(mode, req.Padding) > maxPacketSize:
		return nil, AcceptUnsupported, fmt.Errorf("padding of %d octets is too large", req.Padding)
	}

	self, peer := req.Receiver, req.Sender
	if req.ConfSender {
		self, peer = req.Sender, req.Receiver
		if req.TypeP&^0x3f000000 != 0 {
			return nil, AcceptUnsupported, fmt.Errorf("unsupported Type-P descriptor %#x", req.TypeP)
		}
		if peer.Port() == 0 {
			return nil, AcceptFailure, errors.New("no receiver port")
		}
		// RFC 4656 §6.2: without authentication only send test traffic
		// to the client itself, so the server cannot be used to flood
		// third parties.
		if !mode.secure() && peer.Addr().WithZone("") != sc.remote.Addr().WithZone("") {
			return nil, AcceptFailure, fmt.Errorf("open mode: refusing to send to %s", peer.Addr())
		}
	}
	peer = netip.AddrPortFrom(withZone(peer.Addr(), sc.remote.Addr()), peer.Port())

	// The SID seeds the schedule, so it must be final before the span
	// check; the receiver assigns it.
	if req.ConfReceiver {
		sidAddr := self.Addr()
		if !sidAddr.IsValid() || sidAddr.IsUnspecified() {
			sidAddr = sc.local
		}
		req.SID = newSID(sidAddr)
	}
	if !withinSpan(req, TimestampFromTime(time.Now())) {
		return nil, AcceptPermLimit, fmt.Errorf("session would not fit within %v", maxSessionSpan)
	}

	conn, bound, err := sc.listenTest(self.Addr())
	if err != nil {
		return nil, AcceptTempLimit, err
	}
	addr := self.Addr()
	if !addr.IsValid() || addr.IsUnspecified() {
		addr = bound
	}
	port := localPort(conn)
	var keys *testKeys
	if mode.secure() {
		keys = deriveTestKeys(&sc.cc.keys, req.SID)
	}
	s := &session{req: req}
	if req.ConfReceiver {
		req.Receiver = netip.AddrPortFrom(addr, port)
		if err := prepareReceiver(conn, bound.Is6()); err != nil {
			conn.Close()
			return nil, AcceptInternal, err
		}
		s.rcv = newReceiver(conn, peer, req, mode, keys)
		return s, AcceptOK, nil
	}
	req.Sender = netip.AddrPortFrom(addr, port)
	if err := prepareSender(conn, bound.Is6(), uint8(req.TypeP>>24)); err != nil {
		conn.Close()
		return nil, AcceptInternal, err
	}
	select {
	case sc.srv.senders <- struct{}{}:
	default:
		conn.Close()
		return nil, AcceptTempLimit, errors.New("too many sending sessions")
	}
	s.snd = newSender(conn, peer, req, mode, keys, cfg.EndpointOptions)
	s.snd.release = func() { <-sc.srv.senders }
	return s, AcceptOK, nil
}

// listenTest opens the server's test socket on the requested address or,
// when that is not local (for instance behind NAT), on the control
// connection's local address.
func (sc *serverConn) listenTest(want netip.Addr) (*net.UDPConn, netip.Addr, error) {
	var candidates []netip.Addr
	if want.IsValid() && !want.IsUnspecified() {
		candidates = append(candidates, withZone(want, sc.local))
	}
	if want.Is4() == sc.local.Is4() && sc.local != want {
		candidates = append(candidates, sc.local)
	}
	err := errors.New("no usable local address")
	for _, a := range candidates {
		var conn *net.UDPConn
		if conn, err = listenUDP(a, sc.srv.cfg.PortRange); err == nil {
			return conn, a, nil
		}
	}
	return nil, netip.Addr{}, fmt.Errorf("opening test socket: %w", err)
}

// withinSpan bounds how far a session's start may be from now and how long
// its actual schedule plus Timeout runs, which also keeps the timestamp
// arithmetic far from overflow. The SID must be final: it seeds the
// exponential waits.
func withinSpan(req *TestRequest, now Timestamp) bool {
	limit := FromDuration(maxSessionSpan)
	if req.Timeout > limit || absDiff(req.Start, now) > limit {
		return false
	}
	budget := limit - req.Timeout
	sched := NewSchedule(req.SID, req.Slots)
	var span Timestamp
	for range req.Packets {
		d := sched.Next()
		if d > budget-span {
			return false
		}
		span += d
	}
	return true
}

// withZone gives a link-local IPv6 address the zone of the control
// connection's address, which the protocol cannot carry.
func withZone(a, ref netip.Addr) netip.Addr {
	if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" && ref.Zone() != "" {
		return a.WithZone(ref.Zone())
	}
	return a
}

func (sc *serverConn) startSessions() error {
	if err := sc.cc.recvHMAC(); err != nil {
		return err
	}
	sessions := sc.pending
	sc.pending = nil
	if err := sc.cc.sendMessage(make([]byte, blockSize)); err != nil { // Start-Ack, Accept = 0
		for _, s := range sessions {
			s.close()
		}
		return err
	}
	for _, s := range sessions {
		s.start()
	}
	err := sc.cc.runSessions(context.Background(), sessions)
	for _, s := range sessions {
		switch {
		case s.snd != nil:
			sc.srv.cfg.Logf("%s: session %s: sent %d of %d packets", sc.name, s.req.SID, s.snd.nextSeqno-skipped(s.snd.skips), s.req.Packets)
		case s.err != nil:
			sc.srv.cfg.Logf("%s: session %s: %v", sc.name, s.req.SID, s.err)
		case s.data != nil:
			sc.srv.cfg.Logf("%s: session %s: %d packet records", sc.name, s.req.SID, len(s.data.Records))
			sc.finished = append(sc.finished, s)
			if len(sc.finished) > maxFinishedSessions {
				sc.finished = sc.finished[1:]
			}
		}
	}
	return err
}

func skipped(skips []SkipRange) uint32 {
	var n uint32
	for _, s := range skips {
		n += s.Last - s.First + 1
	}
	return n
}

// fetchSession answers Fetch-Session (RFC 4656 §3.9) for sessions this
// connection received.
func (sc *serverConn) fetchSession(first []byte) error {
	rest, err := sc.cc.recvMessage(blockSize)
	if err != nil {
		return err
	}
	begin, end := getUint32(first[8:]), getUint32(first[12:])
	sid := SID(rest)
	var d *SessionData
	for _, s := range sc.finished {
		if s.req.SID == sid {
			d = s.data
		}
	}
	cc := sc.cc
	ack := make([]byte, blockSize)
	if d == nil {
		sc.srv.cfg.Logf("%s: fetch of unknown session %s refused", sc.name, sid)
		ack[0] = byte(AcceptFailure)
		return cc.sendMessage(ack)
	}

	records := d.Records
	if begin != 0 || end != math.MaxUint32 {
		records = nil
		for _, r := range d.Records {
			if r.Seq >= begin && r.Seq <= end {
				records = append(records, r)
			}
		}
	}
	ack[1] = 1 // finished
	putUint32(ack[4:], d.NextSeqno)
	putUint32(ack[8:], uint32(len(d.Skips)))
	putUint32(ack[12:], uint32(len(records)))
	steps := [][]byte{ack, nil, d.Request.marshalPreamble(), nil, d.Request.marshalSlots(), nil, marshalSkips(d.Skips), nil}
	for _, b := range steps {
		if b == nil {
			err = cc.sendHMAC()
		} else {
			err = cc.send(b)
		}
		if err != nil {
			return err
		}
	}
	const chunk = 16 // records per 25 whole blocks
	buf := make([]byte, chunk*recordSize)
	for i := 0; i < len(records); i += chunk {
		n := min(chunk, len(records)-i)
		clear(buf)
		for j := range n {
			records[i+j].marshal(buf[j*recordSize:])
		}
		if err := cc.send(buf[:roundBlocks(n*recordSize)]); err != nil {
			return err
		}
	}
	return cc.sendMessage(nil)
}
