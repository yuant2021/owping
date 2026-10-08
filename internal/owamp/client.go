package owamp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"time"
)

// responseTimeout bounds each wait for a server response.
const responseTimeout = time.Minute

// Bounds on fetched session data, which comes from the server.
const (
	maxFetchSlots = 1 << 20
	maxFetchSkips = 1 << 20
)

// ClientConfig configures a control-client connection.
type ClientConfig struct {
	EndpointOptions
	Network    string // "tcp" (default), "tcp4" or "tcp6"
	LocalAddr  string // local IP address for control and test traffic
	Modes      Mode   // acceptable modes; zero means ModeOpen
	KeyID      string // identity for authenticated and encrypted modes
	Passphrase []byte
}

// TestSpec holds the parameters of a requested test stream.
type TestSpec struct {
	Packets uint32
	Slots   []Slot
	Padding uint32
	Start   Timestamp
	Timeout Timestamp
	DSCP    uint8
}

// Client is a control-client connection to an OWAMP server (RFC 4656 §3).
type Client struct {
	cc       *controlConn
	opts     EndpointOptions
	local    netip.Addr
	remote   netip.AddrPort
	rtt      time.Duration
	uptime   time.Time
	sessions []*session
	started  bool
}

// Dial connects to the OWAMP server at address ("host:port") and completes
// the connection setup, choosing the most secure mode both sides accept.
func Dial(ctx context.Context, address string, cfg ClientConfig) (*Client, error) {
	if len(cfg.KeyID) > keyIDSize {
		return nil, fmt.Errorf("identity is longer than %d octets", keyIDSize)
	}
	network := cfg.Network
	if network == "" {
		network = "tcp"
	}
	var d net.Dialer
	if cfg.LocalAddr != "" {
		ip, err := netip.ParseAddr(cfg.LocalAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid local address %q", cfg.LocalAddr)
		}
		d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 0))
	}
	nc, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	local := nc.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := nc.RemoteAddr().(*net.TCPAddr).AddrPort()
	c := &Client{
		cc:     newControlConn(nc),
		opts:   cfg.EndpointOptions,
		local:  local.Addr().Unmap(),
		remote: netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()),
	}
	abort := context.AfterFunc(ctx, func() { nc.Close() })
	err = c.setup(cfg)
	if !abort() {
		err = ctx.Err()
	}
	if err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) setup(cfg ClientConfig) error {
	cc := c.cc
	cc.deadline(responseTimeout)
	b, err := cc.readRaw(greetingSize)
	if err != nil {
		return fmt.Errorf("reading server greeting: %w", err)
	}
	g := parseServerGreeting(b)
	if g.modes == 0 {
		return errors.New("server is not accepting connections")
	}
	want := cfg.Modes
	if want == 0 {
		want = ModeOpen
	}
	if cfg.KeyID == "" {
		want &^= ModeAuthenticated | ModeEncrypted
	}
	sr := setupResponse{}
	switch avail := want & g.modes; {
	case avail&ModeEncrypted != 0:
		sr.mode = ModeEncrypted
	case avail&ModeAuthenticated != 0:
		sr.mode = ModeAuthenticated
	case avail&ModeOpen != 0:
		sr.mode = ModeOpen
	default:
		// Mode 0 tells the server we will not continue.
		cc.w.Write(sr.marshal())
		cc.flush()
		return fmt.Errorf("no common mode: server offers %s, client accepts %s", g.modes, want)
	}

	var keys sessionKeys
	if sr.mode.secure() {
		if g.count < MinPBKDF2Count || g.count > maxPBKDF2Count {
			return fmt.Errorf("server requested unreasonable PBKDF2 iteration count %d", g.count)
		}
		copy(sr.keyID[:], cfg.KeyID)
		mustRandom(keys.aes[:])
		mustRandom(keys.hmac[:])
		mustRandom(sr.clientIV[:])
		copy(sr.token[:16], g.challenge[:])
		copy(sr.token[16:32], keys.aes[:])
		copy(sr.token[32:], keys.hmac[:])
		if err := tokenCrypt(cfg.Passphrase, g.salt[:], g.count, sr.token[:], true); err != nil {
			return err
		}
	}

	sent := time.Now()
	if _, err := cc.w.Write(sr.marshal()); err != nil {
		return err
	}
	if err := cc.flush(); err != nil {
		return err
	}
	resp, err := cc.readRaw(2 * blockSize)
	if err != nil {
		return fmt.Errorf("reading Server-Start: %w", err)
	}
	c.rtt = time.Since(sent)
	if a := Accept(resp[15]); a != AcceptOK {
		if sr.mode.secure() {
			return fmt.Errorf("server rejected the connection (%s): check identity and pass-phrase", a)
		}
		return &AcceptError{Op: "control connection", Accept: a}
	}
	if sr.mode.secure() {
		cc.startCipher(sr.mode, keys, sr.clientIV[:], resp[16:32])
	} else {
		cc.mode = ModeOpen
	}
	start, err := cc.recv(blockSize) // Start-Time, encrypted in secure modes
	if err != nil {
		return fmt.Errorf("reading Server-Start: %w", err)
	}
	c.uptime = Timestamp(getUint64(start)).Time()
	cc.deadline(0)
	return nil
}

// Mode returns the negotiated security mode.
func (c *Client) Mode() Mode { return c.cc.mode }

// RTTBound returns an upper bound of the round-trip time to the server,
// measured during connection setup.
func (c *Client) RTTBound() time.Duration { return c.rtt }

// ServerStart returns when the server process started, as it reports.
func (c *Client) ServerStart() time.Time { return c.uptime }

// LocalAddr returns the local address used for control and test traffic.
func (c *Client) LocalAddr() netip.Addr { return c.local }

// RemoteAddr returns the server's control address.
func (c *Client) RemoteAddr() netip.AddrPort { return c.remote }

// RequestSession asks the server for a test session between the two hosts
// of the control connection. With toServer the client sends and the server
// receives; otherwise the server sends. It returns the session's SID.
func (c *Client) RequestSession(spec TestSpec, toServer bool) (SID, error) {
	if c.started {
		return SID{}, errors.New("sessions already started")
	}
	conn, err := listenUDP(c.local, c.opts.PortRange)
	if err != nil {
		return SID{}, fmt.Errorf("opening test socket: %w", err)
	}
	v6 := c.local.Is6()
	if toServer {
		err = prepareSender(conn, v6, spec.DSCP)
	} else {
		err = prepareReceiver(conn, v6)
	}
	if err != nil {
		conn.Close()
		return SID{}, err
	}

	local := netip.AddrPortFrom(c.local, localPort(conn))
	server := netip.AddrPortFrom(c.remote.Addr(), 0)
	req := &TestRequest{
		Packets: spec.Packets,
		Padding: spec.Padding,
		Start:   spec.Start,
		Timeout: spec.Timeout,
		TypeP:   uint32(spec.DSCP&0x3f) << 24,
		Slots:   spec.Slots,
	}
	if toServer {
		req.ConfReceiver = true
		req.Sender, req.Receiver = local, server
	} else {
		req.ConfSender = true
		req.Sender, req.Receiver = server, local
		req.SID = newSID(c.local)
	}

	port, sid, err := c.request(req)
	if err != nil {
		conn.Close()
		return SID{}, err
	}
	s := &session{req: req}
	if toServer {
		req.SID = sid
		req.Receiver = netip.AddrPortFrom(server.Addr(), port)
		s.snd = newSender(conn, req.Receiver, req, c.cc.mode, c.testKeys(req.SID), c.opts)
	} else {
		req.Sender = netip.AddrPortFrom(server.Addr(), port)
		s.rcv = newReceiver(conn, req.Sender, req, c.cc.mode, c.testKeys(req.SID))
	}
	c.sessions = append(c.sessions, s)
	return req.SID, nil
}

// request sends Request-Session and returns the port and SID from
// Accept-Session.
func (c *Client) request(req *TestRequest) (uint16, SID, error) {
	c.cc.deadline(responseTimeout)
	defer c.cc.deadline(0)
	if err := c.cc.writeTestRequest(req); err != nil {
		return 0, SID{}, err
	}
	b, err := c.cc.recvMessage(2 * blockSize)
	if err != nil {
		return 0, SID{}, err
	}
	if a := Accept(b[0]); a != AcceptOK {
		return 0, SID{}, &AcceptError{Op: "Request-Session", Accept: a}
	}
	port := getUint16(b[2:])
	if port == 0 {
		return 0, SID{}, protocolError("Accept-Session without a port")
	}
	return port, SID(b[4:20]), nil
}

func (c *Client) testKeys(sid SID) *testKeys {
	if !c.cc.mode.secure() {
		return nil
	}
	return deriveTestKeys(&c.cc.keys, sid)
}

// StartSessions starts all requested sessions.
func (c *Client) StartSessions() error {
	if len(c.sessions) == 0 {
		return errors.New("no sessions requested")
	}
	b := make([]byte, blockSize)
	b[0] = cmdStartSessions
	c.cc.deadline(responseTimeout)
	defer c.cc.deadline(0)
	if err := c.cc.sendMessage(b); err != nil {
		return err
	}
	ack, err := c.cc.recvMessage(blockSize)
	if err != nil {
		return err
	}
	if a := Accept(ack[0]); a != AcceptOK {
		return &AcceptError{Op: "Start-Sessions", Accept: a}
	}
	c.started = true
	for _, s := range c.sessions {
		s.start()
	}
	return nil
}

// Wait runs the started sessions to completion and exchanges Stop-Sessions
// with the server. Cancelling ctx ends the sessions early; the data
// collected until then remains available.
func (c *Client) Wait(ctx context.Context) error {
	return c.cc.runSessions(ctx, c.sessions)
}

// Results returns the data of a finished session in which the client
// received.
func (c *Client) Results(sid SID) (*SessionData, error) {
	for _, s := range c.sessions {
		if s.req.SID != sid || s.rcv == nil {
			continue
		}
		if s.err != nil {
			return nil, s.err
		}
		if s.data == nil {
			return nil, errors.New("session has not finished")
		}
		return s.data, nil
	}
	return nil, fmt.Errorf("no local receive session %s", sid)
}

// Fetch retrieves the complete data of a finished session from the server
// (RFC 4656 §3.9).
func (c *Client) Fetch(sid SID) (*SessionData, error) {
	b := make([]byte, 2*blockSize)
	b[0] = cmdFetchSession
	putUint32(b[12:], math.MaxUint32) // Begin Seq 0 .. End Seq all ones: complete session
	copy(b[16:], sid[:])
	cc := c.cc
	cc.deadline(responseTimeout)
	defer cc.deadline(0)
	if err := cc.sendMessage(b); err != nil {
		return nil, err
	}
	ack, err := cc.recvMessage(blockSize)
	if err != nil {
		return nil, err
	}
	if a := Accept(ack[0]); a != AcceptOK {
		return nil, &AcceptError{Op: "Fetch-Session", Accept: a}
	}
	d := &SessionData{Finished: ack[1] != 0, NextSeqno: getUint32(ack[4:])}
	nskips, nrecs := getUint32(ack[8:]), getUint32(ack[12:])

	first, err := cc.recv(blockSize)
	if err != nil {
		return nil, err
	}
	req, err := cc.readTestRequest(first, maxFetchSlots)
	if err != nil {
		return nil, err
	}
	d.Request = *req
	for _, s := range c.sessions {
		if s.req.SID == sid && s.req.Packets != req.Packets {
			return nil, protocolError("fetched session has %d packets, %d were requested", req.Packets, s.req.Packets)
		}
	}
	if nskips > req.Packets || nskips > maxFetchSkips {
		return nil, protocolError("Fetch-Ack reports %d skip ranges for %d packets", nskips, req.Packets)
	}
	// Records cover each packet once plus duplicates; anything far beyond
	// that is not a plausible session.
	if uint64(nrecs) > 8*uint64(req.Packets)+1024 {
		return nil, protocolError("Fetch-Ack reports %d records for %d packets", nrecs, req.Packets)
	}
	sb, err := cc.recvMessage(roundBlocks(8 * int(nskips)))
	if err != nil {
		return nil, err
	}
	if d.Skips, err = parseSkips(sb, int(nskips)); err != nil {
		return nil, err
	}

	// Records arrive as one padded stream; 16 records are 25 whole blocks.
	const chunk = 16
	d.Records = make([]Record, 0, min(nrecs, 1<<16))
	for left := nrecs; left > 0; {
		n := min(left, chunk)
		cc.deadline(responseTimeout)
		buf, err := cc.recv(roundBlocks(int(n) * recordSize))
		if err != nil {
			return nil, err
		}
		for i := range int(n) {
			d.Records = append(d.Records, parseRecord(buf[i*recordSize:]))
		}
		left -= n
	}
	if err := cc.recvHMAC(); err != nil {
		return nil, err
	}
	return d, nil
}

// Close ends the control connection and any sessions still running.
func (c *Client) Close() error {
	for _, s := range c.sessions {
		if c.started {
			s.stop()
		} else {
			s.close()
		}
	}
	return c.cc.nc.Close()
}

func mustRandom(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}
