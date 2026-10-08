package owamp

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"hash"
	"io"
	"net"
	"time"
)

var errBadHMAC = errors.New("owamp: HMAC verification failed")

// writeTimeout bounds each write so a peer that stops reading cannot stall
// the connection forever.
const writeTimeout = time.Minute

type deadlineWriter struct{ nc net.Conn }

func (w deadlineWriter) Write(b []byte) (int, error) {
	w.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	return w.nc.Write(b)
}

// controlConn frames an OWAMP-Control connection. After setup in
// authenticated and encrypted modes every block is AES-CBC encrypted as one
// stream per direction, and each HMAC block covers everything sent in that
// direction since the previous HMAC block (RFC 4656 §3.2, §3.4).
//
// One goroutine may receive while another sends: the two directions share no
// state.
type controlConn struct {
	nc   net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	mode Mode
	keys sessionKeys

	enc, dec         cipher.BlockMode // nil in open mode
	sendMAC, recvMAC hash.Hash
	sendSum, recvSum [sha1.Size]byte
}

func newControlConn(nc net.Conn) *controlConn {
	return &controlConn{nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(deadlineWriter{nc})}
}

// startCipher switches to authenticated/encrypted operation with the keys
// from the Set-Up-Response token.
func (c *controlConn) startCipher(mode Mode, keys sessionKeys, sendIV, recvIV []byte) {
	block, err := aes.NewCipher(keys.aes[:])
	if err != nil {
		panic(err)
	}
	c.mode = mode
	c.keys = keys
	c.enc = cipher.NewCBCEncrypter(block, sendIV)
	c.dec = cipher.NewCBCDecrypter(block, recvIV)
	c.sendMAC = hmac.New(sha1.New, keys.hmac[:])
	c.recvMAC = hmac.New(sha1.New, keys.hmac[:])
}

func (c *controlConn) secure() bool { return c.enc != nil }

// readRaw reads exactly n cleartext bytes (connection setup only).
func (c *controlConn) readRaw(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(c.r, b)
	return b, err
}

// recv reads n bytes (whole blocks) of message body, decrypting them and
// adding them to the receive HMAC.
func (c *controlConn) recv(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(c.r, b); err != nil {
		return nil, err
	}
	if c.secure() {
		c.dec.CryptBlocks(b, b)
		c.recvMAC.Write(b)
	}
	return b, nil
}

// recvHMAC reads an HMAC block and verifies it against everything received
// since the previous HMAC block. In open mode the block is ignored.
func (c *controlConn) recvHMAC() error {
	var b [blockSize]byte
	if _, err := io.ReadFull(c.r, b[:]); err != nil {
		return err
	}
	if !c.secure() {
		return nil
	}
	c.dec.CryptBlocks(b[:], b[:])
	sum := c.recvMAC.Sum(c.recvSum[:0])
	c.recvMAC.Reset()
	if !hmac.Equal(sum[:macSize], b[:]) {
		return errBadHMAC
	}
	return nil
}

// send queues message body bytes (whole blocks), encrypting b in place.
func (c *controlConn) send(b []byte) error {
	if c.secure() {
		c.sendMAC.Write(b)
		c.enc.CryptBlocks(b, b)
	}
	_, err := c.w.Write(b)
	return err
}

// sendHMAC queues the HMAC block covering everything sent since the previous
// one. In open mode the block is zero.
func (c *controlConn) sendHMAC() error {
	var b [blockSize]byte
	if c.secure() {
		copy(b[:], c.sendMAC.Sum(c.sendSum[:0]))
		c.sendMAC.Reset()
		c.enc.CryptBlocks(b[:], b[:])
	}
	_, err := c.w.Write(b[:])
	return err
}

// sendMessage queues body followed by its HMAC block and flushes.
func (c *controlConn) sendMessage(body []byte) error {
	if err := c.send(body); err != nil {
		return err
	}
	if err := c.sendHMAC(); err != nil {
		return err
	}
	return c.w.Flush()
}

// recvMessage reads an n-byte body followed by its HMAC block.
func (c *controlConn) recvMessage(n int) ([]byte, error) {
	b, err := c.recv(n)
	if err != nil {
		return nil, err
	}
	return b, c.recvHMAC()
}

func (c *controlConn) flush() error { return c.w.Flush() }

// deadline sets the read deadline d from now; d <= 0 clears it.
func (c *controlConn) deadline(d time.Duration) {
	if d <= 0 {
		c.nc.SetReadDeadline(time.Time{})
		return
	}
	c.nc.SetReadDeadline(time.Now().Add(d))
}

// writeTestRequest sends a complete Request-Session command.
func (c *controlConn) writeTestRequest(r *TestRequest) error {
	if err := c.send(r.marshalPreamble()); err != nil {
		return err
	}
	if err := c.sendHMAC(); err != nil {
		return err
	}
	return c.sendMessage(r.marshalSlots())
}

// readTestRequest reads the rest of a Request-Session command whose first
// block has already been received. maxSlots bounds the slot count accepted.
func (c *controlConn) readTestRequest(first []byte, maxSlots uint32) (*TestRequest, error) {
	rest, err := c.recvMessage(requestPreambleSize - blockSize)
	if err != nil {
		return nil, err
	}
	req, nslots, refused := parsePreamble(append(first, rest...))
	var ae *AcceptError
	if refused != nil && !errors.As(refused, &ae) {
		return nil, refused
	}
	if nslots == 0 || nslots > maxSlots {
		// The slot blocks cannot be skipped safely; the stream is lost.
		return nil, protocolError("Request-Session with %d slots", nslots)
	}
	slots := make([]Slot, 0, min(nslots, 1024)) // grow only as slots arrive
	for range nslots {
		b, rerr := c.recv(blockSize)
		if rerr != nil {
			return nil, rerr
		}
		s, perr := parseSlot(b)
		if perr != nil && refused == nil {
			refused = &AcceptError{Op: "Request-Session", Accept: AcceptUnsupported}
		}
		slots = append(slots, s)
	}
	if err := c.recvHMAC(); err != nil {
		return nil, err
	}
	if refused != nil { // the stream is intact; only this request is refused
		return nil, refused
	}
	req.Slots = slots
	return req, nil
}
