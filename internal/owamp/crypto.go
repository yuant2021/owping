package owamp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"fmt"
	"hash"
	"strings"
)

// Mode is an OWAMP security mode (RFC 4656 §3.1). Values are bits so that a
// Mode can also hold the set of modes offered or accepted.
type Mode uint32

const (
	ModeOpen          Mode = 1
	ModeAuthenticated Mode = 2
	ModeEncrypted     Mode = 4

	modeMask = ModeOpen | ModeAuthenticated | ModeEncrypted
)

func (m Mode) String() string {
	switch m {
	case ModeOpen:
		return "open"
	case ModeAuthenticated:
		return "authenticated"
	case ModeEncrypted:
		return "encrypted"
	}
	var parts []string
	for _, b := range []Mode{ModeAuthenticated, ModeEncrypted, ModeOpen} {
		if m&b != 0 {
			parts = append(parts, b.String())
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

// ParseModes parses owping's -A syntax: any combination of the letters
// O(pen), A(uthenticated) and E(ncrypted).
func ParseModes(s string) (Mode, error) {
	var m Mode
	for _, c := range strings.ToUpper(s) {
		switch c {
		case 'O':
			m |= ModeOpen
		case 'A':
			m |= ModeAuthenticated
		case 'E':
			m |= ModeEncrypted
		default:
			return 0, fmt.Errorf("invalid mode %q (use letters O, A, E)", c)
		}
	}
	if m == 0 {
		return 0, fmt.Errorf("empty mode list")
	}
	return m, nil
}

// secure reports whether the mode encrypts and authenticates traffic.
func (m Mode) secure() bool { return m&(ModeAuthenticated|ModeEncrypted) != 0 }

const (
	blockSize = aes.BlockSize
	macSize   = 16 // HMAC-SHA1 truncated to 128 bits
	tokenSize = 64
)

// MinPBKDF2Count is the lowest iteration count RFC 4656 allows.
const MinPBKDF2Count = 1024

// maxPBKDF2Count bounds the work a server can make a client do.
const maxPBKDF2Count = 1 << 24

// deriveKey derives the token key from a shared passphrase (RFC 4656 §3.1).
func deriveKey(passphrase, salt []byte, count uint32) ([]byte, error) {
	return pbkdf2.Key(sha1.New, string(passphrase), salt, int(count), 16)
}

// tokenCrypt encrypts or decrypts the Set-Up-Response token with AES-CBC
// using IV=0 and the key derived from the passphrase.
func tokenCrypt(passphrase, salt []byte, count uint32, token []byte, encrypt bool) error {
	key, err := deriveKey(passphrase, salt, count)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var iv [blockSize]byte
	if encrypt {
		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(token, token)
	} else {
		cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(token, token)
	}
	return nil
}

// sessionKeys are the control-connection keys carried in the token.
type sessionKeys struct {
	aes  [16]byte
	hmac [32]byte
}

// testKeys are the per-test-session keys of RFC 4656 §4.1.2, derived from
// the control-connection keys and the SID.
type testKeys struct {
	block   cipher.Block
	hmacKey [32]byte
}

func deriveTestKeys(k *sessionKeys, sid SID) *testKeys {
	sidCipher, err := aes.NewCipher(sid[:])
	if err != nil {
		panic(err)
	}
	var aesKey [16]byte
	sidCipher.Encrypt(aesKey[:], k.aes[:])
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		panic(err)
	}
	t := &testKeys{block: block}
	var iv [blockSize]byte
	cipher.NewCBCEncrypter(sidCipher, iv[:]).CryptBlocks(t.hmacKey[:], k.hmac[:])
	return t
}

// testPacketSize returns the OWAMP-Test payload size for mode and padding.
func testPacketSize(mode Mode, padding uint32) int {
	if mode.secure() {
		return 48 + int(padding)
	}
	return 14 + int(padding)
}

// packetCodec encodes and decodes OWAMP-Test packets (RFC 4656 §4.1.2).
// It is not safe for concurrent use.
type packetCodec struct {
	mode Mode
	keys *testKeys
	mac  hash.Hash
	sum  [sha1.Size]byte
	tmp  [2 * blockSize]byte // plaintext of the protected blocks
}

func newPacketCodec(mode Mode, keys *testKeys) *packetCodec {
	c := &packetCodec{mode: mode, keys: keys}
	if mode.secure() {
		c.mac = hmac.New(sha1.New, keys.hmacKey[:])
	}
	return c
}

// sealSeq writes the sequence number. In authenticated and encrypted modes
// it also encrypts the first block, which can be done before the send
// timestamp is taken.
func (c *packetCodec) sealSeq(pkt []byte, seq uint32) {
	if !c.mode.secure() {
		putUint32(pkt[0:], seq)
		return
	}
	plain := c.tmp[:blockSize]
	clear(plain)
	putUint32(plain, seq)
	c.keys.block.Encrypt(pkt[:blockSize], plain)
}

// sealTime writes the send timestamp and finishes the packet. It may be
// called again for the same packet to retransmit with a fresh timestamp.
func (c *packetCodec) sealTime(pkt []byte, ts Timestamp, est ErrorEstimate) {
	switch c.mode {
	case ModeOpen:
		putUint64(pkt[4:], uint64(ts))
		putUint16(pkt[12:], uint16(est))
	case ModeAuthenticated:
		// The HMAC covers only the (plaintext) first block.
		putUint64(pkt[16:], uint64(ts))
		putUint16(pkt[24:], uint16(est))
		clear(pkt[26:32])
		c.mac.Reset()
		c.mac.Write(c.tmp[:blockSize])
		copy(pkt[32:48], c.mac.Sum(c.sum[:0]))
	case ModeEncrypted:
		// The HMAC covers both plaintext blocks; the second block is
		// CBC-chained to the first ciphertext block.
		plain := c.tmp[blockSize:]
		clear(plain)
		putUint64(plain, uint64(ts))
		putUint16(plain[8:], uint16(est))
		c.mac.Reset()
		c.mac.Write(c.tmp[:])
		c.mac.Sum(c.sum[:0])
		xorBlock(plain, pkt[:blockSize])
		c.keys.block.Encrypt(pkt[blockSize:2*blockSize], plain)
		copy(pkt[32:48], c.sum[:])
	}
}

// open decrypts and authenticates a received packet in place and returns its
// sequence number, send timestamp and error estimate.
func (c *packetCodec) open(pkt []byte) (seq uint32, ts Timestamp, est ErrorEstimate, ok bool) {
	if !c.mode.secure() {
		return getUint32(pkt), Timestamp(getUint64(pkt[4:])), ErrorEstimate(getUint16(pkt[12:])), true
	}
	c.mac.Reset()
	if c.mode == ModeEncrypted {
		// CBC with IV=0: P1 = D(C1), P2 = D(C2) xor C1.
		copy(c.tmp[:], pkt[:2*blockSize])
		c.keys.block.Decrypt(pkt[:blockSize], c.tmp[:blockSize])
		c.keys.block.Decrypt(pkt[blockSize:2*blockSize], c.tmp[blockSize:])
		xorBlock(pkt[blockSize:2*blockSize], c.tmp[:blockSize])
		c.mac.Write(pkt[:2*blockSize])
	} else {
		c.keys.block.Decrypt(pkt[:blockSize], pkt[:blockSize])
		c.mac.Write(pkt[:blockSize])
	}
	if !hmac.Equal(c.mac.Sum(c.sum[:0])[:macSize], pkt[32:48]) {
		return 0, 0, 0, false
	}
	return getUint32(pkt), Timestamp(getUint64(pkt[16:])), ErrorEstimate(getUint16(pkt[24:])), true
}

func xorBlock(dst, src []byte) {
	for i := range blockSize {
		dst[i] ^= src[i]
	}
}
