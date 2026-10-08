package owamp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PortRange is an inclusive range of UDP ports for test sessions. The zero
// value lets the kernel choose an ephemeral port.
type PortRange struct {
	Low, High uint16
}

// ParsePortRange parses "0" (any port), "N" or "LOW-HIGH".
func ParsePortRange(s string) (PortRange, error) {
	lo, hi, isRange := strings.Cut(s, "-")
	low, err := strconv.ParseUint(lo, 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port range %q", s)
	}
	high := low
	if isRange {
		if high, err = strconv.ParseUint(hi, 10, 16); err != nil {
			return PortRange{}, fmt.Errorf("invalid port range %q", s)
		}
	}
	if low == 0 && high == 0 {
		return PortRange{}, nil
	}
	if low == 0 || high < low {
		return PortRange{}, fmt.Errorf("invalid port range %q", s)
	}
	return PortRange{Low: uint16(low), High: uint16(high)}, nil
}

func (p PortRange) String() string {
	if p.Low == 0 {
		return "0"
	}
	return fmt.Sprintf("%d-%d", p.Low, p.High)
}

// listenUDP opens a test socket on addr using a port from pr, starting the
// search at a random port so concurrent sessions rarely collide.
func listenUDP(addr netip.Addr, pr PortRange) (*net.UDPConn, error) {
	network := "udp4"
	if addr.Is6() {
		network = "udp6"
	}
	if pr.Low == 0 {
		return net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)))
	}
	n := int(pr.High-pr.Low) + 1
	first := rand.IntN(n)
	var err error
	for i := range n {
		port := pr.Low + uint16((first+i)%n)
		var c *net.UDPConn
		c, err = net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port)))
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) && !errors.Is(err, syscall.EACCES) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("no free UDP port in range %s: %w", pr, err)
}

func localPort(c *net.UDPConn) uint16 {
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

func setsockopt(c *net.UDPConn, f func(fd int) error) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = f(int(fd)) }); err != nil {
		return err
	}
	return serr
}

// prepareSender sets the TTL / hop limit to 255 as RFC 4656 §4.1.2 asks,
// so receivers can count hops, and applies the requested DSCP.
func prepareSender(c *net.UDPConn, v6 bool, dscp uint8) error {
	return setsockopt(c, func(fd int) error {
		level, ttlOpt, tosOpt := syscall.IPPROTO_IP, syscall.IP_TTL, syscall.IP_TOS
		if v6 {
			level, ttlOpt, tosOpt = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, syscall.IPV6_TCLASS
		}
		if err := syscall.SetsockoptInt(fd, level, ttlOpt, 255); err != nil {
			return fmt.Errorf("set TTL: %w", err)
		}
		if dscp != 0 {
			if err := syscall.SetsockoptInt(fd, level, tosOpt, int(dscp)<<2); err != nil {
				return fmt.Errorf("set DSCP: %w", err)
			}
		}
		return nil
	})
}

// prepareReceiver enables kernel receive timestamps and TTL / hop limit
// reporting.
func prepareReceiver(c *net.UDPConn, v6 bool) error {
	return setsockopt(c, func(fd int) error {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			return fmt.Errorf("enable SO_TIMESTAMPNS: %w", err)
		}
		level, opt := syscall.IPPROTO_IP, syscall.IP_RECVTTL
		if v6 {
			level, opt = syscall.IPPROTO_IPV6, syscall.IPV6_RECVHOPLIMIT
		}
		if err := syscall.SetsockoptInt(fd, level, opt, 1); err != nil {
			return fmt.Errorf("enable TTL reporting: %w", err)
		}
		return nil
	})
}

// oobSize fits SCM_TIMESTAMPNS plus IP_TTL/IPV6_HOPLIMIT control messages.
const oobSize = 128

// parseRxControl extracts the kernel receive timestamp and the TTL / hop
// limit from a received packet's ancillary data. The TTL is 255 when
// unavailable, as RFC 4656 §4.2 requires.
func parseRxControl(oob []byte) (ts time.Time, haveTS bool, ttl uint8) {
	ttl = 255
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, m := range msgs {
		level, typ := int(m.Header.Level), int(m.Header.Type)
		switch {
		case level == syscall.SOL_SOCKET && typ == syscall.SO_TIMESTAMPNS:
			// struct timespec in native layout: 64-bit fields, or 32-bit
			// fields on 32-bit architectures.
			switch len(m.Data) {
			case 16:
				ts = time.Unix(int64(binary.NativeEndian.Uint64(m.Data)), int64(binary.NativeEndian.Uint64(m.Data[8:])))
				haveTS = true
			case 8:
				ts = time.Unix(int64(int32(binary.NativeEndian.Uint32(m.Data))), int64(int32(binary.NativeEndian.Uint32(m.Data[4:]))))
				haveTS = true
			}
		case level == syscall.IPPROTO_IP && typ == syscall.IP_TTL,
			level == syscall.IPPROTO_IPV6 && typ == syscall.IPV6_HOPLIMIT:
			if len(m.Data) >= 4 {
				ttl = uint8(binary.NativeEndian.Uint32(m.Data))
			}
		}
	}
	return
}

// precise sleeping for the sender thread

const prSetTimerSlack = 29 // PR_SET_TIMERSLACK

// setTimerSlack minimizes the kernel's timer slack for the calling thread so
// nanosleep wakes up close to the requested time. Best effort.
func setTimerSlack() {
	syscall.RawSyscall(syscall.SYS_PRCTL, prSetTimerSlack, 1, 0)
}

// nanosleep sleeps for d on the calling OS thread; unlike time.Sleep it is
// not rounded to the runtime's millisecond poller granularity.
func nanosleep(d time.Duration) {
	ts := syscall.NsecToTimespec(int64(d))
	syscall.Nanosleep(&ts, nil)
}
