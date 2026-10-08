package owamp

import (
	"math"
	"math/bits"
	"time"
)

// Timestamp is the OWAMP time representation (RFC 4656 §4.1.2): an unsigned
// 32.32 fixed-point number of seconds. Absolute times count from
// 1900-01-01T00:00:00Z like NTP; intervals (timeouts, schedule offsets) use
// the same representation.
type Timestamp uint64

// ntpEpochOffset is the number of seconds between the NTP and Unix epochs.
const ntpEpochOffset = 2208988800

// TimestampFromTime converts a wall-clock time to an absolute Timestamp.
func TimestampFromTime(t time.Time) Timestamp {
	sec := uint64(t.Unix()+ntpEpochOffset) << 32
	frac := (uint64(t.Nanosecond()) << 32) / 1e9
	return Timestamp(sec | frac)
}

// Time converts an absolute Timestamp to wall-clock time.
func (ts Timestamp) Time() time.Time {
	return time.Unix(int64(ts>>32)-ntpEpochOffset, int64(fracToNanos(uint32(ts))))
}

// FromSeconds converts a non-negative interval in seconds.
func FromSeconds(s float64) Timestamp {
	if !(s > 0) {
		return 0
	}
	if s >= 1<<32 {
		return math.MaxUint64
	}
	return Timestamp(s * (1 << 32))
}

// FromDuration converts a non-negative interval.
func FromDuration(d time.Duration) Timestamp {
	if d <= 0 {
		return 0
	}
	sec := uint64(d / time.Second)
	ns := uint64(d % time.Second)
	return Timestamp(sec<<32 | (ns<<32)/1e9)
}

// Seconds returns the value in seconds.
func (ts Timestamp) Seconds() float64 { return float64(ts) / (1 << 32) }

// Duration returns an interval as a time.Duration.
func (ts Timestamp) Duration() time.Duration {
	return time.Duration(ts>>32)*time.Second + time.Duration(fracToNanos(uint32(ts)))
}

func fracToNanos(frac uint32) uint64 { return (uint64(frac) * 1e9) >> 32 }

// mul multiplies two 32.32 fixed-point values, computing the 128-bit product
// exactly as RFC 4656 §5.2 requires.
func mul(a, b Timestamp) Timestamp {
	hi, lo := bits.Mul64(uint64(a), uint64(b))
	return Timestamp(hi<<32 | lo>>32)
}

// absDiff returns |a-b|.
func absDiff(a, b Timestamp) Timestamp {
	if a > b {
		return a - b
	}
	return b - a
}

// ErrorEstimate is the 16-bit OWAMP timestamp error estimate
// (RFC 4656 §4.1.2): S(1) Z(1) Scale(6) Multiplier(8). The error is
// Multiplier*2^(Scale-32) seconds; S is set when the clock is synchronized to
// UTC by an external source.
type ErrorEstimate uint16

// lostSendError is the send error estimate of a lost-packet record:
// Multiplier=1, Scale=64 (truncated to 6 bits as the reference
// implementation does), S=0 (RFC 4656 §3.9).
const lostSendError ErrorEstimate = 0x0001

// NewErrorEstimate encodes an error bound given in microseconds using the
// same rounding as the reference implementation.
func NewErrorEstimate(usec uint32, synced bool) ErrorEstimate {
	err := (uint64(usec) << 32) / 1e6
	var scale uint16
	for err >= 0xff {
		err >>= 1
		scale++
	}
	err++ // account for the bits shifted off
	e := ErrorEstimate(scale<<8 | uint16(err))
	if synced {
		e |= 0x8000
	}
	return e
}

// Synchronized reports whether the S bit is set.
func (e ErrorEstimate) Synchronized() bool { return e&0x8000 != 0 }

// Valid reports whether the multiplier is non-zero; RFC 4656 requires
// discarding packets whose estimate is invalid.
func (e ErrorEstimate) Valid() bool { return e&0xff != 0 }

// Seconds returns the error bound in seconds.
func (e ErrorEstimate) Seconds() float64 {
	return math.Ldexp(float64(e&0xff), int(e>>8&0x3f)-32)
}
