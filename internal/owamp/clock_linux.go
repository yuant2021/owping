package owamp

import (
	"math"
	"sync"
	"syscall"
	"time"
)

// Kernel NTP discipline constants (<sys/timex.h>).
const (
	timeError = 5      // TIME_ERROR: clock not synchronized
	staUnsync = 0x0040 // STA_UNSYNC
)

// sysClock caches the kernel clock error estimate; reading it on every packet
// would add a syscall to the timestamping path.
var sysClock clock

type clock struct {
	mu      sync.Mutex
	expires time.Time
	est     ErrorEstimate
}

// Now returns the current time and the error estimate of the system clock.
func Now() (time.Time, ErrorEstimate) {
	t := time.Now()
	return t, sysClock.estimate(t)
}

// estimate returns the error estimate valid at now, refreshing it from the
// kernel at most once per second.
func (c *clock) estimate(now time.Time) ErrorEstimate {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.expires) {
		return c.est
	}
	c.est = kernelErrorEstimate()
	c.expires = now.Add(time.Second)
	return c.est
}

// kernelErrorEstimate derives the error estimate from adjtimex(2): the
// kernel's estimated error and its synchronization state, as maintained by
// ntpd/chronyd.
func kernelErrorEstimate() ErrorEstimate {
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return NewErrorEstimate(math.MaxUint32, false)
	}
	synced := state != timeError && tx.Status&staUnsync == 0
	est := int64(tx.Esterror)
	if est <= 0 {
		est = 1 // the kernel occasionally reports 0; a zero bound is never true
	}
	if est > math.MaxUint32 {
		est = math.MaxUint32
	}
	return NewErrorEstimate(uint32(est), synced)
}
