package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yuant2021/owping/internal/owamp"
	"github.com/yuant2021/owping/internal/stats"
)

// clientDefaultPorts is owping's default test port range.
const clientDefaultPorts = "8760-9960"

func errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "owping: "+format+"\n", args...)
}

// testParams are the validated test options.
type testParams struct {
	spec        owamp.TestSpec // Start is set once connected
	timeout     float64        // seconds; 0 means round-trip time + 2
	delayStart  time.Duration
	units       stats.Units
	percentiles []float64
}

func parseTestParams(o *options) (*testParams, error) {
	p := &testParams{}
	var err error
	if o.count == 0 || o.count > 1<<32-1 {
		return nil, fmt.Errorf("invalid packet count %d", o.count)
	}
	if o.padding > 65000 {
		return nil, fmt.Errorf("padding %d exceeds 65000 octets", o.padding)
	}
	if p.spec.Slots, err = parseSchedule(o.schedule); err != nil {
		return nil, err
	}
	if p.spec.DSCP, err = parseDSCP(o.dscp); err != nil {
		return nil, err
	}
	if p.timeout, err = seconds("-L", o.timeout); err != nil {
		return nil, err
	}
	delay, err := seconds("-z", o.delayStart)
	if err != nil {
		return nil, err
	}
	if p.units, err = stats.ParseUnits(o.units); err != nil {
		return nil, err
	}
	if p.percentiles, err = parsePercentiles(o.percentiles); err != nil {
		return nil, err
	}
	if !(o.bucketWidth > 0) {
		return nil, fmt.Errorf("invalid bucket width %v", o.bucketWidth)
	}
	p.spec.Packets = uint32(o.count)
	p.spec.Padding = uint32(o.padding)
	p.delayStart = time.Duration(delay * float64(time.Second))
	return p, nil
}

func clientConfig(o *options) (owamp.ClientConfig, error) {
	cfg := owamp.ClientConfig{Network: o.network(), LocalAddr: o.srcAddr, KeyID: o.identity}
	var err error
	ports := o.portRange
	if ports == "" {
		ports = clientDefaultPorts
	}
	if cfg.PortRange, err = owamp.ParsePortRange(ports); err != nil {
		return cfg, err
	}
	end, err := seconds("-E", o.endDelay)
	if err != nil {
		return cfg, err
	}
	cfg.EndDelay = time.Duration(end * float64(time.Second))
	cfg.ZeroPadding = o.zeroPadding

	switch {
	case o.modes != "":
		if cfg.Modes, err = owamp.ParseModes(o.modes); err != nil {
			return cfg, err
		}
	case o.identity != "":
		cfg.Modes = owamp.ModeAuthenticated | owamp.ModeEncrypted | owamp.ModeOpen
	default:
		cfg.Modes = owamp.ModeOpen
	}
	if cfg.Modes&owamp.ModeOpen == 0 && o.identity == "" {
		return cfg, errors.New("authenticated and encrypted modes need an identity (-u)")
	}
	if o.keyFile != "" && o.identity == "" {
		return cfg, errors.New("-k needs an identity (-u)")
	}
	if o.identity != "" {
		if o.keyFile != "" {
			keys, err := readPassphrases(o.keyFile)
			if err != nil {
				return cfg, err
			}
			if cfg.Passphrase = keys[o.identity]; cfg.Passphrase == nil {
				return cfg, fmt.Errorf("no pass-phrase for identity %q in %s", o.identity, o.keyFile)
			}
		} else {
			if cfg.Passphrase, err = readPassphrase(fmt.Sprintf("Enter passphrase for identity '%s': ", o.identity)); err != nil {
				return cfg, fmt.Errorf("reading pass-phrase: %w", err)
			}
		}
	}
	return cfg, nil
}

func runClient(o *options, target string) int {
	p, err := parseTestParams(o)
	if err != nil {
		errorf("%v", err)
		return 2
	}
	cfg, err := clientConfig(o)
	if err != nil {
		errorf("%v", err)
		return 2
	}
	if o.raw {
		o.quiet = true
	}
	to, from := o.to, o.from
	if !to && !from {
		to, from = true, true
	}

	// The first interrupt during the test stops it early and still reports
	// the results; any other interrupt exits at once.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var testing atomic.Bool
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigs
		if !testing.Load() {
			os.Exit(2)
		}
		cancel()
		<-sigs
		os.Exit(2)
	}()

	host, address := controlTarget(target)
	c, err := owamp.Dial(ctx, address, cfg)
	if err != nil {
		errorf("unable to open control connection to %s: %v", target, err)
		return 1
	}
	defer c.Close()

	// Defaults follow owping: the loss timeout is the round-trip bound plus
	// two seconds, and the test starts once every request had time for a
	// round trip, plus a second.
	rtt := c.RTTBound()
	timeout := p.timeout
	if timeout <= 0 {
		timeout = rtt.Seconds() + 2
	}
	rtts := 1
	if to {
		rtts++
	}
	if from {
		rtts++
	}
	start := time.Now().Add(max(time.Duration(rtts)*rtt+time.Second, p.delayStart))
	p.spec.Start = owamp.TimestampFromTime(start)
	p.spec.Timeout = owamp.FromSeconds(timeout)

	var toSID, fromSID owamp.SID
	if to {
		if toSID, err = c.RequestSession(p.spec, true); err != nil {
			errorf("unable to set up the test to %s: %v", target, err)
			return 1
		}
	}
	if from {
		if fromSID, err = c.RequestSession(p.spec, false); err != nil {
			errorf("unable to set up the test from %s: %v", target, err)
			return 1
		}
	}
	testing.Store(true)
	if err := c.StartSessions(); err != nil {
		errorf("unable to start the test: %v", err)
		return 1
	}
	if !o.quiet {
		duration := float64(p.spec.Packets)*owamp.MeanInterval(p.spec.Slots) + timeout + rtt.Seconds()
		fmt.Printf("Approximately %.1f seconds until results available\n", time.Until(start).Seconds()+duration)
	}
	if err := c.Wait(ctx); err != nil {
		errorf("test session(s) failed: %v", err)
		return 1
	}

	local := c.LocalAddr().String()
	status := 0
	if to {
		data, err := c.Fetch(toSID)
		if err != nil {
			errorf("unable to fetch data for sid(%s): %v", toSID, err)
			status = 1
		} else {
			report(o, p, data, stats.Endpoint{Host: local, Addr: data.Request.Sender}, stats.Endpoint{Host: host, Addr: data.Request.Receiver})
		}
	}
	if from {
		data, err := c.Results(fromSID)
		if err != nil {
			errorf("session %s: %v", fromSID, err)
			status = 1
		} else {
			report(o, p, data, stats.Endpoint{Host: host, Addr: data.Request.Sender}, stats.Endpoint{Host: local, Addr: data.Request.Receiver})
		}
	}
	return status
}

func report(o *options, p *testParams, d *owamp.SessionData, from, to stats.Endpoint) {
	w := os.Stdout
	if o.raw {
		stats.WriteRaw(w, d)
		return
	}
	if o.quiet {
		return
	}
	if o.verbose {
		stats.WriteRecords(w, d, p.units)
	}
	s := stats.Summarize(d, from, to)
	if o.machine {
		s.WriteMachine(w, o.bucketWidth)
	} else {
		s.WriteSummary(w, p.units, p.percentiles)
	}
}
