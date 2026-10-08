// Command owping measures one-way delay, loss, duplication and reordering
// with the One-Way Active Measurement Protocol (OWAMP, RFC 4656). It
// interoperates with the perfSONAR owping/owampd implementation and can
// also act as the server itself.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/yuant2021/owping/internal/owamp"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	// Connection.
	modes     string
	keyFile   string
	identity  string
	srcAddr   string
	ipv4      bool
	ipv6      bool
	portRange string

	// Test.
	count       uint
	schedule    string
	padding     uint
	timeout     float64
	delayStart  float64
	endDelay    float64
	dscp        string
	to          bool
	from        bool
	zeroPadding bool

	// Output.
	verbose     bool
	quiet       bool
	raw         bool
	machine     bool
	percentiles string
	units       string
	bucketWidth float64
	version     bool

	// Server.
	server     bool
	listen     string
	maxPackets uint
	maxConns   int
}

const usageText = `Usage:
  owping [options] host[:port]   one-way ping to and from an OWAMP server
  owping -server [options]       run an OWAMP server (like owampd)

Connection options:
  -A modes      modes to accept (client) or offer (server), any of
                O(pen) A(uthenticated) E(ncrypted); default AEO when
                pass-phrases are configured, otherwise O
  -u identity   identity for authenticated/encrypted modes; without -k
                the pass-phrase is read from the terminal
  -k file       pass-phrase file, one "identity hex-pass-phrase" per line
                (owamp pfstore format); the server accepts every entry
  -S address    local address for the control connection and the tests
  -4, -6        use IPv4 or IPv6 only
  -P range      UDP port range for test packets, e.g. 8760-9960, or 0 for
                any port (default: client 8760-9960, server 0)

Test options:
  -c count      packets per direction (default 100)
  -i wait       mean seconds between packets (default 0.1); a comma
                separated schedule of slots, each with suffix e for
                exponential (default) or f for fixed, e.g. 0.1e,0f
  -s padding    octets of padding per packet (default 0)
  -L timeout    seconds after which a packet counts as lost
                (default: round-trip time + 2)
  -z delay      seconds to wait before the test starts
  -E delay      seconds a sender waits after the last packet's timeout
                before stopping (default 1)
  -D dscp       DSCP value: a number or one of default, ef, cs0-cs7,
                af11-af43
  -t            test toward the server only
  -f            test from the server only
  -zero-padding pad packets with zeros instead of pseudo-random octets

Output options:
  -v            print every packet record
  -Q            quiet: no output, only the exit status
  -R            print raw packet records instead of summaries
  -M            print machine-readable summaries
  -a list       extra delay percentiles to report, e.g. 50,90,99
  -n unit       delay unit: n, u, m or s (default m)
  -b width      histogram bucket width in seconds for -M (default 0.0001)
  -V            print the version

Server options:
  -server       run as an OWAMP server
  -listen addr  control address to listen on (default :861)
  -max-packets n
                packets allowed per session (default 100000)
  -max-conns n  concurrent control connections (default 64)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	o, rest, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Print(usageText)
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "owping: %v\nRun 'owping -h' for usage.\n", err)
		return 2
	}
	switch {
	case o.version:
		fmt.Println("owping", version)
		return 0
	case o.server:
		if len(rest) > 0 {
			fmt.Fprintf(os.Stderr, "owping: unexpected argument %q in server mode\n", rest[0])
			return 2
		}
		return runServer(o)
	case len(rest) != 1:
		fmt.Fprint(os.Stderr, "owping: exactly one server address is required\nRun 'owping -h' for usage.\n")
		return 2
	}
	return runClient(o, rest[0])
}

// parseArgs parses flags, which may also follow the host argument.
func parseArgs(args []string) (*options, []string, error) {
	o := &options{}
	fs := flag.NewFlagSet("owping", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&o.modes, "A", "", "")
	fs.StringVar(&o.keyFile, "k", "", "")
	fs.StringVar(&o.identity, "u", "", "")
	fs.StringVar(&o.srcAddr, "S", "", "")
	fs.BoolVar(&o.ipv4, "4", false, "")
	fs.BoolVar(&o.ipv6, "6", false, "")
	fs.StringVar(&o.portRange, "P", "", "")

	fs.UintVar(&o.count, "c", 100, "")
	fs.StringVar(&o.schedule, "i", "0.1", "")
	fs.UintVar(&o.padding, "s", 0, "")
	fs.Float64Var(&o.timeout, "L", 0, "")
	fs.Float64Var(&o.delayStart, "z", 0, "")
	fs.Float64Var(&o.endDelay, "E", owamp.DefaultEndDelay.Seconds(), "")
	fs.StringVar(&o.dscp, "D", "", "")
	fs.BoolVar(&o.to, "t", false, "")
	fs.BoolVar(&o.from, "f", false, "")
	fs.BoolVar(&o.zeroPadding, "zero-padding", false, "")

	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.quiet, "Q", false, "")
	fs.BoolVar(&o.raw, "R", false, "")
	fs.BoolVar(&o.machine, "M", false, "")
	fs.StringVar(&o.percentiles, "a", "", "")
	fs.StringVar(&o.units, "n", "m", "")
	fs.Float64Var(&o.bucketWidth, "b", 0.0001, "")
	fs.BoolVar(&o.version, "V", false, "")

	fs.BoolVar(&o.server, "server", false, "")
	fs.StringVar(&o.listen, "listen", ":861", "")
	fs.UintVar(&o.maxPackets, "max-packets", 100000, "")
	fs.IntVar(&o.maxConns, "max-conns", 64, "")

	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		rest = append(rest, args[0])
		args = args[1:]
	}
	if o.ipv4 && o.ipv6 {
		return nil, nil, errors.New("-4 and -6 are mutually exclusive")
	}
	return o, rest, nil
}

// network returns the TCP network selected by -4/-6.
func (o *options) network() string {
	switch {
	case o.ipv4:
		return "tcp4"
	case o.ipv6:
		return "tcp6"
	}
	return "tcp"
}
