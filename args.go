package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/yuant2021/owping/internal/owamp"
)

// maxSeconds bounds user-supplied intervals.
const maxSeconds = 86400

// parseSchedule parses -i: comma-separated slots "SECONDS[e|f]".
func parseSchedule(s string) ([]owamp.Slot, error) {
	var slots []owamp.Slot
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		typ := owamp.SlotExponential
		if n := len(f); n > 0 {
			switch f[n-1] {
			case 'e', 'E':
				f = f[:n-1]
			case 'f', 'F':
				typ = owamp.SlotFixed
				f = f[:n-1]
			}
		}
		v, err := strconv.ParseFloat(f, 64)
		if err != nil || !(v >= 0 && v <= maxSeconds) {
			return nil, fmt.Errorf("invalid schedule %q", s)
		}
		slots = append(slots, owamp.Slot{Type: typ, Value: owamp.FromSeconds(v)})
	}
	return slots, nil
}

// parseDSCP parses -D: a number (decimal, 0x hex or 0 octal) or a DSCP name.
func parseDSCP(s string) (uint8, error) {
	name := strings.ToLower(strings.TrimSpace(s))
	switch {
	case name == "" || name == "none" || name == "default" || name == "df":
		return 0, nil
	case name == "ef":
		return 46, nil
	case len(name) == 3 && name[:2] == "cs" && name[2] >= '0' && name[2] <= '7':
		return (name[2] - '0') << 3, nil
	case len(name) == 4 && name[:2] == "af" && name[2] >= '1' && name[2] <= '4' && name[3] >= '1' && name[3] <= '3':
		return (name[2]-'0')<<3 | (name[3]-'0')<<1, nil
	}
	v, err := strconv.ParseUint(name, 0, 8)
	if err != nil || v > 63 {
		return 0, fmt.Errorf("invalid DSCP value %q", s)
	}
	return uint8(v), nil
}

// parsePercentiles parses -a: comma-separated percentages.
func parsePercentiles(s string) ([]float64, error) {
	if s == "" {
		return nil, nil
	}
	var ps []float64
	for _, f := range strings.Split(s, ",") {
		v, err := strconv.ParseFloat(strings.TrimSpace(f), 64)
		if err != nil || !(v > 0 && v <= 100) {
			return nil, fmt.Errorf("invalid percentile %q", f)
		}
		ps = append(ps, v)
	}
	return ps, nil
}

// controlTarget splits the host argument into a display name and a
// "host:port" dial address, defaulting to the OWAMP port.
func controlTarget(arg string) (host, address string) {
	if a, err := netip.ParseAddr(arg); err == nil {
		return arg, net.JoinHostPort(a.String(), strconv.Itoa(owamp.DefaultPort))
	}
	if h, p, err := net.SplitHostPort(arg); err == nil {
		return h, net.JoinHostPort(h, p)
	}
	host = strings.TrimSuffix(strings.TrimPrefix(arg, "["), "]")
	return host, net.JoinHostPort(host, strconv.Itoa(owamp.DefaultPort))
}

// readPassphrases reads a pass-phrase file in the owamp pfstore format:
// "identity hex-encoded-pass-phrase" per line; blank lines and lines
// starting with '#' are ignored.
func readPassphrases(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	keys := make(map[string][]byte)
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || text[0] == '#' {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: expected \"identity hex-pass-phrase\"", path, line)
		}
		pass, err := hex.DecodeString(fields[1])
		if err != nil || len(pass) == 0 {
			return nil, fmt.Errorf("%s:%d: pass-phrase is not hex encoded", path, line)
		}
		if len(fields[0]) > 80 {
			return nil, fmt.Errorf("%s:%d: identity longer than 80 octets", path, line)
		}
		keys[fields[0]] = pass
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no pass-phrases", path)
	}
	return keys, nil
}

// seconds validates a non-negative seconds flag value.
func seconds(name string, v float64) (float64, error) {
	if !(v >= 0 && v <= maxSeconds) {
		return 0, fmt.Errorf("invalid %s value %v", name, v)
	}
	return v, nil
}
