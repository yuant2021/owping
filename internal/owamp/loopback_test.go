package owamp

import (
	"context"
	"net"
	"testing"
	"time"
)

// startServer runs a server on a loopback port for the duration of the test.
func startServer(t *testing.T, cfg ServerConfig) string {
	t.Helper()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

// TestLoopbackSessions runs a complete two-way test (Request-Session in
// both directions, Start-Sessions, Stop-Sessions, Fetch-Session) against
// the server in each security mode and checks that every packet arrives
// exactly once.
func TestLoopbackSessions(t *testing.T) {
	const identity, packets = "tester", 20
	keys := map[string][]byte{identity: []byte("correct horse")}
	for _, mode := range []Mode{ModeOpen, ModeAuthenticated, ModeEncrypted} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			opts := EndpointOptions{EndDelay: 100 * time.Millisecond}
			addr := startServer(t, ServerConfig{EndpointOptions: opts, Modes: mode, Keys: keys})
			ctx := context.Background()
			c, err := Dial(ctx, addr, ClientConfig{EndpointOptions: opts, Modes: mode, KeyID: identity, Passphrase: keys[identity]})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.Mode() != mode {
				t.Fatalf("negotiated %s, want %s", c.Mode(), mode)
			}

			spec := TestSpec{
				Packets: packets,
				Slots:   []Slot{{SlotExponential, FromSeconds(0.01)}},
				Padding: 32,
				Start:   TimestampFromTime(time.Now().Add(300 * time.Millisecond)),
				Timeout: FromSeconds(2),
			}
			toSID, err := c.RequestSession(spec, true)
			if err != nil {
				t.Fatal(err)
			}
			fromSID, err := c.RequestSession(spec, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.StartSessions(); err != nil {
				t.Fatal(err)
			}
			if err := c.Wait(ctx); err != nil {
				t.Fatal(err)
			}
			to, err := c.Fetch(toSID)
			if err != nil {
				t.Fatal(err)
			}
			from, err := c.Results(fromSID)
			if err != nil {
				t.Fatal(err)
			}
			for name, d := range map[string]*SessionData{"to": to, "from": from} {
				if !d.Finished || d.NextSeqno != packets || len(d.Skips) != 0 {
					t.Errorf("%s: finished=%v next=%d skips=%v", name, d.Finished, d.NextSeqno, d.Skips)
				}
				seen := make(map[uint32]bool)
				for _, r := range d.Records {
					delay := float64(int64(r.Recv-r.Send)) / (1 << 32)
					if r.Lost() || seen[r.Seq] || r.Seq >= packets || delay < -1 || delay > 1 {
						t.Errorf("%s: unexpected record %+v", name, r)
					}
					seen[r.Seq] = true
				}
				if len(seen) != packets {
					t.Errorf("%s: %d of %d packets received", name, len(seen), packets)
				}
			}
		})
	}
}

// TestWrongPassphraseRejected checks that the server refuses a client whose
// pass-phrase does not match before any test can be requested.
func TestWrongPassphraseRejected(t *testing.T) {
	addr := startServer(t, ServerConfig{Modes: ModeEncrypted, Keys: map[string][]byte{"tester": []byte("right")}})
	_, err := Dial(context.Background(), addr, ClientConfig{Modes: ModeEncrypted, KeyID: "tester", Passphrase: []byte("wrong")})
	if err == nil {
		t.Fatal("Dial succeeded with a wrong pass-phrase")
	}
}
