package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"owping/internal/owamp"
)

func runServer(o *options) int {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	cfg := owamp.ServerConfig{
		MaxPackets: uint32(min(o.maxPackets, 1<<32-1)),
		MaxConns:   o.maxConns,
		Logf:       logger.Printf,
	}
	var err error
	ports := o.portRange
	if ports == "" {
		ports = "0"
	}
	if cfg.PortRange, err = owamp.ParsePortRange(ports); err != nil {
		errorf("%v", err)
		return 2
	}
	end, err := seconds("-E", o.endDelay)
	if err != nil {
		errorf("%v", err)
		return 2
	}
	cfg.EndDelay = time.Duration(end * float64(time.Second))
	cfg.ZeroPadding = o.zeroPadding
	if o.keyFile != "" {
		if cfg.Keys, err = readPassphrases(o.keyFile); err != nil {
			errorf("%v", err)
			return 2
		}
	}
	switch {
	case o.modes != "":
		if cfg.Modes, err = owamp.ParseModes(o.modes); err != nil {
			errorf("%v", err)
			return 2
		}
	case cfg.Keys != nil:
		cfg.Modes = owamp.ModeAuthenticated | owamp.ModeEncrypted | owamp.ModeOpen
	default:
		cfg.Modes = owamp.ModeOpen
	}
	if o.maxPackets == 0 || o.maxConns <= 0 {
		errorf("-max-packets and -max-conns must be positive")
		return 2
	}
	srv, err := owamp.NewServer(cfg)
	if err != nil {
		errorf("%v", err)
		return 2
	}

	ln, err := net.Listen(o.network(), o.listen)
	if err != nil {
		errorf("%v", err)
		if errors.Is(err, syscall.EACCES) {
			errorf("ports below 1024 need root or CAP_NET_BIND_SERVICE; try -listen :8861")
		}
		return 1
	}
	logger.Printf("owping %s: OWAMP server listening on %s, modes %s", version, ln.Addr(), cfg.Modes)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx, ln); err != nil {
		logger.Printf("%v", err)
		return 1
	}
	logger.Printf("shutting down")
	return 0
}
