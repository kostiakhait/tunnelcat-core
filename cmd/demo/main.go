// Copyright (c) 2026 Konstantin Khait

// Command demo is a minimal reference client for tunnelcat-core: it logs in
// to a control server you supply and exposes the resulting tunnel as a local
// SOCKS5 proxy (optionally also as a TUN interface). It has no dependency on
// any specific control-plane deployment beyond the plain login endpoint
// Authenticator.Login talks to — point -server at your own control node.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	core "github.com/kostiakhait/tunnelcat-core"
)

func main() {
	server := flag.String("server", "", "control server URL, e.g. https://control.example.com:443 (required)")
	apiKey := flag.String("apikey", "", "API key issued by the control server")
	user := flag.String("user", "", "username")
	pass := flag.String("pass", "", "password")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
	withTUN := flag.Bool("tun", false, "also bring up a TUN interface (requires admin/root); this demo does not configure OS routing for it")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "tunnelcat-core demo: -server is required")
		flag.Usage()
		os.Exit(2)
	}

	auth := core.NewAuthenticator(*server, *apiKey, *user, *pass)
	if err := auth.Login(); err != nil {
		log.Fatalf("login: %v", err)
	}
	log.Printf("logged in to %s", *server)

	dialer := core.NewTunnelDialer(auth)

	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *socksAddr, err)
	}
	socks := core.NewSOCKS5Server("", dialer)
	go func() {
		if err := socks.Serve(ln); err != nil {
			log.Printf("socks5 serve: %v", err)
		}
	}()
	log.Printf("SOCKS5 proxy listening on %s", ln.Addr())

	if *withTUN {
		tun := core.NewTUNBridge(ln.Addr().String())
		if err := tun.Start(); err != nil {
			log.Fatalf("tun start: %v", err)
		}
		defer tun.Stop()
		log.Printf("TUN interface %q is up at %s — configure your OS routing table to send traffic there", core.TUNDeviceName, core.TUNAddr)
	}

	log.Printf("tunnelcat-core demo running. Point a SOCKS5-aware client at %s, or Ctrl+C to exit.", ln.Addr())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Printf("shutting down")
}
