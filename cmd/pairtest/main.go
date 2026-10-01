// Command pairtest runs one real pairing server on loopback with a fixed
// payload and an automatic "codes match" answer, so the Dart pairing_client
// can be tested against the actual Go implementation.
//
// It prints one JSON line to stdout — {"uri": "...", "sas_file": "..."} —
// then serves until the envelope is delivered or the session ends, and
// exits 0 on delivery, 1 otherwise. The SAS the desktop computed is written
// to sas_file so the test can compare it with its own.
//
//	go run ./cmd/pairtest [-reject] [-listen 127.0.0.1:0] [-advertise 10.0.2.2] [-relay URL]
//
// -advertise replaces the host in the QR's address, e.g. 10.0.2.2 so an
// Android emulator reaches a server listening on the host's loopback.
//
// -relay also serves the session through a mailbox relay (see
// ./cmd/devrelay) and adds r=URL to the QR. To force the relay path,
// combine it with an unreachable -advertise such as 192.0.2.1.
//
// Development only: never shipped (goreleaser builds ./cmd/portlight).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tudiapps/portlight-cli/internal/pairing"
	"github.com/tudiapps/portlight-cli/internal/relay"
	"github.com/tudiapps/portlight-cli/internal/sshconfig"
)

// fixedPayload is what the test expects to find after decrypting. The key
// is a throwaway generated for this fixture, never used anywhere.
var fixedPayload = pairing.Payload{
	Version:   pairing.PayloadVersion,
	CreatedAt: 1790000000,
	Hosts: []sshconfig.HostConfig{{
		Alias: "interop-host", HostName: "10.9.8.7", User: "deploy", Port: 2222,
		Key: "id_interop", ProxyJump: "bastion", Group: "servers", Tags: []string{},
	}},
	Keys: []sshconfig.Key{{
		Name:       "id_interop",
		Algorithm:  "ssh-ed25519",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPortlightInteropFixtureNotARealKeyAAAAAA",
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\ninterop-fixture\n-----END OPENSSH PRIVATE KEY-----\n",
	}},
	KnownHosts: []string{"interop-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture"},
}

func main() {
	reject := flag.Bool("reject", false, "answer \"codes differ\" instead of confirming")
	listen := flag.String("listen", "127.0.0.1:0", "address to listen on")
	advertise := flag.String("advertise", "", "host to put in the QR instead of the listen host")
	relayURL := flag.String("relay", "", "mailbox relay base URL to serve through as well")
	flag.Parse()
	if err := run(*reject, *listen, *advertise, *relayURL); err != nil {
		fmt.Fprintln(os.Stderr, "pairtest:", err)
		os.Exit(1)
	}
}

func run(reject bool, listen, advertise, relayURL string) error {
	var relayClient *relay.Client
	if relayURL != "" {
		c, err := relay.New(relayURL)
		if err != nil {
			return err
		}
		relayClient = c
	}
	body, err := json.Marshal(fixedPayload)
	if err != nil {
		return err
	}
	sasFile := filepath.Join(os.TempDir(), "portlight-pairtest-"+strconv.Itoa(os.Getpid())+".sas")
	confirm := func(sas string) bool {
		_ = os.WriteFile(sasFile, []byte(sas), 0o600)
		return !reject
	}
	server, err := pairing.NewServer(body, confirm, pairing.Options{})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: server}
	go func() { _ = httpServer.Serve(listener) }()
	defer server.Close(httpServer)

	addr := listener.Addr().String()
	if advertise != "" {
		_, port, _ := net.SplitHostPort(addr)
		addr = net.JoinHostPort(advertise, port)
	}
	endpoints := pairing.Endpoints{Addrs: []string{addr}}
	relayDone := make(chan error, 1)
	if relayClient != nil {
		endpoints.Relay = relayClient.URL()
		go func() { relayDone <- server.ServeRelay(context.Background(), relayClient, pairing.RelayOptions{}) }()
	} else {
		relayDone <- nil
	}
	line, _ := json.Marshal(map[string]string{
		"uri":      server.QRURI(endpoints),
		"sas_file": sasFile,
	})
	fmt.Println(string(line))

	err = server.Wait()
	// The relay loop returns once the phone has seen the outcome.
	if relayErr := <-relayDone; relayErr != nil {
		fmt.Fprintln(os.Stderr, "pairtest: relay:", relayErr)
	}
	return err
}
