// Command devrelay runs an in-memory pairing relay (API v1, see
// docs/pairing-protocol.md "Relay (son yedek)") for local development and
// interop tests.
//
// It prints one JSON line to stdout — {"url": "http://127.0.0.1:NNNN"} —
// and serves until interrupted. Nothing is logged or written to disk.
//
//	go run ./cmd/devrelay [-listen 127.0.0.1:0]
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
	"os/signal"
	"time"

	"github.com/tudiapps/portlight-cli/internal/relay/memrelay"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "address to listen on")
	flag.Parse()
	if err := run(*listen); err != nil {
		fmt.Fprintln(os.Stderr, "devrelay:", err)
		os.Exit(1)
	}
}

func run(listen string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           memrelay.New(memrelay.Options{}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	line, _ := json.Marshal(map[string]string{"url": "http://" + listener.Addr().String()})
	fmt.Println(string(line))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- server.Serve(listener) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}
