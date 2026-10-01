package relay_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tudiapps/portlight-cli/internal/relay"
	"github.com/tudiapps/portlight-cli/internal/relay/memrelay"
)

// clock is a settable time source for TTL tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newID(b byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func newRelay(t *testing.T, opts memrelay.Options) (*memrelay.Relay, *relay.Client) {
	t.Helper()
	m := memrelay.New(opts)
	ts := httptest.NewServer(m)
	t.Cleanup(ts.Close)
	c, err := relay.New(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdle)
	return m, c
}

func TestPutThenTakeDeletes(t *testing.T) {
	m, c := newRelay(t, memrelay.Options{})
	ctx := context.Background()
	id := newID(1)

	if err := c.Put(ctx, id, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, id, []byte("again")); !errors.Is(err, relay.ErrBoxFull) {
		t.Fatalf("second put = %v", err)
	}
	body, found, err := c.Take(ctx, id, 0)
	if err != nil || !found || string(body) != "sealed" {
		t.Fatalf("take = %q %v %v", body, found, err)
	}
	if _, found, err := c.Take(ctx, id, 0); err != nil || found {
		t.Fatalf("second take = %v %v", found, err)
	}
	if m.Len() != 0 {
		t.Fatalf("relay still holds %d boxes", m.Len())
	}
	// A taken box can be filled again.
	if err := c.Put(ctx, id, nil); err != nil {
		t.Fatalf("empty put after take = %v", err)
	}
	if body, found, _ := c.Take(ctx, id, 0); !found || len(body) != 0 {
		t.Fatalf("empty body = %q %v", body, found)
	}
}

func TestTakeWaitsForPut(t *testing.T) {
	_, c := newRelay(t, memrelay.Options{})
	ctx := context.Background()
	id := newID(2)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = c.Put(ctx, id, []byte("late"))
	}()
	start := time.Now()
	body, found, err := c.Take(ctx, id, 5*time.Second)
	if err != nil || !found || string(body) != "late" {
		t.Fatalf("take = %q %v %v", body, found, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("take did not return when the box was filled")
	}
}

func TestTakeTimesOutEmpty(t *testing.T) {
	_, c := newRelay(t, memrelay.Options{MaxWait: 100 * time.Millisecond})
	// The client asks for 1 s; the relay caps it.
	if _, found, err := c.Take(context.Background(), newID(3), time.Second); err != nil || found {
		t.Fatalf("take = %v %v", found, err)
	}
}

func TestConcurrentTakersExactlyOneWins(t *testing.T) {
	_, c := newRelay(t, memrelay.Options{})
	ctx := context.Background()
	id := newID(4)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, found, err := c.Take(ctx, id, time.Second); err == nil && found {
				wins.Add(1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	if err := c.Put(ctx, id, []byte("x")); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d takers got the blob", wins.Load())
	}
}

func TestBlobExpires(t *testing.T) {
	clk := &clock{t: time.Now()}
	_, c := newRelay(t, memrelay.Options{Now: clk.now})
	ctx := context.Background()
	id := newID(5)
	if err := c.Put(ctx, id, []byte("x")); err != nil {
		t.Fatal(err)
	}
	clk.advance(relay.BoxTTL)
	if _, found, err := c.Take(ctx, id, 0); err != nil || found {
		t.Fatalf("expired take = %v %v", found, err)
	}
}

func TestRelayStatusCodes(t *testing.T) {
	m := memrelay.New(memrelay.Options{})
	ts := httptest.NewServer(m)
	defer ts.Close()
	do := func(method, path string, body []byte) int {
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	cases := []struct {
		name, method, path string
		body               []byte
		want               int
	}{
		{"health", http.MethodGet, "/v1/health", nil, http.StatusOK},
		{"put", http.MethodPut, "/v1/box/" + newID(6), []byte("x"), http.StatusCreated},
		{"put full", http.MethodPut, "/v1/box/" + newID(6), []byte("y"), http.StatusConflict},
		{"take", http.MethodGet, "/v1/box/" + newID(6) + "?wait=0", nil, http.StatusOK},
		{"take empty", http.MethodGet, "/v1/box/" + newID(6), nil, http.StatusNoContent},
		{"short id", http.MethodPut, "/v1/box/abc", nil, http.StatusNotFound},
		{"bad char", http.MethodGet, "/v1/box/" + strings.Repeat("!", 43), nil, http.StatusNotFound},
		{"long id", http.MethodGet, "/v1/box/" + newID(6) + "A", nil, http.StatusNotFound},
		{"too large", http.MethodPut, "/v1/box/" + newID(7), make([]byte, relay.MaxBody+1), http.StatusRequestEntityTooLarge},
		{"max size", http.MethodPut, "/v1/box/" + newID(8), make([]byte, relay.MaxBody), http.StatusCreated},
		{"bad wait", http.MethodGet, "/v1/box/" + newID(9) + "?wait=x", nil, http.StatusBadRequest},
	}
	for _, tc := range cases {
		if got := do(tc.method, tc.path, tc.body); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestTypedErrors(t *testing.T) {
	var code atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(code.Load()))
	}))
	defer ts.Close()
	c, err := relay.New(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		code      int
		want      error
		permanent bool
	}{
		{http.StatusConflict, relay.ErrBoxFull, false},
		{http.StatusRequestEntityTooLarge, relay.ErrTooLarge, true},
		{http.StatusTooManyRequests, relay.ErrRateLimited, false},
		{http.StatusNotFound, relay.ErrNotFound, true},
	}
	for _, tc := range cases {
		code.Store(int32(tc.code))
		err := c.Put(context.Background(), newID(1), nil)
		if !errors.Is(err, tc.want) || relay.IsPermanent(err) != tc.permanent {
			t.Errorf("%d: %v (permanent %v)", tc.code, err, relay.IsPermanent(err))
		}
	}
	code.Store(http.StatusBadGateway)
	_, _, err = c.Take(context.Background(), newID(1), 0)
	var se *relay.StatusError
	if !errors.As(err, &se) || se.Code != http.StatusBadGateway || relay.IsPermanent(err) {
		t.Fatalf("502 = %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer elsewhere.Close()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer ts.Close()
	c, _ := relay.New(ts.URL)
	err := c.Put(context.Background(), newID(1), []byte("x"))
	if !relay.IsPermanent(err) || hits.Load() != 0 {
		t.Fatalf("redirect: %v, followed %d times", err, hits.Load())
	}
}

func TestErrorsDoNotCarryBoxIDs(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	c, _ := relay.New(ts.URL)
	ts.Close() // connection refused from now on
	id := newID(9)
	_, _, err := c.Take(context.Background(), id, 0)
	var te *relay.TransportError
	if !errors.As(err, &te) || relay.IsPermanent(err) {
		t.Fatalf("take on closed relay = %v", err)
	}
	if strings.Contains(err.Error(), id) {
		t.Fatalf("error leaks the box id: %v", err)
	}
}

func TestClientRefusesBadInput(t *testing.T) {
	_, c := newRelay(t, memrelay.Options{})
	if err := c.Put(context.Background(), "not-an-id", nil); err == nil {
		t.Fatal("malformed id accepted")
	}
	if err := c.Put(context.Background(), newID(1), make([]byte, relay.MaxBody+1)); !errors.Is(err, relay.ErrTooLarge) {
		t.Fatalf("oversize put = %v", err)
	}
}

func TestParseURL(t *testing.T) {
	ok := map[string]string{
		"https://relay.example.com":        "https://relay.example.com",
		"https://relay.example.com/":       "https://relay.example.com",
		"https://relay.example.com/base/":  "https://relay.example.com/base",
		"http://127.0.0.1:8080":            "http://127.0.0.1:8080",
		"http://[::1]:8080":                "http://[::1]:8080",
		"http://localhost:8080":            "http://localhost:8080",
		"  https://relay.example.com:443 ": "https://relay.example.com:443",
	}
	for in, want := range ok {
		u, err := relay.ParseURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%q = %v, %v; want %q", in, u, err, want)
		}
	}
	for _, in := range []string{
		"http://relay.example.com",
		"http://192.168.1.2:8080",
		"ftp://relay.example.com",
		"relay.example.com",
		"https://user:pw@relay.example.com",
		"https://relay.example.com/?x=1",
		"https://relay.example.com/#frag",
		"",
	} {
		if _, err := relay.ParseURL(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
