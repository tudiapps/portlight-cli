package pairing

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/tudiapps/portlight-cli/internal/envelope"
	"github.com/tudiapps/portlight-cli/internal/relay"
	"github.com/tudiapps/portlight-cli/internal/relay/memrelay"
)

// relayPhone plays the app's side of the relay path: it only ever talks to
// the relay, never to the desktop.
type relayPhone struct {
	t        *testing.T
	c        *relay.Client
	sid      []byte
	secret   []byte
	identity *age.X25519Identity
	nonce    []byte
	cliNonce []byte
}

func newRelayPhone(t *testing.T, s *Server, c *relay.Client) *relayPhone {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := envelope.Random(envelope.NonceSize)
	u, err := url.Parse(s.QRURI(Endpoints{Relay: c.URL()}))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("r") != c.URL() {
		t.Fatalf("QR relay = %q", q.Get("r"))
	}
	sid, _ := b64.DecodeString(q.Get("sid"))
	secret, _ := b64.DecodeString(q.Get("k"))
	return &relayPhone{t: t, c: c, sid: sid, secret: secret, identity: id, nonce: nonce}
}

func (p *relayPhone) box(name string) string {
	return b64.EncodeToString(envelope.RelayBox(p.secret, p.sid, name))
}

func (p *relayPhone) send(name string, body []byte) {
	p.t.Helper()
	if err := p.c.Put(context.Background(), p.box(name), body); err != nil {
		p.t.Fatalf("put %s: %v", name, err)
	}
}

// await collects a response frame: uint16_be(status) ‖ body.
func (p *relayPhone) await(name string) (int, []byte) {
	p.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		frame, found, err := p.c.Take(context.Background(), p.box(name), time.Second)
		if err != nil {
			p.t.Fatalf("take %s: %v", name, err)
		}
		if !found {
			continue
		}
		if len(frame) < 2 {
			p.t.Fatalf("%s: short frame %q", name, frame)
		}
		return int(binary.BigEndian.Uint16(frame)), frame[2:]
	}
	p.t.Fatalf("no answer in %s", name)
	return 0, nil
}

func (p *relayPhone) request(step string, body any) (int, []byte) {
	p.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	p.send(step, raw)
	return p.await(step + "/response")
}

func (p *relayPhone) claim() int {
	p.t.Helper()
	recipient := p.identity.Recipient().String()
	commitment := envelope.Commitment(p.nonce)
	code, body := p.request("claim", claimRequest{
		Recipient:  recipient,
		Commitment: b64.EncodeToString(commitment),
		MAC:        b64.EncodeToString(envelope.ClaimMAC(p.secret, p.sid, recipient, commitment)),
	})
	if code == http.StatusOK {
		var cr claimResponse
		if err := json.Unmarshal(body, &cr); err != nil {
			p.t.Fatal(err)
		}
		p.cliNonce, _ = b64.DecodeString(cr.CLINonce)
	}
	return code
}

func (p *relayPhone) reveal() int {
	code, _ := p.request("reveal", revealRequest{PhoneNonce: b64.EncodeToString(p.nonce)})
	return code
}

func (p *relayPhone) sas() string {
	return envelope.SAS(p.secret, p.sid, p.identity.Recipient().String(), p.cliNonce, p.nonce)
}

func (p *relayPhone) envelope() (int, []byte) { return p.request("envelope", nil) }

func (p *relayPhone) reject() {
	raw, _ := json.Marshal(rejectRequest{MAC: b64.EncodeToString(envelope.RejectMAC(p.secret, p.sid))})
	p.send("reject", raw) // fire and forget: there is no reject/response box
}

// relayRun is ServeRelay running in the background.
type relayRun struct {
	done   chan error
	cancel context.CancelFunc
	warns  atomic.Int32
}

// serveRelay runs f's session through the relay behind c.
func serveRelay(t *testing.T, f *fixture, c *relay.Client) *relayRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &relayRun{done: make(chan error, 1), cancel: cancel}
	go func() {
		r.done <- f.server.ServeRelay(ctx, c, RelayOptions{
			Wait:       time.Second,
			MinBackoff: 10 * time.Millisecond,
			MaxBackoff: 50 * time.Millisecond,
			Warn:       func(string) { r.warns.Add(1) },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("ServeRelay did not stop on cancel")
		}
	})
	return r
}

// result waits for ServeRelay to end on its own.
func (r *relayRun) result(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		r.done <- err // for Cleanup
		return err
	case <-time.After(ReportGrace + 3*time.Second):
		t.Fatal("ServeRelay did not return after the session ended")
		return nil
	}
}

func newMemRelay(t *testing.T) (*memrelay.Relay, *relay.Client) {
	t.Helper()
	m := memrelay.New(memrelay.Options{})
	ts := httptest.NewServer(m)
	t.Cleanup(ts.Close)
	c, err := relay.New(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdle)
	return m, c
}

func TestRelayOnlyPairingDelivers(t *testing.T) {
	f := newFixture(t, `{"hosts":["secret-host"]}`)
	f.ts.Close() // the phone cannot reach the desktop at all
	m, c := newMemRelay(t)
	run := serveRelay(t, f, c)
	p := newRelayPhone(t, f.server, c)

	if code := p.claim(); code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	if code := p.reveal(); code != http.StatusAccepted {
		t.Fatalf("reveal = %d", code)
	}
	if shown := <-f.shown; shown != p.sas() {
		t.Fatalf("desktop shows %q, phone computes %q", shown, p.sas())
	}
	f.approve <- true

	code, sealed := p.envelope()
	if code != http.StatusOK {
		t.Fatalf("envelope = %d %q", code, sealed)
	}
	if bytes.Contains(sealed, []byte("secret-host")) {
		t.Fatal("relay carried plaintext")
	}
	opened, err := envelope.Open(sealed, p.identity)
	if err != nil || string(opened) != `{"hosts":["secret-host"]}` {
		t.Fatalf("opened %q, %v", opened, err)
	}
	if err := f.waitErr(t); err != nil {
		t.Fatalf("Wait = %v", err)
	}
	if err := run.result(t); err != nil {
		t.Fatalf("ServeRelay = %v", err)
	}
	if n := m.Len(); n != 0 {
		t.Fatalf("relay still holds %d boxes", n)
	}
}

func TestRelayPhoneRejectEndsSession(t *testing.T) {
	f := newFixture(t, "{}")
	_, c := newMemRelay(t)
	run := serveRelay(t, f, c)
	p := newRelayPhone(t, f.server, c)
	p.claim()
	p.reveal()
	<-f.shown

	p.reject()
	if err := f.waitErr(t); !errors.Is(err, ErrRejectedOnPhone) {
		t.Fatalf("Wait = %v", err)
	}
	f.approve <- true // the desktop answering late changes nothing
	if err := run.result(t); err != nil {
		t.Fatalf("ServeRelay = %v", err)
	}
}

func TestRelayDesktopRejectDelivers403(t *testing.T) {
	f := newFixture(t, "{}")
	_, c := newMemRelay(t)
	run := serveRelay(t, f, c)
	p := newRelayPhone(t, f.server, c)
	p.claim()
	p.reveal()
	// The phone asks for the envelope right away; the answer waits for
	// the desktop's decision.
	p.send("envelope", nil)
	<-f.shown
	f.approve <- false

	code, body := p.await("envelope/response")
	if code != http.StatusForbidden || len(body) > 64 {
		t.Fatalf("envelope = %d %q", code, body)
	}
	if err := f.waitErr(t); !errors.Is(err, ErrRejected) {
		t.Fatalf("Wait = %v", err)
	}
	if err := run.result(t); err != nil {
		t.Fatalf("ServeRelay = %v", err)
	}
}

func TestRelayDownLANStillWorks(t *testing.T) {
	f := newFixture(t, "{}")
	dead := httptest.NewServer(http.NotFoundHandler())
	c, err := relay.New(dead.URL)
	if err != nil {
		t.Fatal(err)
	}
	dead.Close() // connection refused: transient, retried
	run := serveRelay(t, f, c)

	p := newPhone(t, f.ts, f.server)
	if code := p.claim(); code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	p.reveal()
	<-f.shown
	f.approve <- true
	if code, _ := p.envelope(); code != http.StatusOK {
		t.Fatalf("envelope = %d", code)
	}
	if err := f.waitErr(t); err != nil {
		t.Fatalf("Wait = %v", err)
	}
	if err := run.result(t); err != nil {
		t.Fatalf("ServeRelay = %v", err)
	}
	if run.warns.Load() == 0 {
		t.Fatal("no warning about the unreachable relay")
	}
}

func TestPermanentRelayErrorStopsOnlyTheRelay(t *testing.T) {
	f := newFixture(t, "{}")
	// Not a relay: every box is 404.
	ts := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	c, _ := relay.New(ts.URL)
	run := serveRelay(t, f, c)

	if err := run.result(t); !errors.Is(err, relay.ErrNotFound) {
		t.Fatalf("ServeRelay = %v", err)
	}
	p := newPhone(t, f.ts, f.server)
	if code := p.claim(); code != http.StatusOK {
		t.Fatalf("LAN claim after relay failure = %d", code)
	}
}

func TestClaimRaceLANAndRelayExactlyOneWins(t *testing.T) {
	for range 5 {
		f := newFixture(t, "{}")
		_, c := newMemRelay(t)
		serveRelay(t, f, c)
		lan := newPhone(t, f.ts, f.server)
		rp := newRelayPhone(t, f.server, c)

		var wg sync.WaitGroup
		var lanCode, relayCode int
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; lanCode = lan.claim() }()
		go func() { defer wg.Done(); <-start; relayCode = rp.claim() }()
		close(start)
		wg.Wait()

		codes := []int{lanCode, relayCode}
		ok, conflict := 0, 0
		for _, code := range codes {
			switch code {
			case http.StatusOK:
				ok++
			case http.StatusConflict:
				conflict++
			}
		}
		if ok != 1 || conflict != 1 {
			t.Fatalf("LAN %d, relay %d; want one 200 and one 409", lanCode, relayCode)
		}
	}
}

func TestRelayJunkThenRealClaim(t *testing.T) {
	f := newFixture(t, "{}")
	_, c := newMemRelay(t)
	serveRelay(t, f, c)
	p := newRelayPhone(t, f.server, c)

	p.send("claim", []byte("not json"))
	if code, _ := p.await("claim/response"); code != http.StatusBadRequest {
		t.Fatalf("junk claim = %d", code)
	}
	p.send("claim", bytes.Repeat([]byte("x"), 64<<10))
	if code, _ := p.await("claim/response"); code != http.StatusBadRequest {
		t.Fatalf("oversize claim = %d", code)
	}
	if code := p.claim(); code != http.StatusOK {
		t.Fatalf("real claim after junk = %d", code)
	}
	if code := p.reveal(); code != http.StatusAccepted {
		t.Fatalf("reveal = %d", code)
	}
}

func TestLateRelayClaimGets410AndLoopEnds(t *testing.T) {
	f := newFixture(t, "{}")
	_, c := newMemRelay(t)
	run := serveRelay(t, f, c)
	f.clock.advance(HandshakeTTL)

	p := newRelayPhone(t, f.server, c)
	if code := p.claim(); code != http.StatusGone {
		t.Fatalf("late claim = %d", code)
	}
	if err := run.result(t); err != nil {
		t.Fatalf("ServeRelay = %v", err)
	}
}

func TestQRCarriesRelayOnlyWhenSet(t *testing.T) {
	f := newFixture(t, "{}")
	plain, _ := url.Parse(f.server.URI("10.0.0.2:4455"))
	if plain.Query().Has("r") {
		t.Fatal("r present without a relay")
	}
	withRelay, _ := url.Parse(f.server.QRURI(Endpoints{
		Addrs: []string{"10.0.0.2:4455"},
		Relay: "https://relay.example.com/base",
	}))
	q := withRelay.Query()
	if q.Get("r") != "https://relay.example.com/base" || q.Get("a") != "10.0.0.2:4455" {
		t.Fatalf("URI = %s", withRelay)
	}
	if !strings.Contains(withRelay.RawQuery, "r=https%3A%2F%2Frelay.example.com%2Fbase") {
		t.Fatalf("r is not URL-encoded: %s", withRelay.RawQuery)
	}
}
