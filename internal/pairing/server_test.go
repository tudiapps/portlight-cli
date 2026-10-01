package pairing

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/tudiapps/portlight-cli/internal/envelope"
)

// clock is a settable time source for expiry tests.
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

// phone plays the app's side of docs/pairing-protocol.md.
type phone struct {
	t        *testing.T
	base     string
	sid      []byte
	secret   []byte
	identity *age.X25519Identity
	nonce    []byte
	cliNonce []byte
}

func newPhone(t *testing.T, ts *httptest.Server, s *Server) *phone {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := envelope.Random(envelope.NonceSize)
	// Read what the QR carries, the way the app would.
	u, err := url.Parse(s.URI("ignored:1"))
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := b64.DecodeString(u.Query().Get("sid"))
	secret, _ := b64.DecodeString(u.Query().Get("k"))
	return &phone{t: t, base: ts.URL, sid: sid, secret: secret, identity: id, nonce: nonce}
}

func (p *phone) url(step string) string {
	return p.base + "/v1/pair/" + b64.EncodeToString(p.sid) + "/" + step
}

func (p *phone) post(step string, body any) (*http.Response, []byte) {
	p.t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(p.url(step), "application/json", bytes.NewReader(raw))
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func (p *phone) claimWith(secret []byte) int {
	p.t.Helper()
	recipient := p.identity.Recipient().String()
	commitment := envelope.Commitment(p.nonce)
	resp, body := p.post("claim", claimRequest{
		Recipient:  recipient,
		Commitment: b64.EncodeToString(commitment),
		MAC:        b64.EncodeToString(envelope.ClaimMAC(secret, p.sid, recipient, commitment)),
	})
	if resp.StatusCode == http.StatusOK {
		var cr claimResponse
		if err := json.Unmarshal(body, &cr); err != nil {
			p.t.Fatal(err)
		}
		p.cliNonce, _ = b64.DecodeString(cr.CLINonce)
	}
	return resp.StatusCode
}

func (p *phone) claim() int { return p.claimWith(p.secret) }

func (p *phone) revealWith(nonce []byte) int {
	p.t.Helper()
	resp, _ := p.post("reveal", revealRequest{PhoneNonce: b64.EncodeToString(nonce)})
	return resp.StatusCode
}

func (p *phone) reveal() int { return p.revealWith(p.nonce) }

func (p *phone) sas() string {
	return envelope.SAS(p.secret, p.sid, p.identity.Recipient().String(), p.cliNonce, p.nonce)
}

func (p *phone) envelope() (int, []byte) {
	p.t.Helper()
	resp, err := http.Get(p.url("envelope"))
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

type fixture struct {
	server  *Server
	ts      *httptest.Server
	clock   *clock
	shown   chan string
	approve chan bool
}

func newFixture(t *testing.T, payload string) *fixture {
	t.Helper()
	f := &fixture{
		clock:   &clock{t: time.Now()},
		shown:   make(chan string, 1),
		approve: make(chan bool, 1),
	}
	confirm := func(sas string) bool {
		f.shown <- sas
		return <-f.approve
	}
	s, err := NewServer([]byte(payload), confirm, Options{Now: f.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	f.server = s
	f.ts = httptest.NewServer(s)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fixture) waitErr(t *testing.T) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f.server.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return")
		return nil
	}
}

func TestPairingDeliversOnlyAfterConfirmation(t *testing.T) {
	f := newFixture(t, `{"hosts":["secret-host"]}`)
	p := newPhone(t, f.ts, f.server)

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
		t.Fatalf("envelope = %d %s", code, sealed)
	}
	if bytes.Contains(sealed, []byte("secret-host")) {
		t.Fatal("envelope is not encrypted")
	}
	opened, err := envelope.Open(sealed, p.identity)
	if err != nil || string(opened) != `{"hosts":["secret-host"]}` {
		t.Fatalf("opened %q, %v", opened, err)
	}
	if err := f.waitErr(t); err != nil {
		t.Fatalf("Wait = %v", err)
	}

	// Single use: the session is gone.
	if code, _ := p.envelope(); code != http.StatusGone {
		t.Fatalf("second envelope = %d", code)
	}
	if code := newPhone(t, f.ts, f.server).claim(); code != http.StatusGone {
		t.Fatalf("claim after delivery = %d", code)
	}
}

func TestClaimWithoutQRSecretIsRefusedAndDoesNotBlockThePhone(t *testing.T) {
	f := newFixture(t, "{}")
	attacker := newPhone(t, f.ts, f.server)
	wrong, _ := envelope.Random(envelope.SecretSize)

	if code := attacker.claimWith(wrong); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated claim = %d", code)
	}
	if code := newPhone(t, f.ts, f.server).claim(); code != http.StatusOK {
		t.Fatalf("real phone claim after attacker = %d", code)
	}
}

func TestSecondClaimConflicts(t *testing.T) {
	f := newFixture(t, "{}")
	if code := newPhone(t, f.ts, f.server).claim(); code != http.StatusOK {
		t.Fatal("first claim failed")
	}
	if code := newPhone(t, f.ts, f.server).claim(); code != http.StatusConflict {
		t.Fatalf("second claim = %d", code)
	}
}

func TestRevealThatBreaksCommitmentAbortsSession(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	other, _ := envelope.Random(envelope.NonceSize)

	if code := p.revealWith(other); code != http.StatusBadRequest {
		t.Fatalf("bad reveal = %d", code)
	}
	if err := f.waitErr(t); !errors.Is(err, ErrAborted) {
		t.Fatalf("Wait = %v", err)
	}
	if code := p.reveal(); code != http.StatusGone {
		t.Fatalf("reveal after abort = %d", code)
	}
}

func TestRejectedCodesSendNothing(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	p.reveal()
	<-f.shown
	f.approve <- false

	if code, body := p.envelope(); code != http.StatusForbidden || len(body) > 64 {
		t.Fatalf("envelope after reject = %d %q", code, body)
	}
	if err := f.waitErr(t); !errors.Is(err, ErrRejected) {
		t.Fatalf("Wait = %v", err)
	}
}

func TestUnclaimedSessionExpires(t *testing.T) {
	f := newFixture(t, "{}")
	f.clock.advance(HandshakeTTL)

	if code := newPhone(t, f.ts, f.server).claim(); code != http.StatusGone {
		t.Fatalf("late claim = %d", code)
	}
	if err := f.waitErr(t); !errors.Is(err, ErrExpired) {
		t.Fatalf("Wait = %v", err)
	}
}

func TestSlowDecisionExpires(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	p.reveal()
	<-f.shown
	f.clock.advance(DecisionTTL)
	f.approve <- true

	if code, _ := p.envelope(); code != http.StatusGone {
		t.Fatalf("envelope after late approval = %d", code)
	}
	if err := f.waitErr(t); !errors.Is(err, ErrExpired) {
		t.Fatalf("Wait = %v", err)
	}
}

func TestUnknownSessionIsNotFound(t *testing.T) {
	f := newFixture(t, "{}")
	resp, err := http.Post(f.ts.URL+"/v1/pair/AAAAAAAAAAAAAAAAAAAAAA/claim", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestURIKeepsSecretOutOfTheNetworkPath(t *testing.T) {
	f := newFixture(t, "{}")
	u, err := url.Parse(f.server.URI("192.168.1.5:4455", "10.0.0.9:4455"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "portlight" || q.Get("v") != "1" || q.Get("a") != "192.168.1.5:4455,10.0.0.9:4455" {
		t.Fatalf("URI = %s", u)
	}
	secret, _ := b64.DecodeString(q.Get("k"))
	sid, _ := b64.DecodeString(q.Get("sid"))
	if len(secret) != envelope.SecretSize || len(sid) != envelope.SessionIDSize {
		t.Fatalf("sizes: secret %d, sid %d", len(secret), len(sid))
	}
	// The secret authenticates the claim; only the session id is in URLs.
	if strings.Contains(newPhone(t, f.ts, f.server).url("claim"), q.Get("k")) {
		t.Fatal("secret appears in a request URL")
	}
}

func (p *phone) rejectWith(secret []byte) int {
	p.t.Helper()
	resp, _ := p.post("reject", rejectRequest{MAC: b64.EncodeToString(envelope.RejectMAC(secret, p.sid))})
	return resp.StatusCode
}

func TestRepeatedClaimGetsTheSameAnswer(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	if code := p.claim(); code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	first := p.cliNonce

	// The phone lost the response and claims again with the same keys.
	if code := p.claim(); code != http.StatusOK {
		t.Fatalf("repeated claim = %d", code)
	}
	if !bytes.Equal(first, p.cliNonce) {
		t.Fatal("repeated claim got a different nonce")
	}
	// A different phone is still refused.
	if code := newPhone(t, f.ts, f.server).claim(); code != http.StatusConflict {
		t.Fatalf("other claim = %d", code)
	}
}

func TestRejectNeedsTheQRSecret(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	wrong, _ := envelope.Random(envelope.SecretSize)

	if code := p.rejectWith(wrong); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated reject = %d", code)
	}
	if code := p.reveal(); code != http.StatusAccepted {
		t.Fatalf("session did not survive a forged reject: %d", code)
	}
}

func TestPhoneRejectWhileDesktopDecides(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	p.reveal()
	<-f.shown

	if code := p.rejectWith(p.secret); code != http.StatusNoContent {
		t.Fatalf("reject = %d", code)
	}
	if err := f.waitErr(t); !errors.Is(err, ErrRejectedOnPhone) {
		t.Fatalf("Wait = %v", err)
	}
	f.approve <- true // the desktop answering late changes nothing
	if code, _ := p.envelope(); code != http.StatusGone {
		t.Fatalf("envelope after phone reject = %d", code)
	}
}

func TestPhoneRejectAfterDesktopConfirmed(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	p.reveal()
	<-f.shown
	f.approve <- true
	// Let decide() run before the phone answers.
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.server.mu.Lock()
		st := f.server.state
		f.server.mu.Unlock()
		if st == stateConfirmed || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if code := p.rejectWith(p.secret); code != http.StatusNoContent {
		t.Fatalf("reject = %d", code)
	}
	if err := f.waitErr(t); !errors.Is(err, ErrRejectedOnPhone) {
		t.Fatalf("Wait = %v", err)
	}
}

func TestConfirmedButNeverFetchedExpires(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	p.reveal()
	<-f.shown
	f.approve <- true
	time.Sleep(50 * time.Millisecond) // decide() runs
	f.clock.advance(DecisionTTL)

	if err := f.waitErr(t); !errors.Is(err, ErrExpired) {
		t.Fatalf("Wait = %v", err)
	}
}
