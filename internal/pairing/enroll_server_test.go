package pairing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tudiapps/portlight-cli/internal/enroll"
	"github.com/tudiapps/portlight-cli/internal/envelope"
	"golang.org/x/crypto/ssh"
)

type handled struct {
	req enroll.Request
	pub ssh.PublicKey
}

type enrollFixture struct {
	*fixture
	ek       []byte
	requests chan handled
	answer   chan []enroll.Result // nil result slice + closed = declined
	approve  chan bool
}

func newEnrollFixture(t *testing.T) *enrollFixture {
	t.Helper()
	ek, _ := envelope.Random(envelope.EnrollKeySize)
	f := &enrollFixture{
		fixture: &fixture{
			clock:   &clock{t: time.Now()},
			shown:   make(chan string, 1),
			approve: make(chan bool, 1),
		},
		ek:       ek,
		requests: make(chan handled, 1),
		answer:   make(chan []enroll.Result, 1),
		approve:  make(chan bool, 1),
	}
	confirm := func(sas string) bool {
		f.shown <- sas
		return <-f.fixture.approve
	}
	handle := func(_ context.Context, req enroll.Request, pub ssh.PublicKey) ([]enroll.Result, bool) {
		f.requests <- handled{req, pub}
		if !<-f.approve {
			return nil, false
		}
		return <-f.answer, true
	}
	s, err := NewServer([]byte(`{"version":1}`), confirm, Options{
		Now:    f.clock.now,
		Enroll: &EnrollHandler{Key: ek, Handle: handle},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.server = s
	f.ts = httptest.NewServer(s)
	t.Cleanup(f.ts.Close)
	return f
}

// deliver runs the v1 handshake to the end, as a phone that confirmed.
func (f *enrollFixture) deliver(t *testing.T) *phone {
	t.Helper()
	p := newPhone(t, f.ts, f.server)
	if p.claim() != http.StatusOK || p.reveal() != http.StatusAccepted {
		t.Fatal("handshake failed")
	}
	<-f.shown
	f.fixture.approve <- true
	if code, _ := p.envelope(); code != http.StatusOK {
		t.Fatalf("envelope = %d", code)
	}
	return p
}

func phonePublicKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pubRaw, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(pubRaw)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " phone", pub
}

func (p *phone) sendEnroll(ek []byte, req any) int {
	p.t.Helper()
	plain, _ := json.Marshal(req)
	box, err := envelope.SealEnrollRequest(ek, p.sid, plain)
	if err != nil {
		p.t.Fatal(err)
	}
	resp, _ := p.post("enroll", box)
	return resp.StatusCode
}

func (p *phone) enrollResult(ek []byte) (int, enroll.Report, []byte) {
	p.t.Helper()
	resp, err := http.Get(p.url("enroll/result"))
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var report enroll.Report
	if resp.StatusCode == http.StatusOK {
		var box envelope.Box
		if err := json.Unmarshal(raw, &box); err != nil {
			p.t.Fatal(err)
		}
		plain, err := envelope.OpenEnrollResult(ek, p.sid, box)
		if err != nil {
			p.t.Fatal(err)
		}
		if err := json.Unmarshal(plain, &report); err != nil {
			p.t.Fatal(err)
		}
	}
	return resp.StatusCode, report, raw
}

func (p *phone) closeEnroll(ek []byte) int {
	resp, _ := p.post("close", rejectRequest{MAC: b64.EncodeToString(envelope.EnrollCloseMAC(ek, p.sid))})
	return resp.StatusCode
}

var oneHost = []enroll.Host{{Alias: "prod-secret", HostName: "10.0.0.1", User: "ubuntu", Port: 22}}

func TestEnrollDeliversSealedPerHostResults(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	line, pub := phonePublicKey(t)

	if code := p.sendEnroll(f.ek, enroll.Request{PublicKey: line, Hosts: oneHost}); code != http.StatusAccepted {
		t.Fatalf("enroll = %d", code)
	}
	got := <-f.requests
	if got.req.Hosts[0] != oneHost[0] || !bytes.Equal(got.pub.Marshal(), pub.Marshal()) {
		t.Fatalf("handler got %+v", got.req)
	}
	f.approve <- true
	want := []enroll.Result{{Alias: "prod-secret", Status: enroll.StatusAdded, HostKey: "ssh-ed25519 AAAA"}}
	f.answer <- want

	code, report, raw := p.enrollResult(f.ek)
	if code != http.StatusOK || len(report.Results) != 1 || report.Results[0] != want[0] {
		t.Fatalf("result = %d %+v", code, report)
	}
	if bytes.Contains(raw, []byte("prod-secret")) {
		t.Fatal("result travels in the clear")
	}
	if err := f.waitErr(t); err != nil {
		t.Fatalf("Wait = %v", err)
	}
	if outcome, results := f.server.Enrollment(); outcome != EnrollCompleted || len(results) != 1 {
		t.Fatalf("Enrollment = %v %v", outcome, results)
	}
	// Single use.
	if code := p.sendEnroll(f.ek, enroll.Request{PublicKey: line, Hosts: oneHost}); code != http.StatusGone {
		t.Fatalf("enroll after the end = %d", code)
	}
}

func TestEnrollDeclinedOnTheDesktopIs403(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	line, _ := phonePublicKey(t)
	p.sendEnroll(f.ek, enroll.Request{PublicKey: line, Hosts: oneHost})
	<-f.requests
	f.approve <- false

	if code, _, _ := p.enrollResult(f.ek); code != http.StatusForbidden {
		t.Fatalf("result = %d, want 403", code)
	}
	if err := f.waitErr(t); err != nil {
		t.Fatal(err)
	}
	if outcome, _ := f.server.Enrollment(); outcome != EnrollDeclined {
		t.Fatalf("outcome = %v", outcome)
	}
}

func TestEnrollWithoutTheEnrollKeyIsRefusedAndChangesNothing(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	line, _ := phonePublicKey(t)
	// Someone who saw the QR knows k, but ek was only inside the envelope.
	if code := p.sendEnroll(p.secret, enroll.Request{PublicKey: line, Hosts: oneHost}); code != http.StatusUnauthorized {
		t.Fatalf("forged enroll = %d", code)
	}
	if code := p.closeEnroll(p.secret); code != http.StatusUnauthorized {
		t.Fatalf("forged close = %d", code)
	}
	if code := p.sendEnroll(f.ek, enroll.Request{PublicKey: line, Hosts: oneHost}); code != http.StatusAccepted {
		t.Fatalf("real enroll after forgery = %d", code)
	}
}

func TestInvalidEnrollContentIs400AndTheSessionGoesOn(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	line, _ := phonePublicKey(t)
	for name, body := range map[string]any{
		"options":       enroll.Request{PublicKey: `command="id" ` + line, Hosts: oneHost},
		"no hosts":      enroll.Request{PublicKey: line},
		"unknown field": map[string]any{"public_key": line, "hosts": oneHost, "extra": 1},
	} {
		if code := p.sendEnroll(f.ek, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	if code := p.sendEnroll(f.ek, enroll.Request{PublicKey: line, Hosts: oneHost}); code != http.StatusAccepted {
		t.Fatalf("valid enroll = %d", code)
	}
	if code := p.sendEnroll(f.ek, enroll.Request{PublicKey: line, Hosts: oneHost}); code != http.StatusConflict {
		t.Fatalf("second enroll = %d, want 409", code)
	}
}

func TestCloseEndsTheSessionWithoutAKey(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	if code := p.closeEnroll(f.ek); code != http.StatusNoContent {
		t.Fatalf("close = %d", code)
	}
	if err := f.waitErr(t); err != nil {
		t.Fatal(err)
	}
	if outcome, _ := f.server.Enrollment(); outcome != EnrollSkipped {
		t.Fatalf("outcome = %v", outcome)
	}
}

func TestRejectAfterTheEnvelopeIsASkipNotAFailure(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	resp, _ := p.post("reject", rejectRequest{MAC: b64.EncodeToString(envelope.RejectMAC(p.secret, p.sid))})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reject = %d", resp.StatusCode)
	}
	if err := f.waitErr(t); err != nil {
		t.Fatalf("Wait = %v, the envelope was delivered", err)
	}
}

func TestEnrollPhaseExpiryIsNotAFailedPairing(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	f.clock.advance(EnrollTTL + time.Second)

	if code, _, _ := p.enrollResult(f.ek); code != http.StatusGone {
		t.Fatalf("result after expiry = %d", code)
	}
	if err := f.waitErr(t); err != nil {
		t.Fatalf("Wait = %v", err)
	}
	if outcome, _ := f.server.Enrollment(); outcome != EnrollExpired {
		t.Fatalf("outcome = %v", outcome)
	}
}

func TestEnvelopeIsNotHandedOutTwiceInTheEnrollPhase(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	if code, _ := p.envelope(); code != http.StatusGone {
		t.Fatalf("second envelope = %d", code)
	}
}

func TestResultBeforeARequestConflicts(t *testing.T) {
	f := newEnrollFixture(t)
	p := f.deliver(t)
	if code, _, _ := p.enrollResult(f.ek); code != http.StatusConflict {
		t.Fatalf("early result = %d", code)
	}
}

func TestWithoutEnrollTheSessionEndsAtTheEnvelopeAsInV1(t *testing.T) {
	f := newFixture(t, "{}")
	p := newPhone(t, f.ts, f.server)
	p.claim()
	p.reveal()
	<-f.shown
	f.approve <- true
	p.envelope()
	if err := f.waitErr(t); err != nil {
		t.Fatal(err)
	}
	line, _ := phonePublicKey(t)
	if code := p.sendEnroll(make([]byte, envelope.EnrollKeySize), enroll.Request{PublicKey: line, Hosts: oneHost}); code != http.StatusGone {
		t.Fatalf("enroll without the extension = %d", code)
	}
	if outcome, _ := f.server.Enrollment(); outcome != EnrollNotOffered {
		t.Fatalf("outcome = %v", outcome)
	}
}

func TestHandlerResultsAreAlignedWithTheRequest(t *testing.T) {
	req := enroll.Request{Hosts: []enroll.Host{{Alias: "a"}, {Alias: "b"}}}
	got := aligned(req, []enroll.Result{{Alias: "a", Status: enroll.StatusAdded}})
	if len(got) != 2 || got[0].Status != enroll.StatusAdded || got[1].Alias != "b" || got[1].Reason != enroll.ReasonTimeout {
		t.Fatalf("aligned = %+v", got)
	}
}

func TestEnrollKeyMustBe32Bytes(t *testing.T) {
	_, err := NewServer(nil, func(string) bool { return true }, Options{Enroll: &EnrollHandler{Key: []byte("short")}})
	if err == nil {
		t.Fatal("accepted a short enroll key")
	}
}
