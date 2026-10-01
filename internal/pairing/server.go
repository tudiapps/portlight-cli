package pairing

import (
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tudiapps/portlight-cli/internal/envelope"
)

// Protocol limits. See docs/pairing-protocol.md.
const (
	// HandshakeTTL is how long after the QR appears the phone has to claim
	// the session and reveal its nonce.
	HandshakeTTL = 60 * time.Second
	// DecisionTTL is how long the user has to compare codes once both
	// screens show one.
	DecisionTTL = 60 * time.Second

	maxBody = 4 << 10
)

// Errors Wait can return.
var (
	ErrRejected = errors.New("codes did not match; nothing was sent")
	ErrExpired  = errors.New("pairing session expired; nothing was sent")
	ErrAborted  = errors.New("pairing aborted after a protocol violation; nothing was sent")
	// ErrRejectedOnPhone: the phone's user said the codes differ, or
	// cancelled. Nothing was sent.
	ErrRejectedOnPhone = errors.New("pairing cancelled on the phone; nothing was sent")
)

type state int

const (
	stateWaiting   state = iota // QR shown, nobody has claimed it
	stateClaimed                // phone's recipient and commitment accepted
	stateRevealed               // nonces exchanged, SAS on both screens
	stateConfirmed              // user said the codes match
	stateDone                   // envelope delivered
	stateFailed                 // rejected, expired or aborted
)

var b64 = base64.RawURLEncoding

// Server is one single-use pairing session.
//
// It holds the payload in memory and seals it only after the user has
// confirmed the SAS, to the recipient that SAS was computed over.
type Server struct {
	sessionID []byte
	secret    []byte
	payload   []byte
	confirm   func(sas string) bool
	now       func() time.Time
	mux       *http.ServeMux

	mu         sync.Mutex
	state      state
	failure    error
	deadline   time.Time // of the current phase
	recipient  string
	commitment []byte
	cliNonce   []byte
	sealed     []byte
	claimed    chan struct{} // closed when a claim is first accepted
	revealed   chan struct{} // closed when the nonces have been exchanged
	decided    chan struct{} // closed when the user decides or time runs out
	finished   chan struct{} // closed on stateDone or stateFailed
	reported   chan struct{} // closed once the phone has seen the outcome
	reportOnce sync.Once
}

// Options tune a Server; the zero value is the production setting.
type Options struct {
	// Now replaces time.Now, for tests.
	Now func() time.Time
}

// NewServer starts a session that will deliver payload once confirm
// approves the SAS. confirm is called at most once, on its own goroutine.
func NewServer(payload []byte, confirm func(sas string) bool, opts Options) (*Server, error) {
	sid, err := envelope.Random(envelope.SessionIDSize)
	if err != nil {
		return nil, err
	}
	secret, err := envelope.Random(envelope.SecretSize)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := &Server{
		sessionID: sid,
		secret:    secret,
		payload:   payload,
		confirm:   confirm,
		now:       now,
		deadline:  now().Add(HandshakeTTL),
		claimed:   make(chan struct{}),
		revealed:  make(chan struct{}),
		decided:   make(chan struct{}),
		finished:  make(chan struct{}),
		reported:  make(chan struct{}),
		mux:       http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /v1/pair/{sid}/claim", s.handleClaim)
	s.mux.HandleFunc("POST /v1/pair/{sid}/reveal", s.handleReveal)
	s.mux.HandleFunc("GET /v1/pair/{sid}/envelope", s.handleEnvelope)
	s.mux.HandleFunc("POST /v1/pair/{sid}/reject", s.handleReject)
	return s, nil
}

// URI is what the QR code carries: the session, the secret (which never
// crosses the network; it only proves the claimant saw the screen) and the
// "host:port" addresses to try, preferred first.
func (s *Server) URI(addrs ...string) string {
	return s.QRURI(Endpoints{Addrs: addrs})
}

// Endpoints are the ways the phone can reach this session.
type Endpoints struct {
	// Addrs are "host:port" LAN addresses, preferred first.
	Addrs []string
	// Relay is the mailbox relay's base URL (see relay.ParseURL), or ""
	// when no relay is used.
	Relay string
}

// QRURI is URI with an optional relay: it adds r=<relay base URL>.
func (s *Server) QRURI(e Endpoints) string {
	q := url.Values{}
	q.Set("v", "1")
	q.Set("sid", b64.EncodeToString(s.sessionID))
	q.Set("k", b64.EncodeToString(s.secret))
	q.Set("a", strings.Join(e.Addrs, ","))
	if e.Relay != "" {
		q.Set("r", e.Relay)
	}
	return "portlight://pair?" + q.Encode()
}

// relayBox is the relay mailbox id for one message of this session.
func (s *Server) relayBox(name string) string {
	return b64.EncodeToString(envelope.RelayBox(s.secret, s.sessionID, name))
}

// SessionID is the session's id, for the mDNS tag.
func (s *Server) SessionID() []byte { return slices.Clone(s.sessionID) }

// Reported is closed once the phone has learned how the session ended:
// it received the envelope, was told 403/410, or cancelled itself. A caller
// should keep serving until then (bounded by a grace period) so the phone
// sees "rejected" rather than a refused connection.
func (s *Server) Reported() <-chan struct{} { return s.reported }

func (s *Server) markReported() { s.reportOnce.Do(func() { close(s.reported) }) }

// ReportGrace bounds how long Close waits for the phone to collect the
// outcome after the session has ended.
const ReportGrace = 5 * time.Second

// Close waits until the phone has seen the outcome (at most ReportGrace),
// then shuts httpServer down, letting in-flight responses finish.
func (s *Server) Close(httpServer *http.Server) {
	select {
	case <-s.reported:
	case <-time.After(ReportGrace):
	}
	ctx, cancel := context.WithTimeout(context.Background(), ReportGrace)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		_ = httpServer.Close()
	}
}

// Wait blocks until the envelope is delivered (nil) or the session fails.
func (s *Server) Wait() error {
	for {
		s.mu.Lock()
		s.expireLocked()
		st, err, deadline := s.state, s.failure, s.deadline
		s.mu.Unlock()
		switch st {
		case stateDone:
			return nil
		case stateFailed:
			return err
		}
		select {
		case <-s.finished:
		case <-time.After(time.Until(deadline) + 10*time.Millisecond):
		}
	}
}

// ServeHTTP routes the three protocol calls.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) knownSession(r *http.Request) bool {
	sid, err := b64.DecodeString(r.PathValue("sid"))
	return err == nil && subtle.ConstantTimeCompare(sid, s.sessionID) == 1
}

type claimRequest struct {
	Recipient  string `json:"recipient"`
	Commitment string `json:"commitment"`
	MAC        string `json:"mac"`
}

type claimResponse struct {
	CLINonce string `json:"cli_nonce"`
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	if !s.knownSession(r) {
		http.NotFound(w, r)
		return
	}
	var req claimRequest
	if !decode(w, r, &req) {
		return
	}
	commitment, err1 := b64.DecodeString(req.Commitment)
	mac, err2 := b64.DecodeString(req.MAC)
	if err1 != nil || err2 != nil || len(commitment) != 32 || req.Recipient == "" {
		http.Error(w, "malformed claim", http.StatusBadRequest)
		return
	}
	// Checked before any state change: a claim without the QR secret
	// cannot take the session away from the phone that scanned it.
	want := envelope.ClaimMAC(s.secret, s.sessionID, req.Recipient, commitment)
	if !hmac.Equal(mac, want) {
		http.Error(w, "claim not authenticated", http.StatusUnauthorized)
		return
	}
	if _, err := envelope.Seal(nil, req.Recipient); err != nil {
		http.Error(w, "recipient is not an age X25519 key", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// A retry of the claim we already accepted (the phone lost our answer
	// and tried again, perhaps on another address) gets the same answer,
	// not a 409 that would read as someone else on the network.
	if s.state == stateClaimed && req.Recipient == s.recipient &&
		hmac.Equal(commitment, s.commitment) {
		writeJSON(w, claimResponse{CLINonce: b64.EncodeToString(s.cliNonce)})
		return
	}
	if !s.phaseLocked(w, stateWaiting) {
		return
	}
	nonce, err := envelope.Random(envelope.NonceSize)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.recipient, s.commitment, s.cliNonce = req.Recipient, commitment, nonce
	s.state = stateClaimed
	close(s.claimed)
	writeJSON(w, claimResponse{CLINonce: b64.EncodeToString(nonce)})
}

type revealRequest struct {
	PhoneNonce string `json:"phone_nonce"`
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	if !s.knownSession(r) {
		http.NotFound(w, r)
		return
	}
	var req revealRequest
	if !decode(w, r, &req) {
		return
	}
	phoneNonce, err := b64.DecodeString(req.PhoneNonce)

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.phaseLocked(w, stateClaimed) {
		return
	}
	if err != nil || !hmac.Equal(envelope.Commitment(phoneNonce), s.commitment) {
		// Whoever sent this is not the phone that committed; the session
		// can no longer be trusted.
		s.failLocked(ErrAborted)
		http.Error(w, "nonce does not match commitment", http.StatusBadRequest)
		return
	}
	sas := envelope.SAS(s.secret, s.sessionID, s.recipient, s.cliNonce, phoneNonce)
	s.state = stateRevealed
	close(s.revealed)
	s.deadline = s.now().Add(DecisionTTL)
	go func() { s.decide(s.confirm(sas)) }()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) decide(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if s.state != stateRevealed {
		return // expired while the user was looking
	}
	if !ok {
		s.failLocked(ErrRejected)
		return
	}
	sealed, err := envelope.Seal(s.payload, s.recipient)
	if err != nil {
		s.failLocked(fmt.Errorf("sealing payload: %w", err))
		return
	}
	s.sealed = sealed
	s.state = stateConfirmed
	// The phone's user still has to confirm on their side; if they never
	// fetch, the session must end rather than wait forever.
	s.deadline = s.now().Add(DecisionTTL)
	close(s.decided)
}

type rejectRequest struct {
	MAC string `json:"mac"`
}

// handleReject is the phone saying "codes differ" or cancelling. It is
// MAC'd with the QR secret so nobody else can end the session; once the
// phone has claimed it, it is accepted in any unfinished state.
func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	if !s.knownSession(r) {
		http.NotFound(w, r)
		return
	}
	var req rejectRequest
	if !decode(w, r, &req) {
		return
	}
	mac, err := b64.DecodeString(req.MAC)
	if err != nil || !hmac.Equal(mac, envelope.RejectMAC(s.secret, s.sessionID)) {
		http.Error(w, "reject not authenticated", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if s.state == stateFailed || s.state == stateDone {
		http.Error(w, "session is over", http.StatusGone)
		return
	}
	s.failLocked(ErrRejectedOnPhone)
	s.markReported()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEnvelope(w http.ResponseWriter, r *http.Request) {
	if !s.knownSession(r) {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	s.expireLocked()
	deadline := s.deadline
	s.mu.Unlock()

	select {
	case <-s.decided:
	case <-s.finished:
	case <-time.After(time.Until(deadline)):
	case <-r.Context().Done():
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if s.state != stateConfirmed {
		s.phaseLocked(w, stateConfirmed)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.sealed)
	s.markReported()
	// Single use: once handed over, the session is closed.
	s.sealed, s.payload = nil, nil
	s.state = stateDone
	close(s.finished)
}

// phaseLocked reports whether the session is in want; otherwise it writes
// the matching error. 409 means someone got there first, 410 that the
// session is over.
func (s *Server) phaseLocked(w http.ResponseWriter, want state) bool {
	s.expireLocked()
	switch {
	case s.state == want:
		return true
	case s.state == stateFailed && errors.Is(s.failure, ErrRejected):
		http.Error(w, "rejected on the desktop", http.StatusForbidden)
		s.markReported()
	case s.state == stateFailed || s.state == stateDone:
		http.Error(w, "session is over", http.StatusGone)
		s.markReported()
	case s.state > want:
		http.Error(w, "session already claimed", http.StatusConflict)
	default:
		http.Error(w, "out of order", http.StatusConflict)
	}
	return false
}

func (s *Server) expireLocked() {
	if s.state != stateFailed && s.state != stateDone && !s.now().Before(s.deadline) {
		s.failLocked(ErrExpired)
	}
}

func (s *Server) failLocked(err error) {
	if s.state == stateFailed || s.state == stateDone {
		return
	}
	s.state, s.failure = stateFailed, err
	s.payload, s.sealed = nil, nil
	close(s.finished)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "malformed JSON", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
