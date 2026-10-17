package pairing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"net/http"
	"time"

	"github.com/tudiapps/portlight-cli/internal/enroll"
	"github.com/tudiapps/portlight-cli/internal/envelope"
)

// The enroll extension: after the envelope, the phone may send one sealed
// public key + host list; the desktop user approves it, the key is added
// to the hosts, and the sealed per-host result goes back. See
// docs/pairing-protocol.md "Enroll uzantısı".

// Enrollment reports how the enroll phase ended and, if the key was added
// anywhere, the per-host results. Valid once Wait has returned nil.
func (s *Server) Enrollment() (EnrollOutcome, []enroll.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enroll == nil {
		return EnrollNotOffered, nil
	}
	return s.enrollOutcome, s.enrollResults
}

// notOfferedLocked answers a request for an enroll step the session has no
// enroll phase for: 410 once it is over, 409 before that.
func (s *Server) notOfferedLocked(w http.ResponseWriter) {
	s.expireLocked()
	if s.state == stateDone || s.state == stateFailed {
		http.Error(w, "session is over", http.StatusGone)
		return
	}
	http.Error(w, "enroll not offered", http.StatusConflict)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.knownSession(r) {
		http.NotFound(w, r)
		return
	}
	var box envelope.Box
	if !decodeMax(w, r, &box, maxEnrollBody) {
		return
	}
	if s.enroll == nil {
		s.mu.Lock()
		s.notOfferedLocked(w)
		s.mu.Unlock()
		return
	}
	// Checked before any state change: without ek (which only the phone
	// that opened the envelope has) nobody can spend the enroll phase.
	plain, err := envelope.OpenEnrollRequest(s.enroll.Key, s.sessionID, box)
	if err != nil {
		http.Error(w, "enroll request not authenticated", http.StatusUnauthorized)
		return
	}
	var req enroll.Request
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "malformed enroll request", http.StatusBadRequest)
		return
	}
	pub, err := req.Validate()
	if err != nil {
		http.Error(w, "invalid enroll request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.phaseLocked(w, stateDelivered) {
		return
	}
	s.state = stateEnrolling
	s.deadline = s.now().Add(EnrollDecisionTTL + EnrollWorkTTL + enrollGrace)
	close(s.enrollRequested)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), EnrollDecisionTTL+EnrollWorkTTL)
		defer cancel()
		results, approved := s.enroll.Handle(ctx, req, pub)
		s.enrolled(req, results, approved)
	}()
	w.WriteHeader(http.StatusAccepted)
}

// enrolled records the desktop's answer and seals the results.
func (s *Server) enrolled(req enroll.Request, results []enroll.Result, approved bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if s.state != stateEnrolling {
		return // ran out of time
	}
	if approved {
		results = aligned(req, results)
		body, err := json.Marshal(enroll.Report{Results: results})
		if err != nil {
			s.finishLocked(EnrollExpired)
			return
		}
		box, err := envelope.SealEnrollResult(s.enroll.Key, s.sessionID, body)
		if err != nil {
			s.finishLocked(EnrollExpired)
			return
		}
		sealed, err := json.Marshal(box)
		if err != nil {
			s.finishLocked(EnrollExpired)
			return
		}
		s.enrollSealed, s.enrollResults = sealed, results
	}
	s.enrollApproved = approved
	s.state = stateEnrolled
	// The phone is normally long-polling already.
	s.deadline = s.now().Add(DecisionTTL)
	close(s.enrollDecided)
}

// aligned returns exactly one result per requested host, in request order,
// whatever the handler returned.
func aligned(req enroll.Request, results []enroll.Result) []enroll.Result {
	out := make([]enroll.Result, len(req.Hosts))
	for i, h := range req.Hosts {
		if i < len(results) && results[i].Alias == h.Alias {
			out[i] = results[i]
			continue
		}
		out[i] = enroll.Result{Alias: h.Alias, Status: enroll.StatusFailed, Reason: enroll.ReasonTimeout}
	}
	return out
}

func (s *Server) handleEnrollResult(w http.ResponseWriter, r *http.Request) {
	if !s.knownSession(r) {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	if s.enroll == nil {
		s.notOfferedLocked(w)
		s.mu.Unlock()
		return
	}
	s.expireLocked()
	if s.state != stateEnrolling && s.state != stateEnrolled {
		s.phaseLocked(w, stateEnrolling)
		s.mu.Unlock()
		return
	}
	deadline := s.deadline
	s.mu.Unlock()

	select {
	case <-s.enrollDecided:
	case <-s.finished:
	case <-time.After(time.Until(deadline)):
	case <-r.Context().Done():
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if s.state != stateEnrolled {
		s.phaseLocked(w, stateEnrolled)
		return
	}
	if !s.enrollApproved {
		http.Error(w, "declined on the desktop", http.StatusForbidden)
		s.finishLocked(EnrollDeclined)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.enrollSealed)
	s.finishLocked(EnrollCompleted)
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	if !s.knownSession(r) {
		http.NotFound(w, r)
		return
	}
	var req rejectRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enroll == nil {
		s.notOfferedLocked(w)
		return
	}
	mac, err := b64.DecodeString(req.MAC)
	if err != nil || !hmac.Equal(mac, envelope.EnrollCloseMAC(s.enroll.Key, s.sessionID)) {
		http.Error(w, "close not authenticated", http.StatusUnauthorized)
		return
	}
	s.expireLocked()
	switch {
	case s.state == stateDone || s.state == stateFailed:
		http.Error(w, "session is over", http.StatusGone)
	case s.state == stateDelivered:
		s.finishLocked(EnrollSkipped)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "not in the enroll phase", http.StatusConflict)
	}
}
