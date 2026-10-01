// Package memrelay is an in-memory implementation of relay API v1 (see
// docs/pairing-protocol.md "Relay (son yedek)"), for local development
// and tests. It keeps nothing on disk and logs nothing.
package memrelay

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/tudiapps/portlight-cli/internal/relay"
)

// Options tune a Relay; the zero value is the API v1 setting.
type Options struct {
	// TTL of an untaken blob (default relay.BoxTTL).
	TTL time.Duration
	// MaxWait caps ?wait= (default relay.MaxWait).
	MaxWait time.Duration
	// Now replaces time.Now, for tests.
	Now func() time.Time
}

type box struct {
	data    []byte
	expires time.Time
}

// Relay is an http.Handler serving relay API v1 from memory.
type Relay struct {
	ttl     time.Duration
	maxWait time.Duration
	now     func() time.Time
	mux     *http.ServeMux

	mu      sync.Mutex
	boxes   map[string]box
	waiters map[string]chan struct{} // closed when the box is filled
}

// New returns an empty relay.
func New(opts Options) *Relay {
	r := &Relay{
		ttl:     opts.TTL,
		maxWait: opts.MaxWait,
		now:     opts.Now,
		mux:     http.NewServeMux(),
		boxes:   map[string]box{},
		waiters: map[string]chan struct{}{},
	}
	if r.ttl <= 0 {
		r.ttl = relay.BoxTTL
	}
	if r.maxWait <= 0 {
		r.maxWait = relay.MaxWait
	}
	if r.now == nil {
		r.now = time.Now
	}
	r.mux.HandleFunc("PUT /v1/box/{id}", r.put)
	r.mux.HandleFunc("GET /v1/box/{id}", r.take)
	r.mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

// ServeHTTP implements http.Handler.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) { r.mux.ServeHTTP(w, req) }

// Len is the number of live boxes, for tests.
func (r *Relay) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	return len(r.boxes)
}

func (r *Relay) put(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if !relay.IDPattern.MatchString(id) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if req.ContentLength > relay.MaxBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, relay.MaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	if _, full := r.boxes[id]; full {
		w.WriteHeader(http.StatusConflict)
		return
	}
	r.boxes[id] = box{data: data, expires: r.now().Add(r.ttl)}
	if ch, ok := r.waiters[id]; ok {
		close(ch)
		delete(r.waiters, id)
	}
	w.WriteHeader(http.StatusCreated)
}

func (r *Relay) take(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if !relay.IDPattern.MatchString(id) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	wait := time.Duration(0)
	if raw := req.URL.Query().Get("wait"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wait = min(time.Duration(n)*time.Second, r.maxWait)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		r.mu.Lock()
		r.sweepLocked()
		if b, ok := r.boxes[id]; ok {
			// Take and delete under one lock: exactly one reader wins.
			delete(r.boxes, id)
			r.mu.Unlock()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b.data)
			return
		}
		ch, ok := r.waiters[id]
		if !ok {
			ch = make(chan struct{})
			r.waiters[id] = ch
		}
		r.mu.Unlock()

		select {
		case <-ch:
		case <-timer.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-req.Context().Done():
			return
		}
	}
}

func (r *Relay) sweepLocked() {
	now := r.now()
	for id, b := range r.boxes {
		if !now.Before(b.expires) {
			delete(r.boxes, id)
		}
	}
}
