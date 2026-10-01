package pairing

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tudiapps/portlight-cli/internal/relay"
)

// ErrRelayUndelivered means a response the session had already committed to
// (possibly the envelope) could not be put into the relay. The session
// state is unchanged by this; the phone may simply not have received it.
var ErrRelayUndelivered = errors.New("relay: a response could not be delivered")

// RelayOptions tune ServeRelay; the zero value is the production setting.
type RelayOptions struct {
	// Wait is the long-poll per request (default relay.MaxWait).
	Wait time.Duration
	// MinBackoff and MaxBackoff bound the retry delay after a transient
	// relay error (defaults 250 ms and 5 s).
	MinBackoff, MaxBackoff time.Duration
	// Warn receives user-facing warnings about the relay. It never gets
	// box ids or message bodies. Nil drops them.
	Warn func(string)
}

// ServeRelay runs the session through the mailbox relay alongside the LAN
// server (docs/pairing-protocol.md "Relay (son yedek)"). Each request box
// is taken, run through the same handler as the direct path, and the
// handler's answer is put into the matching response box as
// uint16_be(status) ‖ body. Whichever path claims first wins.
//
//   - claim: from the start until the nonces are exchanged
//   - reveal: once the session is claimed (by either path) until revealed
//   - envelope: once revealed, until the end
//   - reject: from start to end (no response box)
//
// It returns once the session has ended and the phone has seen the outcome
// (at most ReportGrace later), when ctx is cancelled, or when the relay
// fails permanently — the LAN path is unaffected in every case. Transient
// errors are retried with backoff.
func (s *Server) ServeRelay(ctx context.Context, c *relay.Client, opts RelayOptions) error {
	if opts.Wait <= 0 {
		opts.Wait = relay.MaxWait
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = 250 * time.Millisecond
	}
	if opts.MaxBackoff < opts.MinBackoff {
		opts.MaxBackoff = max(5*time.Second, opts.MinBackoff)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	l := &relayLoop{s: s, c: c, opts: opts, ctx: ctx, cancel: cancel}

	l.wg.Add(5)
	go l.watch()
	go l.poll(nil, s.revealed, "claim", http.MethodPost, "claim/response")
	go l.poll(s.claimed, s.revealed, "reveal", http.MethodPost, "reveal/response")
	go l.poll(s.revealed, nil, "envelope", http.MethodGet, "envelope/response")
	go l.poll(nil, nil, "reject", http.MethodPost, "")
	l.wg.Wait()

	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

type relayLoop struct {
	s      *Server
	c      *relay.Client
	opts   RelayOptions
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.Mutex
	err        error
	warnedOnce bool
}

// watch ends the loop once the session is over and the phone has seen
// how, bounded by ReportGrace — the relay twin of Server.Close.
func (l *relayLoop) watch() {
	defer l.wg.Done()
	s := l.s
	for {
		s.mu.Lock()
		s.expireLocked()
		deadline := s.deadline
		s.mu.Unlock()
		select {
		case <-s.finished:
			select {
			case <-s.reported:
			case <-time.After(ReportGrace):
			case <-l.ctx.Done():
			}
			l.cancel()
			return
		case <-l.ctx.Done():
			return
		case <-time.After(time.Until(deadline) + 10*time.Millisecond):
		}
	}
}

// fail stops the whole relay loop after a permanent error.
func (l *relayLoop) fail(err error) {
	l.mu.Lock()
	if l.err == nil {
		l.err = err
	}
	l.mu.Unlock()
	l.cancel()
}

// transient warns once that the relay is struggling.
func (l *relayLoop) transient(err error) {
	l.mu.Lock()
	first := !l.warnedOnce
	l.warnedOnce = true
	l.mu.Unlock()
	if first && l.opts.Warn != nil {
		l.opts.Warn(fmt.Sprintf("relay'e şu an ulaşılamıyor, yeniden deneniyor (%v)", err))
	}
}

// sleep waits d or until ctx ends; it reports whether to go on.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// poll serves one request box: after start is closed (nil: right away)
// and until stop is closed (nil: until the loop ends).
func (l *relayLoop) poll(start, stop <-chan struct{}, name, method, response string) {
	defer l.wg.Done()
	if start != nil {
		select {
		case <-start:
		case <-l.ctx.Done():
			return
		}
	}
	stageCtx, cancel := context.WithCancel(l.ctx)
	defer cancel()
	if stop != nil {
		go func() {
			select {
			case <-stop:
				cancel()
			case <-stageCtx.Done():
			}
		}()
	}

	id := l.s.relayBox(name)
	backoff := l.opts.MinBackoff
	for stageCtx.Err() == nil {
		began := time.Now()
		body, found, err := l.c.Take(stageCtx, id, l.opts.Wait)
		if err != nil {
			if stageCtx.Err() != nil {
				return
			}
			if relay.IsPermanent(err) {
				l.fail(err)
				return
			}
			l.transient(err)
			if !sleep(stageCtx, backoff) {
				return
			}
			backoff = min(backoff*2, l.opts.MaxBackoff)
			continue
		}
		backoff = l.opts.MinBackoff
		if !found {
			// A relay that answers "empty" at once must not make us spin.
			if time.Since(began) < 100*time.Millisecond && !sleep(stageCtx, l.opts.MinBackoff) {
				return
			}
			continue
		}
		status, answer, wrote := l.s.serveBoxed(l.ctx, method, name, body)
		if response == "" || !wrote {
			continue
		}
		l.deliver(response, status, answer)
	}
}

// deliver puts one response frame, retrying transient errors. It is not
// cut short by the loop ending: an answer the session already committed
// to (a 403, or the envelope) must still reach the phone.
func (l *relayLoop) deliver(name string, status int, body []byte) {
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame, uint16(status))
	copy(frame[2:], body)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(l.ctx), ReportGrace+10*time.Second)
	defer cancel()
	id := l.s.relayBox(name)
	backoff := l.opts.MinBackoff
	for {
		err := l.c.Put(ctx, id, frame)
		switch {
		case err == nil:
			return
		case errors.Is(err, relay.ErrBoxFull):
			// The phone did not collect an earlier answer to the same
			// step (e.g. a junk request, then a real one). Nothing to do.
			return
		case relay.IsPermanent(err) || ctx.Err() != nil:
			l.fail(fmt.Errorf("%w: %w", ErrRelayUndelivered, err))
			return
		}
		l.transient(err)
		if !sleep(ctx, backoff) {
			l.fail(fmt.Errorf("%w: %w", ErrRelayUndelivered, err))
			return
		}
		backoff = min(backoff*2, l.opts.MaxBackoff)
	}
}

// serveBoxed runs one relayed request through the direct-path handler and
// captures its answer. wrote is false if the handler gave up without
// answering (the loop is shutting down).
func (s *Server) serveBoxed(ctx context.Context, method, step string, body []byte) (status int, answer []byte, wrote bool) {
	target := "/v1/pair/" + b64.EncodeToString(s.sessionID) + "/" + step
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, false
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := &recorder{header: http.Header{}}
	s.ServeHTTP(rec, req)
	if !rec.wrote {
		return 0, nil, false
	}
	return rec.status, rec.body.Bytes(), true
}

// recorder is a minimal in-memory http.ResponseWriter.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.status, r.wrote = code, true
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.body.Write(p)
}
