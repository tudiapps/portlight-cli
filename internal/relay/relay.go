// Package relay is a client for the pairing mailbox relay (API v1, see
// docs/pairing-protocol.md "Relay (son yedek)").
//
// The relay only moves opaque blobs between single-use boxes. Everything
// that goes through it is already MAC'd or sealed; this package never logs
// box ids or bodies, and its errors never carry the request URL (which
// contains the box id).
package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Limits of relay API v1.
const (
	// MaxBody is the largest blob a box accepts.
	MaxBody = 8 << 20
	// MaxWait is the longest long-poll the relay honours.
	MaxWait = 25 * time.Second
	// BoxTTL is how long an untaken blob lives.
	BoxTTL = 60 * time.Second
)

// IDPattern is what a box id must look like: 32 bytes, base64url, no padding.
var IDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Typed errors for the relay's non-success answers.
var (
	// ErrBoxFull (409): the box already holds a blob.
	ErrBoxFull = errors.New("relay: box already full")
	// ErrTooLarge (413, or a response over MaxBody).
	ErrTooLarge = errors.New("relay: body too large")
	// ErrRateLimited (429).
	ErrRateLimited = errors.New("relay: rate limited")
	// ErrNotFound (404): the relay rejected the box id or does not speak
	// this API.
	ErrNotFound = errors.New("relay: not found")
)

// StatusError is any other unexpected HTTP status.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return "relay: unexpected HTTP status " + strconv.Itoa(e.Code) }

// TransportError is a network-level failure (DNS, TCP, TLS, timeout). The
// request URL is deliberately left out.
type TransportError struct{ Err error }

func (e *TransportError) Error() string { return "relay: " + e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

// IsPermanent reports whether retrying err cannot help: the relay is the
// wrong kind of server, refuses the size, or redirects. Network errors,
// 5xx, 408 and 429 are transient.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrTooLarge) {
		return true
	}
	var se *StatusError
	if errors.As(err, &se) {
		switch {
		case se.Code == http.StatusRequestTimeout:
			return false
		case se.Code >= 300 && se.Code < 500:
			return true
		}
	}
	return false
}

// ParseURL checks a relay base URL: https, or plain http only to a
// loopback host (for local development and tests). It returns the URL
// without a trailing slash.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("relay URL: %w", err)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("relay URL must be a plain base URL like https://relay.example.com")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("relay URL must use https:// (http:// is allowed only for loopback)")
		}
	default:
		return nil, fmt.Errorf("relay URL must use https://")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Client talks to one relay.
type Client struct {
	base *url.URL
	http *http.Client
}

// New returns a client for the relay at base (see ParseURL).
func New(base string) (*Client, error) {
	u, err := ParseURL(base)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = MaxWait + 10*time.Second
	transport.MaxIdleConnsPerHost = 8
	return &Client{
		base: u,
		http: &http.Client{
			Transport: transport,
			// A relay that redirects is misconfigured or hostile; the
			// box id must not be forwarded anywhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// URL is the relay's base URL, as it goes into the QR.
func (c *Client) URL() string { return c.base.String() }

// Host is the relay's host, for telling the user which relay is used.
func (c *Client) Host() string { return c.base.Host }

// CloseIdle releases idle connections.
func (c *Client) CloseIdle() { c.http.CloseIdleConnections() }

func (c *Client) endpoint(path string) string { return c.base.String() + path }

func checkID(id string) error {
	if !IDPattern.MatchString(id) {
		return errors.New("relay: malformed box id")
	}
	return nil
}

// Put stores body in box id. It fails with ErrBoxFull if the box is
// already occupied.
func (c *Client) Put(ctx context.Context, id string, body []byte) error {
	if err := checkID(id); err != nil {
		return err
	}
	if len(body) > MaxBody {
		return ErrTooLarge
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint("/v1/box/"+id), bytes.NewReader(body))
	if err != nil {
		return errors.New("relay: building request failed")
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	return statusErr(resp.StatusCode)
}

// Take removes and returns the blob in box id, waiting up to wait for one
// to arrive. found is false if the box stayed empty.
func (c *Client) Take(ctx context.Context, id string, wait time.Duration) (body []byte, found bool, err error) {
	if err := checkID(id); err != nil {
		return nil, false, err
	}
	// The relay counts whole seconds; round up so a short wait still waits.
	secs := int((min(max(wait, 0), MaxWait) + time.Second - 1) / time.Second)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second+15*time.Second)
	defer cancel()
	target := c.endpoint("/v1/box/"+id) + "?wait=" + strconv.Itoa(secs)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, false, errors.New("relay: building request failed")
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, false, err
	}
	defer drain(resp)
	switch resp.StatusCode {
	case http.StatusOK:
		data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
		if err != nil {
			return nil, false, transportErr(err)
		}
		if len(data) > MaxBody {
			return nil, false, ErrTooLarge
		}
		return data, true, nil
	case http.StatusNoContent:
		return nil, false, nil
	}
	return nil, false, statusErr(resp.StatusCode)
}

// Health checks that the relay answers.
func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("/v1/health"), nil)
	if err != nil {
		return errors.New("relay: building request failed")
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return statusErr(resp.StatusCode)
	}
	return nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		if ctxErr := req.Context().Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return nil, ctxErr
		}
		return nil, transportErr(err)
	}
	return resp, nil
}

// transportErr drops the *url.Error wrapper, whose message includes the
// URL and therefore the box id.
func transportErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return &TransportError{Err: err}
}

func statusErr(code int) error {
	switch code {
	case http.StatusConflict:
		return ErrBoxFull
	case http.StatusRequestEntityTooLarge:
		return ErrTooLarge
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusNotFound:
		return ErrNotFound
	}
	return &StatusError{Code: code}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}
