// Package enroll adds a phone-generated public key to the servers this
// desktop can already log in to (docs/pairing-protocol.md "Enroll
// uzantısı"). It reads the phone's request, resolves each host only against
// what the desktop already knows (its SSH config and known_hosts), and
// appends the key to authorized_keys over SSH with the desktop's own keys
// and agent. It never accepts an unknown host key and writes nothing
// locally.
package enroll

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Per-host outcomes, as the phone reads them.
const (
	StatusAdded   = "added"
	StatusPresent = "present"
	StatusFailed  = "failed"
)

// Why a host failed. The phone shows one message per reason.
const (
	ReasonNotKnown       = "not_known"
	ReasonUnknownHostKey = "unknown_host_key"
	ReasonHostKeyChanged = "host_key_changed"
	ReasonAuthFailed     = "auth_failed"
	ReasonUnreachable    = "unreachable"
	ReasonProxyJump      = "proxy_jump"
	ReasonWriteFailed    = "write_failed"
	ReasonTimeout        = "timeout"
)

// MaxHosts bounds one request.
const MaxHosts = 64

// KeyComment is the only comment written next to an enrolled key.
const KeyComment = "portlight-mobile"

// Host is one server the phone asks for.
type Host struct {
	Alias    string `json:"alias"`
	HostName string `json:"host_name"`
	User     string `json:"user"`
	Port     int    `json:"port"`
}

// Request is the phone's enroll message, once opened.
type Request struct {
	PublicKey string `json:"public_key"`
	Hosts     []Host `json:"hosts"`
}

// Result is what happened on one host. HostKey is the server key the
// desktop saw and verified against its known_hosts, in authorized_keys form.
type Result struct {
	Alias   string `json:"alias"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	HostKey string `json:"host_key,omitempty"`
}

// Report is the result message, in the order of the request's hosts.
type Report struct {
	Results []Result `json:"results"`
}

// ErrKeyOptions is returned for an authorized_keys line that carries
// options such as command="..." — enroll only adds plain keys.
var ErrKeyOptions = errors.New("key has authorized_keys options; only a plain public key can be enrolled")

// ParsePublicKey accepts exactly one plain public key line: no options, no
// second line, a comment at most.
func ParsePublicKey(publicKey string) (ssh.PublicKey, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return nil, fmt.Errorf("public key is empty")
	}
	if strings.ContainsAny(publicKey, "\r\n") {
		return nil, fmt.Errorf("expected a single public key line")
	}
	pub, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, fmt.Errorf("not a valid public key: %w", err)
	}
	if len(options) > 0 {
		return nil, ErrKeyOptions
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, fmt.Errorf("expected a single public key line")
	}
	return pub, nil
}

// AuthorizedLine is what reaches a server: the key re-encoded, so nothing
// the phone sent but the key itself is written, plus a fixed comment.
func AuthorizedLine(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + KeyComment
}

// Validate checks the request and returns its parsed key.
func (r Request) Validate() (ssh.PublicKey, error) {
	pub, err := ParsePublicKey(r.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(r.Hosts) == 0 || len(r.Hosts) > MaxHosts {
		return nil, fmt.Errorf("expected 1 to %d hosts, got %d", MaxHosts, len(r.Hosts))
	}
	seen := map[string]bool{}
	for i, h := range r.Hosts {
		switch {
		case !printable(h.Alias, 255, false):
			return nil, fmt.Errorf("host %d: invalid alias", i+1)
		case !printable(h.HostName, 253, true) || strings.HasPrefix(h.HostName, "-"):
			return nil, fmt.Errorf("host %d: invalid host name", i+1)
		case !printable(h.User, 64, true) || strings.ContainsAny(h.User, "@:") || strings.HasPrefix(h.User, "-"):
			return nil, fmt.Errorf("host %d: invalid user", i+1)
		case h.Port < 1 || h.Port > 65535:
			return nil, fmt.Errorf("host %d: invalid port", i+1)
		case seen[h.Alias]:
			return nil, fmt.Errorf("host %d: duplicate alias", i+1)
		}
		seen[h.Alias] = true
	}
	return pub, nil
}

// printable: non-empty, at most max bytes, no control characters, and no
// spaces at all when noSpace.
func printable(s string, max int, noSpace bool) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || (noSpace && unicode.IsSpace(r)) {
			return false
		}
	}
	return true
}
