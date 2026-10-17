package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tudiapps/portlight-cli/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Remote commands. The key never goes into a command line: it is written
// to the append command's stdin. Wrapped in sh -c so fish/csh login shells
// read them the same way.
const (
	readCommand   = `sh -c 'test ! -e .ssh/authorized_keys || cat .ssh/authorized_keys'`
	appendCommand = `sh -c 'umask 077 && mkdir -p .ssh && cat >> .ssh/authorized_keys'`
)

// Defaults for a Distributor's zero fields.
const (
	DefaultConcurrency    = 4
	DefaultConnectTimeout = 15 * time.Second
	DefaultCommandTimeout = 15 * time.Second
	maxAuthorizedKeys     = 1 << 20
	maxPassphraseAttempts = 3
)

// Distributor appends a public key to authorized_keys on hosts the desktop
// already knows, logging in with the desktop's own keys and agent.
type Distributor struct {
	// Hosts and Keys are what BuildPayload read: the SSH config (and PuTTY)
	// hosts with their key names, and the private keys themselves. Keys
	// stay on this machine; they are only used to log in.
	Hosts []sshconfig.HostConfig
	Keys  []sshconfig.Key
	// KnownHostsPath defaults to ~/.ssh/known_hosts. A host whose key is
	// not in it is never connected to.
	KnownHostsPath string
	// Passphrase unlocks an encrypted key (attempt counts from 1); empty
	// skips the key. Nil skips every encrypted key.
	Passphrase func(keyName string, attempt int) ([]byte, error)
	// Agent opens the SSH agent; nil uses the system agent. A nil agent
	// with a nil error means there is none.
	Agent func() (agent.Agent, io.Closer, error)
	// Dial replaces the TCP dialer, for tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// LocalUser is the user for a ProxyJump host that names none; empty
	// means the current OS user, as ssh does.
	LocalUser string
	// Concurrency, ConnectTimeout and CommandTimeout default to the
	// Default* constants.
	Concurrency    int
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	// Progress is called once per host as it finishes, never concurrently.
	Progress func(Plan, Result, error)
}

// Target is where the desktop connects for one host.
type Target struct {
	Addr     string // host:port
	User     string
	Key      string // payload key name to try first; may be empty
	Jump     *Target
	JumpName string // as written in ProxyJump, for display
}

// Plan is one requested host and where it resolves to; Target is nil when
// the desktop does not know the host (Reason says why).
type Plan struct {
	Host   Host
	Target *Target
	Reason string
}

// Plan resolves each host against the SSH config and known_hosts without
// touching the network. A host is either a config alias with the same
// HostName and Port, or a host:port present in known_hosts; anything else
// is ReasonNotKnown and is never dialled.
func (d *Distributor) Plan(hosts []Host) ([]Plan, error) {
	kh, err := d.knownHosts()
	if err != nil {
		return nil, err
	}
	plans := make([]Plan, len(hosts))
	for i, h := range hosts {
		plans[i] = Plan{Host: h}
		if cfg, ok := d.configHost(h.Alias); ok && cfg.HostName == h.HostName && cfg.Port == h.Port {
			t := &Target{Addr: joinHostPort(cfg.HostName, cfg.Port), User: h.User, Key: cfg.Key}
			if cfg.ProxyJump != "" {
				jump, err := d.jumpTarget(cfg.ProxyJump)
				if err != nil {
					plans[i].Reason = ReasonProxyJump
					continue
				}
				t.Jump, t.JumpName = jump, cfg.ProxyJump
			}
			plans[i].Target = t
			continue
		}
		addr := joinHostPort(h.HostName, h.Port)
		if known, _ := lookup(kh, addr); known {
			plans[i].Target = &Target{Addr: addr, User: h.User}
			continue
		}
		plans[i].Reason = ReasonNotKnown
	}
	return plans, nil
}

// Run appends pub to authorized_keys on every planned host, a few at a
// time, and returns one Result per plan in the same order. Passphrases are
// asked for before the first connection.
func (d *Distributor) Run(ctx context.Context, pub ssh.PublicKey, plans []Plan) []Result {
	results := make([]Result, len(plans))
	var mu sync.Mutex
	report := func(i int, r Result, detail error) {
		mu.Lock()
		defer mu.Unlock()
		results[i] = r
		if d.Progress != nil {
			d.Progress(plans[i], r, detail)
		}
	}

	kh, err := d.knownHosts()
	if err != nil {
		for i, p := range plans {
			report(i, failed(p.Host.Alias, ReasonUnknownHostKey), err)
		}
		return results
	}
	auth := d.prepareAuth()
	defer auth.close()

	concurrency := d.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, p := range plans {
		if p.Target == nil {
			report(i, failed(p.Host.Alias, p.Reason), nil)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				report(i, failed(p.Host.Alias, ReasonTimeout), ctx.Err())
				return
			}
			defer func() { <-sem }()
			r, detail := d.one(ctx, kh, auth, pub, p)
			report(i, r, detail)
		}()
	}
	wg.Wait()
	return results
}

func failed(alias, reason string) Result {
	return Result{Alias: alias, Status: StatusFailed, Reason: reason}
}

func (d *Distributor) one(ctx context.Context, kh ssh.HostKeyCallback, auth *authSet, pub ssh.PublicKey, p Plan) (Result, error) {
	client, closeAll, hostKey, reason, err := d.connect(ctx, kh, auth, p.Target, 0)
	if reason != "" {
		return failed(p.Host.Alias, reason), err
	}
	defer closeAll()
	r := Result{Alias: p.Host.Alias, HostKey: hostKey}

	existing, err := d.run(ctx, client, readCommand, nil)
	if err != nil {
		r.Status, r.Reason = StatusFailed, commandReason(err)
		return r, fmt.Errorf("reading authorized_keys: %w", err)
	}
	if containsKey(existing, pub) {
		r.Status = StatusPresent
		return r, nil
	}
	line := AuthorizedLine(pub) + "\n"
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		line = "\n" + line
	}
	if _, err := d.run(ctx, client, appendCommand, strings.NewReader(line)); err != nil {
		r.Status, r.Reason = StatusFailed, commandReason(err)
		return r, fmt.Errorf("writing authorized_keys: %w", err)
	}
	r.Status = StatusAdded
	return r, nil
}

var errCommandTimeout = errors.New("command timed out")

func commandReason(err error) string {
	if errors.Is(err, errCommandTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	return ReasonWriteFailed
}

// containsKey reports whether any authorized_keys line (with or without
// options) is pub.
func containsKey(authorized []byte, pub ssh.PublicKey) bool {
	want := pub.Marshal()
	for _, line := range strings.Split(string(authorized), "\n") {
		if p, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil && bytes.Equal(p.Marshal(), want) {
			return true
		}
	}
	return false
}

// connect logs in to t (through its jump host, if any). On failure it
// returns a reason for the phone and the underlying error for the desktop.
func (d *Distributor) connect(ctx context.Context, kh ssh.HostKeyCallback, auth *authSet, t *Target, depth int) (*ssh.Client, func(), string, string, error) {
	known, want := lookup(kh, t.Addr)
	if !known {
		// Never dialled: the desktop has no key to check the server with.
		return nil, nil, "", ReasonUnknownHostKey, fmt.Errorf("%s is not in known_hosts", t.Addr)
	}

	var conn net.Conn
	closeJump := func() {}
	if t.Jump != nil {
		if depth > 0 {
			return nil, nil, "", ReasonProxyJump, errors.New("ProxyJump chains are not supported")
		}
		jump, closeJ, _, reason, err := d.connect(ctx, kh, auth, t.Jump, depth+1)
		if reason != "" {
			return nil, nil, "", ReasonProxyJump, fmt.Errorf("jump host %s: %s: %w", t.JumpName, reason, err)
		}
		c, err := jump.DialContext(ctx, "tcp", t.Addr)
		if err != nil {
			closeJ()
			return nil, nil, "", ReasonUnreachable, fmt.Errorf("via %s: %w", t.JumpName, err)
		}
		conn, closeJump = c, closeJ
	} else {
		c, err := d.dial(ctx, t.Addr)
		if err != nil {
			reason := ReasonUnreachable
			if isTimeout(err) {
				reason = ReasonTimeout
			}
			return nil, nil, "", reason, err
		}
		conn = c
	}

	// A channel through a jump host has no deadlines; a watchdog that
	// closes the connection works for both kinds.
	var timedOut bool
	var timedOutMu sync.Mutex
	watchdog := time.AfterFunc(d.connectTimeout(), func() {
		timedOutMu.Lock()
		timedOut = true
		timedOutMu.Unlock()
		_ = conn.Close()
	})
	stopCtx := context.AfterFunc(ctx, func() { _ = conn.Close() })

	var presented ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: t.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return auth.signersFor(t.Key), nil
		})},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			presented = key
			return kh(t.Addr, addrString(t.Addr), key)
		},
		HostKeyAlgorithms: hostKeyAlgorithms(want),
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	watchdog.Stop()
	stopCtx()
	timedOutMu.Lock()
	expired := timedOut || ctx.Err() != nil
	timedOutMu.Unlock()
	if err != nil {
		_ = conn.Close()
		closeJump()
		return nil, nil, "", handshakeReason(err, expired), err
	}
	client := ssh.NewClient(c, chans, reqs)
	return client, func() { _ = client.Close(); closeJump() }, hostKeyLine(presented), "", nil
}

func handshakeReason(err error, expired bool) string {
	var keyErr *knownhosts.KeyError
	var revoked *knownhosts.RevokedError
	switch {
	case errors.As(err, &revoked):
		return ReasonHostKeyChanged
	case errors.As(err, &keyErr):
		if len(keyErr.Want) == 0 {
			return ReasonUnknownHostKey
		}
		return ReasonHostKeyChanged
	case strings.Contains(err.Error(), "unable to authenticate"):
		return ReasonAuthFailed
	case expired || isTimeout(err):
		return ReasonTimeout
	default:
		return ReasonUnreachable
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout())
}

func hostKeyLine(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// run executes cmd in one session with stdin, returning stdout (capped).
func (d *Distributor) run(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader) ([]byte, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	out := &cappedBuffer{max: maxAuthorizedKeys}
	sess.Stdout = out
	if stdin != nil {
		sess.Stdin = stdin
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	timeout := d.CommandTimeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return out.buf.Bytes(), err
	case <-timer.C:
		_ = sess.Close()
		return nil, errCommandTimeout
	case <-ctx.Done():
		_ = sess.Close()
		return nil, ctx.Err()
	}
}

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		return 0, errors.New("authorized_keys is too large")
	}
	return b.buf.Write(p)
}

func (d *Distributor) dial(ctx context.Context, addr string) (net.Conn, error) {
	if d.Dial != nil {
		return d.Dial(ctx, "tcp", addr)
	}
	dialer := &net.Dialer{Timeout: d.connectTimeout()}
	return dialer.DialContext(ctx, "tcp", addr)
}

func (d *Distributor) connectTimeout() time.Duration {
	if d.ConnectTimeout > 0 {
		return d.ConnectTimeout
	}
	return DefaultConnectTimeout
}

func (d *Distributor) configHost(alias string) (sshconfig.HostConfig, bool) {
	for _, h := range d.Hosts {
		if h.Alias == alias {
			return h, true
		}
	}
	return sshconfig.HostConfig{}, false
}

// jumpTarget resolves a single-hop ProxyJump: a config alias (which must
// not jump again) or [user@]host[:port].
func (d *Distributor) jumpTarget(spec string) (*Target, error) {
	if strings.Contains(spec, ",") {
		return nil, errors.New("ProxyJump chains are not supported")
	}
	userPart, hostPart := "", spec
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		userPart, hostPart = spec[:at], spec[at+1:]
	}
	host, port := hostPart, 22
	if h, p, err := net.SplitHostPort(hostPart); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad ProxyJump port in %q", spec)
		}
		host, port = h, n
	}
	if host == "" {
		return nil, fmt.Errorf("bad ProxyJump %q", spec)
	}
	if cfg, ok := d.configHost(host); ok && hostPart == host {
		if cfg.ProxyJump != "" {
			return nil, errors.New("ProxyJump chains are not supported")
		}
		u := cfg.User
		if userPart != "" {
			u = userPart
		}
		return &Target{Addr: joinHostPort(cfg.HostName, cfg.Port), User: u, Key: cfg.Key}, nil
	}
	u := userPart
	if u == "" {
		u = d.localUser()
	}
	return &Target{Addr: joinHostPort(host, port), User: u}, nil
}

func (d *Distributor) localUser() string {
	if d.LocalUser != "" {
		return d.LocalUser
	}
	if u, err := user.Current(); err == nil {
		name := u.Username
		// Windows reports DOMAIN\user.
		if i := strings.LastIndex(name, `\`); i >= 0 {
			name = name[i+1:]
		}
		return name
	}
	return "root"
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// knownHosts loads the desktop's known_hosts; a missing file knows nobody.
func (d *Distributor) knownHosts() (ssh.HostKeyCallback, error) {
	path := d.KnownHostsPath
	if path == "" {
		path = filepath.Join(sshconfig.DefaultSshDir(), "known_hosts")
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return func(string, net.Addr, ssh.PublicKey) error { return &knownhosts.KeyError{} }, nil
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("reading known_hosts: %w", err)
	}
	return cb, nil
}

// probeKey is a public key no server has: asking known_hosts about it
// lists the keys known for a host without matching any of them.
var probeKey = func() ssh.PublicKey {
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		panic(err)
	}
	return pub
}()

// lookup reports whether known_hosts has any key for addr, and which.
func lookup(kh ssh.HostKeyCallback, addr string) (bool, []knownhosts.KnownKey) {
	err := kh(addr, addrString(addr), probeKey)
	var keyErr *knownhosts.KeyError
	var revoked *knownhosts.RevokedError
	switch {
	case err == nil, errors.As(err, &revoked):
		return true, nil
	case errors.As(err, &keyErr):
		return len(keyErr.Want) > 0, keyErr.Want
	}
	return false, nil
}

// hostKeyAlgorithms makes the server offer a key type known_hosts has, so
// a server that prefers another type is not mistaken for a changed key.
func hostKeyAlgorithms(want []knownhosts.KnownKey) []string {
	var algos []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			algos = append(algos, a)
		}
	}
	for _, k := range want {
		if k.Key.Type() == ssh.KeyAlgoRSA {
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
		}
		add(k.Key.Type())
	}
	return algos
}

// addrString is a net.Addr that is only its text, so known_hosts is asked
// about exactly the host:port we mean (not a jump host's address).
type addrString string

func (a addrString) Network() string { return "tcp" }
func (a addrString) String() string  { return string(a) }

// authSet is every signer the desktop can log in with.
type authSet struct {
	agentSigners []ssh.Signer
	keys         map[string]ssh.Signer
	order        []string
	closer       io.Closer
}

func (d *Distributor) prepareAuth() *authSet {
	a := &authSet{keys: map[string]ssh.Signer{}}
	open := d.Agent
	if open == nil {
		open = systemAgent
	}
	if ag, closer, err := open(); err == nil && ag != nil {
		if signers, err := ag.Signers(); err == nil {
			a.agentSigners = signers
		}
		a.closer = closer
	}
	for _, k := range d.Keys {
		if k.PrivateKey == "" {
			continue
		}
		signer := d.unlock(k)
		if signer == nil {
			continue
		}
		a.keys[k.Name] = signer
		a.order = append(a.order, k.Name)
	}
	return a
}

func (d *Distributor) unlock(k sshconfig.Key) ssh.Signer {
	if !k.Encrypted {
		signer, err := ssh.ParsePrivateKey([]byte(k.PrivateKey))
		if err != nil {
			return nil
		}
		return signer
	}
	if d.Passphrase == nil {
		return nil
	}
	for attempt := 1; attempt <= maxPassphraseAttempts; attempt++ {
		pass, err := d.Passphrase(k.Name, attempt)
		if err != nil || len(pass) == 0 {
			return nil
		}
		signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(k.PrivateKey), pass)
		clear(pass)
		if err == nil {
			return signer
		}
	}
	return nil
}

// signersFor: the host's own key first, then the agent's, then the rest,
// each public key once (servers count failed attempts).
func (a *authSet) signersFor(keyName string) []ssh.Signer {
	var out []ssh.Signer
	seen := map[string]bool{}
	add := func(s ssh.Signer) {
		blob := string(s.PublicKey().Marshal())
		if !seen[blob] {
			seen[blob] = true
			out = append(out, s)
		}
	}
	if s, ok := a.keys[keyName]; ok {
		add(s)
	}
	for _, s := range a.agentSigners {
		add(s)
	}
	for _, name := range a.order {
		add(a.keys[name])
	}
	return out
}

func (a *authSet) close() {
	if a.closer != nil {
		_ = a.closer.Close()
	}
}
