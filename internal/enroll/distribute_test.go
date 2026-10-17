package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tudiapps/portlight-cli/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// desktopKey is the desktop's login key, as BuildPayload would load it.
func desktopKey(t *testing.T, name, passphrase string) (sshconfig.Key, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return sshconfig.Key{
		Name:       name,
		Algorithm:  signer.PublicKey().Type(),
		Encrypted:  passphrase != "",
		PrivateKey: string(pem.EncodeToMemory(block)),
	}, signer.PublicKey()
}

func phoneKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	return newSigner(t).PublicKey()
}

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func noAgent() (agent.Agent, io.Closer, error) { return nil, nil, nil }

func distributor(knownHosts string, keys ...sshconfig.Key) *Distributor {
	return &Distributor{
		Keys:           keys,
		KnownHostsPath: knownHosts,
		Agent:          noAgent,
		ConnectTimeout: 5 * time.Second,
		CommandTimeout: 5 * time.Second,
	}
}

func localHost(alias string, s *fakeServer, user string) Host {
	return Host{Alias: alias, HostName: "127.0.0.1", User: user, Port: s.port()}
}

func run(t *testing.T, d *Distributor, pub ssh.PublicKey, hosts ...Host) []Result {
	t.Helper()
	plans, err := d.Plan(hosts)
	if err != nil {
		t.Fatal(err)
	}
	return d.Run(context.Background(), pub, plans)
}

func TestAddsTheKeyOnceAndReportsTheVerifiedHostKey(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	server := startFakeServer(t, loginPub)
	d := distributor(writeKnownHosts(t, server.knownHostsLine()), key)
	phone := phoneKey(t)

	results := run(t, d, phone, localHost("box", server, "deploy"))
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(server.hostKey.PublicKey())))
	if got := results[0]; got.Status != StatusAdded || got.Alias != "box" || got.HostKey != want {
		t.Fatalf("first run = %+v, want added with host key %q", got, want)
	}
	if got, want := server.file("deploy"), AuthorizedLine(phone)+"\n"; got != want {
		t.Fatalf("authorized_keys = %q, want %q", got, want)
	}

	// Again: nothing new is written.
	results = run(t, d, phone, localHost("box", server, "deploy"))
	if results[0].Status != StatusPresent {
		t.Fatalf("second run = %+v, want present", results[0])
	}
	if got := strings.Count(server.file("deploy"), "\n"); got != 1 {
		t.Fatalf("authorized_keys has %d lines, want 1", got)
	}
}

func TestStartsOnANewLineWhenTheFileDoesNotEndWithOne(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	server := startFakeServer(t, loginPub)
	server.setFile("root", "ssh-ed25519 AAAAexisting laptop")
	phone := phoneKey(t)

	run(t, distributor(writeKnownHosts(t, server.knownHostsLine()), key), phone, localHost("box", server, "root"))
	want := "ssh-ed25519 AAAAexisting laptop\n" + AuthorizedLine(phone) + "\n"
	if got := server.file("root"); got != want {
		t.Fatalf("authorized_keys = %q, want %q", got, want)
	}
}

func TestAKeyAlreadyThereWithOptionsCountsAsPresent(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	server := startFakeServer(t, loginPub)
	phone := phoneKey(t)
	existing := `from="10.0.0.0/8" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(phone))) + " old\n"
	server.setFile("root", existing)

	results := run(t, distributor(writeKnownHosts(t, server.knownHostsLine()), key), phone, localHost("box", server, "root"))
	if results[0].Status != StatusPresent || server.file("root") != existing {
		t.Fatalf("result %+v, file %q", results[0], server.file("root"))
	}
}

func TestNeverConnectsToAHostKeyKnownHostsDoesNotHave(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	server := startFakeServer(t, loginPub)
	other := startFakeServer(t, loginPub)
	var dials atomic.Int32
	d := distributor(writeKnownHosts(t, other.knownHostsLine()), key)
	d.Hosts = []sshconfig.HostConfig{{Alias: "box", HostName: "127.0.0.1", Port: server.port(), User: "root"}}
	d.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	results := run(t, d, phoneKey(t), localHost("box", server, "root"))
	if results[0].Status != StatusFailed || results[0].Reason != ReasonUnknownHostKey {
		t.Fatalf("result = %+v, want unknown_host_key", results[0])
	}
	if dials.Load() != 0 || len(server.seenCommands()) != 0 {
		t.Fatal("the unknown server was contacted")
	}
}

func TestAChangedHostKeyFailsWithoutWriting(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	server := startFakeServer(t, loginPub)
	// known_hosts holds a different ed25519 key for the same address.
	stale := "[127.0.0.1]:" + itoa(server.port()) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey())))
	d := distributor(writeKnownHosts(t, stale), key)
	d.Hosts = []sshconfig.HostConfig{{Alias: "box", HostName: "127.0.0.1", Port: server.port(), User: "root"}}

	results := run(t, d, phoneKey(t), localHost("box", server, "root"))
	if results[0].Reason != ReasonHostKeyChanged || results[0].HostKey != "" {
		t.Fatalf("result = %+v, want host_key_changed", results[0])
	}
	if len(server.seenCommands()) != 0 {
		t.Fatal("a command ran on a server with a changed key")
	}
}

func TestRefusedLoginIsAuthFailed(t *testing.T) {
	key, _ := desktopKey(t, "id_ed25519", "")
	_, someoneElse := desktopKey(t, "other", "")
	server := startFakeServer(t, someoneElse)

	results := run(t, distributor(writeKnownHosts(t, server.knownHostsLine()), key), phoneKey(t), localHost("box", server, "root"))
	if results[0].Reason != ReasonAuthFailed {
		t.Fatalf("result = %+v, want auth_failed", results[0])
	}
}

func TestEncryptedKeyIsUnlockedOnceWithItsPassphrase(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "s3cret")
	server := startFakeServer(t, loginPub)
	d := distributor(writeKnownHosts(t, server.knownHostsLine()), key)
	var asked []int
	d.Passphrase = func(name string, attempt int) ([]byte, error) {
		asked = append(asked, attempt)
		if attempt == 1 {
			return []byte("wrong"), nil
		}
		return []byte("s3cret"), nil
	}

	results := run(t, d, phoneKey(t), localHost("a", server, "root"), localHost("b", server, "deploy"))
	for _, r := range results {
		if r.Status != StatusAdded {
			t.Fatalf("result = %+v, want added", r)
		}
	}
	if len(asked) != 2 {
		t.Fatalf("passphrase asked %v, want twice (one wrong) for both hosts together", asked)
	}
}

func TestUnknownHostsAreNeverDialled(t *testing.T) {
	key, _ := desktopKey(t, "id_ed25519", "")
	d := distributor(writeKnownHosts(t, "# empty"), key)
	d.Dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialled a host the desktop does not know")
		return nil, nil
	}
	results := run(t, d, phoneKey(t), Host{Alias: "x", HostName: "203.0.113.9", User: "root", Port: 22})
	if results[0].Reason != ReasonNotKnown {
		t.Fatalf("result = %+v, want not_known", results[0])
	}
}

func TestConfigAliasMustMatchHostNameAndPort(t *testing.T) {
	d := distributor(writeKnownHosts(t, "# empty"))
	d.Hosts = []sshconfig.HostConfig{{Alias: "prod", HostName: "10.0.0.1", Port: 22, User: "ubuntu", Key: "id_prod"}}

	plans, err := d.Plan([]Host{
		{Alias: "prod", HostName: "10.0.0.1", User: "root", Port: 22},
		{Alias: "prod", HostName: "198.51.100.7", User: "root", Port: 22}, // alias reused for another address
	})
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].Target == nil || plans[0].Target.Addr != "10.0.0.1:22" || plans[0].Target.User != "root" || plans[0].Target.Key != "id_prod" {
		t.Fatalf("plan 0 = %+v", plans[0].Target)
	}
	if plans[1].Target != nil || plans[1].Reason != ReasonNotKnown {
		t.Fatalf("plan 1 = %+v, want not_known", plans[1])
	}
}

func TestAppendFailureIsWriteFailed(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	server := startFakeServer(t, loginPub)
	server.failApp = true
	results := run(t, distributor(writeKnownHosts(t, server.knownHostsLine()), key), phoneKey(t), localHost("box", server, "root"))
	if results[0].Reason != ReasonWriteFailed {
		t.Fatalf("result = %+v, want write_failed", results[0])
	}
}

func TestUnreachableHost(t *testing.T) {
	key, _ := desktopKey(t, "id_ed25519", "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	line := "[127.0.0.1]:" + itoa(port) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey())))
	results := run(t, distributor(writeKnownHosts(t, line), key), phoneKey(t), Host{Alias: "gone", HostName: "127.0.0.1", User: "root", Port: port})
	if results[0].Reason != ReasonUnreachable {
		t.Fatalf("result = %+v, want unreachable", results[0])
	}
}

func TestProxyJumpThroughAConfigAlias(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	bastion := startFakeServer(t, loginPub)
	target := startFakeServer(t, loginPub)
	d := distributor(writeKnownHosts(t, bastion.knownHostsLine(), target.knownHostsLine()), key)
	d.Hosts = []sshconfig.HostConfig{
		{Alias: "bastion", HostName: "127.0.0.1", Port: bastion.port(), User: "jump"},
		{Alias: "inner", HostName: "127.0.0.1", Port: target.port(), User: "app", ProxyJump: "bastion"},
	}
	phone := phoneKey(t)

	results := run(t, d, phone, localHost("inner", target, "app"))
	if results[0].Status != StatusAdded {
		t.Fatalf("result = %+v, want added", results[0])
	}
	if target.file("app") == "" || bastion.file("jump") != "" {
		t.Fatal("key should land on the target only")
	}
}

func TestProxyJumpChainsAreRefused(t *testing.T) {
	d := distributor(writeKnownHosts(t, "# empty"))
	d.Hosts = []sshconfig.HostConfig{{Alias: "deep", HostName: "10.0.0.2", Port: 22, ProxyJump: "a,b"}}
	plans, err := d.Plan([]Host{{Alias: "deep", HostName: "10.0.0.2", User: "root", Port: 22}})
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].Reason != ReasonProxyJump {
		t.Fatalf("plan = %+v, want proxy_jump", plans[0])
	}
}

func TestCancelledRunReportsTimeout(t *testing.T) {
	key, loginPub := desktopKey(t, "id_ed25519", "")
	server := startFakeServer(t, loginPub)
	d := distributor(writeKnownHosts(t, server.knownHostsLine()), key)
	plans, err := d.Plan([]Host{localHost("box", server, "root")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := d.Run(ctx, phoneKey(t), plans)
	if results[0].Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", results[0])
	}
}

func TestHostKeyAlgorithmsFollowKnownHosts(t *testing.T) {
	if got := hostKeyAlgorithms(nil); len(got) != 0 {
		t.Fatalf("no known keys should leave the default list, got %v", got)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	got := hostKeyAlgorithms([]knownhosts.KnownKey{{Key: rsaPub}, {Key: phoneKey(t)}})
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA, ssh.KeyAlgoED25519}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("algorithms = %v, want %v", got, want)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
