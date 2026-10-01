package sshconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeKey(t *testing.T, path, passphrase string) ssh.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(pem.EncodeToMemory(block)))
	sshPub, _ := ssh.NewPublicKey(pub)
	return sshPub
}

func TestLoadKeysSendsReferencedAndDefaultKeys(t *testing.T) {
	home := fakeHome(t)
	sshDir := filepath.Join(home, ".ssh")
	defaultPub := writeKey(t, filepath.Join(sshDir, "id_ed25519"), "")
	writeKey(t, filepath.Join(sshDir, "work", "deploy"), "hunter2")

	hosts := []HostConfig{
		{Alias: "a", IdentityFile: "~/.ssh/work/deploy"},
		{Alias: "b", IdentityFile: filepath.Join(sshDir, "id_ed25519")},
		{Alias: "c"},
	}
	keys, warnings := LoadKeys(hosts, sshDir, LoadOptions{})

	if len(warnings) != 0 {
		t.Fatalf("warnings = %q", warnings)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %v", keys)
	}
	if hosts[0].Key != "deploy" || hosts[1].Key != "id_ed25519" || hosts[2].Key != "" {
		t.Fatalf("host keys = %q %q %q", hosts[0].Key, hosts[1].Key, hosts[2].Key)
	}

	deploy, def := keys[0], keys[1]
	if !deploy.Encrypted || deploy.Algorithm != ssh.KeyAlgoED25519 || deploy.PublicKey == "" {
		t.Errorf("deploy = %v (pub %q)", deploy, deploy.PublicKey)
	}
	if !strings.Contains(deploy.PrivateKey, "OPENSSH PRIVATE KEY") {
		t.Error("deploy private key not carried as-is")
	}
	if def.Encrypted || def.PublicKey != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(defaultPub))) {
		t.Errorf("default = %v (pub %q)", def, def.PublicKey)
	}
}

func TestLoadKeysWarnsOnlyForUsableProblems(t *testing.T) {
	home := fakeHome(t)
	sshDir := filepath.Join(home, ".ssh")
	writeFile(t, filepath.Join(sshDir, "legacy.ppk"), "PuTTY-User-Key-File-3: ssh-ed25519\n")

	hosts := []HostConfig{
		{Alias: "ppk", IdentityFile: filepath.Join(sshDir, "legacy.ppk")},
		{Alias: "gone", IdentityFile: filepath.Join(sshDir, "missing")},
	}
	keys, warnings := LoadKeys(hosts, sshDir, LoadOptions{})

	// No default keys exist, and their absence is not worth a warning.
	if len(keys) != 0 || len(warnings) != 2 {
		t.Fatalf("keys = %v, warnings = %q", keys, warnings)
	}
	if hosts[0].Key != "" || hosts[1].Key != "" {
		t.Fatal("hosts point at keys that were not sent")
	}
}

func TestLoadKeysKeepsNamesUnique(t *testing.T) {
	home := fakeHome(t)
	writeKey(t, filepath.Join(home, "a", "id"), "")
	writeKey(t, filepath.Join(home, "b", "id"), "")
	hosts := []HostConfig{
		{IdentityFile: filepath.Join(home, "a", "id")},
		{IdentityFile: filepath.Join(home, "b", "id")},
	}

	keys, _ := LoadKeys(hosts, filepath.Join(home, ".ssh"), LoadOptions{})

	if len(keys) != 2 || hosts[0].Key != "id" || hosts[1].Key != "id-2" {
		t.Fatalf("names = %q %q", hosts[0].Key, hosts[1].Key)
	}
}

func TestKeyNeverPrintsMaterial(t *testing.T) {
	k := Key{Name: "id", Algorithm: "ssh-ed25519", PrivateKey: "-----BEGIN SECRET-----"}
	for _, s := range []string{k.String(), fmt.Sprint(k), fmt.Sprintf("%v", []Key{k})} {
		if strings.Contains(s, "SECRET") {
			t.Fatalf("formatted key leaks material: %s", s)
		}
	}
	if k.Redacted().PrivateKey != "" || k.PrivateKey == "" {
		t.Fatal("Redacted must copy, not mutate")
	}
}

func TestHostJSONHidesDesktopPath(t *testing.T) {
	h := HostConfig{Alias: "x", IdentityFile: `C:\Users\me\.ssh\id`, Key: "id"}
	data := string(mustJSON(t, h))
	if strings.Contains(data, "Users") || !strings.Contains(data, `"key":"id"`) {
		t.Fatalf("json = %s", data)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
