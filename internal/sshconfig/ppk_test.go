package sshconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// copyVector puts a testdata .ppk into a fresh ~/.ssh and returns that dir.
func copyVector(t *testing.T, names ...string) string {
	t.Helper()
	sshDir := filepath.Join(fakeHome(t), ".ssh")
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(sshDir, name), string(data))
	}
	return sshDir
}

// passphrases answers the prompt with each value in turn.
func passphrases(values ...string) (func(string, int) ([]byte, error), *int) {
	calls := 0
	return func(string, int) ([]byte, error) {
		calls++
		if calls > len(values) {
			return nil, errors.New("asked too many times")
		}
		return []byte(values[calls-1]), nil
	}, &calls
}

func onlyKey(t *testing.T, keys []Key, warnings []string) Key {
	t.Helper()
	if len(keys) != 1 || len(warnings) != 0 {
		t.Fatalf("keys = %v, warnings = %q", keys, warnings)
	}
	return keys[0]
}

func TestPPKv3UnencryptedBecomesOpenSSH(t *testing.T) {
	sshDir := copyVector(t, "rsa-v3-none.ppk")

	keys, warnings := LoadKeys(nil, sshDir, LoadOptions{})
	k := onlyKey(t, keys, warnings)

	if k.Name != "rsa-v3-none" || !k.FromPPK || k.Encrypted || k.Algorithm != ssh.KeyAlgoRSA {
		t.Fatalf("key = %v", k)
	}
	signer, err := ssh.ParsePrivateKey([]byte(k.PrivateKey))
	if err != nil {
		t.Fatalf("converted key does not parse: %v", err)
	}
	if got := authorizedKey(signer.PublicKey()); got != k.PublicKey {
		t.Fatalf("public halves differ:\n%s\n%s", got, k.PublicKey)
	}
	if !strings.Contains(k.PrivateKey, "OPENSSH PRIVATE KEY") {
		t.Fatal("not in OpenSSH format")
	}
}

func TestProtectedPPKIsOnlyListedInPreview(t *testing.T) {
	sshDir := copyVector(t, "ed25519-v2-aes.ppk")

	keys, warnings := LoadKeys(nil, sshDir, LoadOptions{})
	k := onlyKey(t, keys, warnings)

	if !k.Encrypted || k.PrivateKey != "" || k.Algorithm != ssh.KeyAlgoED25519 || k.PublicKey == "" {
		t.Fatalf("key = %v (pub %q)", k, k.PublicKey)
	}
}

func TestProtectedPPKIsReEncryptedWithTheSamePassphrase(t *testing.T) {
	for _, vector := range []string{"ed25519-v2-aes.ppk", "rsa-v3-argon2id-aes.ppk"} {
		t.Run(vector, func(t *testing.T) {
			sshDir := copyVector(t, vector)
			ask, calls := passphrases("wrong", "testkey")

			keys, warnings := LoadKeys(nil, sshDir, LoadOptions{Passphrase: ask})
			k := onlyKey(t, keys, warnings)

			if *calls != 2 || !k.Encrypted {
				t.Fatalf("calls = %d, key = %v", *calls, k)
			}
			var missing *ssh.PassphraseMissingError
			if _, err := ssh.ParsePrivateKey([]byte(k.PrivateKey)); !errors.As(err, &missing) {
				t.Fatalf("converted key is not protected: %v", err)
			}
			signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(k.PrivateKey), []byte("testkey"))
			if err != nil {
				t.Fatalf("converted key does not open with the original passphrase: %v", err)
			}
			if got := authorizedKey(signer.PublicKey()); got != k.PublicKey {
				t.Fatal("public halves differ")
			}
		})
	}
}

func TestPPKGivesUpAfterThreeWrongPassphrases(t *testing.T) {
	sshDir := copyVector(t, "ed25519-v2-aes.ppk")
	ask, calls := passphrases("a", "b", "c", "testkey")

	keys, warnings := LoadKeys(nil, sshDir, LoadOptions{Passphrase: ask})

	if len(keys) != 0 || *calls != maxPassphraseAttempts || len(warnings) != 1 {
		t.Fatalf("keys = %v, calls = %d, warnings = %q", keys, *calls, warnings)
	}
}

func TestEmptyPassphraseSkipsThePPK(t *testing.T) {
	sshDir := copyVector(t, "ed25519-v2-aes.ppk")
	ask, _ := passphrases("")
	hosts := []HostConfig{{Alias: "box", IdentityFile: filepath.Join(sshDir, "ed25519-v2-aes.ppk")}}

	keys, warnings := LoadKeys(hosts, sshDir, LoadOptions{Passphrase: ask})

	if len(keys) != 0 || len(warnings) != 1 || hosts[0].Key != "" {
		t.Fatalf("keys = %v, warnings = %q, host key = %q", keys, warnings, hosts[0].Key)
	}
}
