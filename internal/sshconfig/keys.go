package sshconfig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kayrus/putty"
	"golang.org/x/crypto/ssh"
)

// Key is a private key pairing hands to the phone.
//
// PrivateKey is the file exactly as it is on disk; a passphrase-protected
// key stays protected and the phone asks for the passphrase on import. The
// desktop path is deliberately not sent.
type Key struct {
	Name       string `json:"name"`
	Algorithm  string `json:"algorithm"`
	PublicKey  string `json:"public_key,omitempty"`
	Encrypted  bool   `json:"encrypted"`
	PrivateKey string `json:"private_key,omitempty"`

	// FromPPK marks a key converted from PuTTY's format; it travels as
	// OpenSSH, re-encrypted with the same passphrase if it had one.
	FromPPK bool `json:"-"`
}

// Redacted returns k without its private half, for previews.
func (k Key) Redacted() Key {
	k.PrivateKey = ""
	return k
}

// String never includes key material, so a key cannot leak through %v.
func (k Key) String() string {
	return fmt.Sprintf("Key(%s, %s, encrypted=%t)", k.Name, k.Algorithm, k.Encrypted)
}

// defaultKeyNames are the files ssh tries when a host names no IdentityFile.
var defaultKeyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// LoadOptions controls how LoadKeys treats keys it cannot read as-is.
type LoadOptions struct {
	// Passphrase unlocks a passphrase-protected PuTTY key so it can be
	// converted; attempt counts from 1. Returning an empty passphrase skips
	// the key. Nil means preview: such keys are listed without private
	// material and nobody is asked.
	Passphrase func(path string, attempt int) ([]byte, error)
}

// maxPassphraseAttempts is how many wrong passphrases a .ppk gets.
const maxPassphraseAttempts = 3

// LoadKeys reads the private keys pairing sends: every IdentityFile the
// hosts name, plus ssh's default keys and any PuTTY .ppk in sshDir. Each
// host's Key field is set to the name of the key it uses. Files that are
// missing are skipped silently when they are only defaults; unreadable or
// unparseable ones are skipped with a warning.
func LoadKeys(hosts []HostConfig, sshDir string, opts LoadOptions) ([]Key, []string) {
	if sshDir == "" {
		sshDir = DefaultSshDir()
	}
	var (
		keys     []Key
		warnings []string
		byPath   = map[string]string{} // absolute path -> key name
		names    = map[string]bool{}
	)

	load := func(path string, explicit bool) string {
		path = expandHome(path)
		if name, ok := byPath[path]; ok {
			return name
		}
		key, err := readKey(path, opts)
		if err != nil {
			if explicit || !errors.Is(err, os.ErrNotExist) {
				warnings = append(warnings, fmt.Sprintf("%s: %v", path, err))
			}
			byPath[path] = ""
			return ""
		}
		base := filepath.Base(path)
		if key.FromPPK {
			base = strings.TrimSuffix(base, filepath.Ext(base))
		}
		key.Name = uniqueName(base, names)
		byPath[path] = key.Name
		keys = append(keys, key)
		return key.Name
	}

	for i := range hosts {
		if hosts[i].IdentityFile != "" {
			hosts[i].Key = load(hosts[i].IdentityFile, true)
		}
	}
	for _, name := range defaultKeyNames {
		load(filepath.Join(sshDir, name), false)
	}
	ppks, _ := filepath.Glob(filepath.Join(sshDir, "*.ppk"))
	for _, path := range ppks {
		load(path, false)
	}
	return keys, warnings
}

func readKey(path string, opts LoadOptions) (Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	if bytes.HasPrefix(data, []byte("PuTTY-User-Key-File-")) {
		return readPPK(path, data, opts)
	}
	key := Key{PrivateKey: string(data)}

	signer, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		key.Algorithm = signer.PublicKey().Type()
		key.PublicKey = authorizedKey(signer.PublicKey())
	case errors.As(err, &missing):
		key.Encrypted = true
		if missing.PublicKey != nil {
			key.Algorithm = missing.PublicKey.Type()
			key.PublicKey = authorizedKey(missing.PublicKey)
		} else if pub := readPublicKey(path + ".pub"); pub != nil {
			// Legacy PEM keys hide the public half; the .pub file has it.
			key.Algorithm = pub.Type()
			key.PublicKey = authorizedKey(pub)
		}
	default:
		// The parser's message never quotes the key bytes.
		return Key{}, fmt.Errorf("not an OpenSSH/PEM private key: %w", err)
	}
	return key, nil
}

func readPublicKey(path string) ssh.PublicKey {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil
	}
	return pub
}

func authorizedKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func uniqueName(base string, taken map[string]bool) string {
	name := base
	for i := 2; taken[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	taken[name] = true
	return name
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// readPPK converts a PuTTY private key to OpenSSH form. A protected key is
// decrypted with a passphrase from opts and re-encrypted with the same one,
// so it stays as protected on the phone as it was on disk.
func readPPK(path string, data []byte, opts LoadOptions) (Key, error) {
	ppk, err := putty.New(data)
	if err != nil {
		return Key{}, fmt.Errorf("not a valid PuTTY key: %w", err)
	}
	rawPub, err := ppk.ParseRawPublicKey()
	if err != nil {
		return Key{}, fmt.Errorf("PuTTY key: %w", err)
	}
	pub, err := ssh.NewPublicKey(derefKey(rawPub))
	if err != nil {
		return Key{}, fmt.Errorf("PuTTY key: %w", err)
	}
	key := Key{
		Algorithm: pub.Type(),
		PublicKey: authorizedKey(pub),
		Encrypted: ppk.Encryption != "none",
		FromPPK:   true,
	}

	var passphrase []byte
	if key.Encrypted {
		if opts.Passphrase == nil {
			return key, nil // preview: listed, not unlocked
		}
		for attempt := 1; ; attempt++ {
			passphrase, err = opts.Passphrase(path, attempt)
			if err != nil {
				return Key{}, err
			}
			if len(passphrase) == 0 {
				return Key{}, fmt.Errorf("skipped: no passphrase given")
			}
			// decrypt works in place, so every attempt starts from the file.
			fresh, _ := putty.New(data)
			if _, err = fresh.ParseRawPrivateKey(passphrase); err == nil {
				ppk = fresh
				break
			}
			if attempt >= maxPassphraseAttempts {
				return Key{}, fmt.Errorf("wrong passphrase %d times; skipped", attempt)
			}
		}
	}

	raw, err := ppk.ParseRawPrivateKey(passphrase)
	if err != nil {
		return Key{}, fmt.Errorf("PuTTY key: %w", err)
	}
	raw = derefKey(raw)
	var block *pem.Block
	if key.Encrypted {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(raw, ppk.Comment, passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(raw, ppk.Comment)
	}
	if err != nil {
		return Key{}, fmt.Errorf("converting %s key: %w", key.Algorithm, err)
	}
	key.PrivateKey = string(pem.EncodeToMemory(block))
	return key, nil
}

// derefKey turns the *ed25519 pointers the PuTTY parser returns into the
// values x/crypto/ssh expects; other key types pass through.
func derefKey(k any) any {
	switch v := k.(type) {
	case *ed25519.PublicKey:
		return *v
	case *ed25519.PrivateKey:
		return *v
	}
	return k
}
