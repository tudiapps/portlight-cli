package envelope

import (
	"bytes"
	"crypto/hmac"
	"testing"

	"filippo.io/age"
)

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()
	b, err := Random(n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealOpensOnlyForRecipient(t *testing.T) {
	phone, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := age.GenerateX25519Identity()
	plaintext := []byte(`{"hosts":[]}`)

	sealed, err := Seal(plaintext, phone.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("sealed envelope contains the plaintext")
	}

	opened, err := Open(sealed, phone)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open = %q, %v", opened, err)
	}
	if _, err := Open(sealed, other); err == nil {
		t.Fatal("another identity opened the envelope")
	}
}

func TestSealRejectsBadRecipient(t *testing.T) {
	if _, err := Seal([]byte("x"), "age1notakey"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSASIsStableAndBindsEveryInput(t *testing.T) {
	secret := mustRandom(t, SecretSize)
	sid := mustRandom(t, SessionIDSize)
	cliNonce := mustRandom(t, NonceSize)
	phoneNonce := mustRandom(t, NonceSize)
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()

	base := SAS(secret, sid, a.Recipient().String(), cliNonce, phoneNonce)
	if len(base) != 7 || base[3] != ' ' {
		t.Fatalf("SAS format = %q", base)
	}
	if again := SAS(secret, sid, a.Recipient().String(), cliNonce, phoneNonce); again != base {
		t.Fatalf("SAS not deterministic: %q vs %q", base, again)
	}

	// Each input changing should (overwhelmingly likely) change the code.
	variants := map[string]string{
		"recipient":   SAS(secret, sid, b.Recipient().String(), cliNonce, phoneNonce),
		"cli nonce":   SAS(secret, sid, a.Recipient().String(), mustRandom(t, NonceSize), phoneNonce),
		"phone nonce": SAS(secret, sid, a.Recipient().String(), cliNonce, mustRandom(t, NonceSize)),
		"secret":      SAS(mustRandom(t, SecretSize), sid, a.Recipient().String(), cliNonce, phoneNonce),
	}
	for name, v := range variants {
		if v == base {
			t.Errorf("SAS ignores the %s", name)
		}
	}
}

func TestClaimMACNeedsTheSecret(t *testing.T) {
	secret := mustRandom(t, SecretSize)
	sid := mustRandom(t, SessionIDSize)
	commitment := Commitment(mustRandom(t, NonceSize))

	good := ClaimMAC(secret, sid, "age1x", commitment)
	if !hmac.Equal(good, ClaimMAC(secret, sid, "age1x", commitment)) {
		t.Fatal("ClaimMAC not deterministic")
	}
	if hmac.Equal(good, ClaimMAC(mustRandom(t, SecretSize), sid, "age1x", commitment)) {
		t.Fatal("ClaimMAC ignores the secret")
	}
	if hmac.Equal(good, ClaimMAC(secret, sid, "age1y", commitment)) {
		t.Fatal("ClaimMAC ignores the recipient")
	}
}

func TestFieldsAreUnambiguous(t *testing.T) {
	// Without length prefixes these two would hash the same bytes.
	if bytes.Equal(hash("l", []byte("ab"), []byte("c")), hash("l", []byte("a"), []byte("bc"))) {
		t.Fatal("field boundaries are not encoded")
	}
}
