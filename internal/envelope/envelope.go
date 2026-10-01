package envelope

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"filippo.io/age"
)

// Sizes of the random values in the pairing handshake. See
// docs/pairing-protocol.md for how each one is used.
const (
	SessionIDSize = 16
	SecretSize    = 32
	NonceSize     = 32
)

// Domain labels keep each HMAC/hash use distinct even though they share
// the QR secret.
const (
	labelClaim  = "portlight/pair/v1/claim"
	labelCommit = "portlight/pair/v1/commit"
	labelSAS    = "portlight/pair/v1/sas"
	labelReject = "portlight/pair/v1/reject"
	labelRelay  = "portlight/pair/v1/relay"
)

// Random returns n bytes from the OS CSPRNG.
func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("reading randomness: %w", err)
	}
	return b, nil
}

// Seal encrypts plaintext as an age v1 file to recipient, the phone's
// ephemeral X25519 key in its "age1..." form.
func Seal(plaintext []byte, recipient string) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	return out.Bytes(), nil
}

// Open decrypts an age file with identity. The CLI never opens envelopes;
// this exists so tests can play the phone.
func Open(sealed []byte, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(sealed), identity)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	return io.ReadAll(r)
}

// ClaimMAC authenticates the phone's claim: only someone who scanned the
// QR (and so holds secret) can produce it.
func ClaimMAC(secret, sessionID []byte, recipient string, commitment []byte) []byte {
	return mac(secret, labelClaim, sessionID, []byte(recipient), commitment)
}

// Commitment binds the phone to its nonce before it sees the CLI's.
func Commitment(phoneNonce []byte) []byte {
	return hash(labelCommit, phoneNonce)
}

// RejectMAC authenticates the phone's "codes differ" or "cancel": only the
// device that scanned the QR can end the session this way.
func RejectMAC(secret, sessionID []byte) []byte {
	return mac(secret, labelReject, sessionID)
}

// Relay mailbox names; see docs/pairing-protocol.md "Relay".
var RelayBoxNames = []string{
	"claim", "claim/response", "reveal", "reveal/response",
	"envelope", "envelope/response", "reject",
}

// RelayBox is the relay mailbox id for one message of a session: 32 bytes
// the relay cannot link to the session or to the session's other boxes.
func RelayBox(secret, sessionID []byte, name string) []byte {
	return mac(secret, labelRelay, sessionID, []byte(name))
}

// SAS is the 6-digit code both screens show, formatted "123 456".
//
// It covers the recipient the CLI will encrypt to and both nonces. Because
// the phone commits to its nonce before the CLI reveals its own, a
// man-in-the-middle cannot search for a recipient whose code collides.
func SAS(secret, sessionID []byte, recipient string, cliNonce, phoneNonce []byte) string {
	sum := mac(secret, labelSAS, sessionID, []byte(recipient), cliNonce, phoneNonce)
	code := binary.BigEndian.Uint32(sum[:4]) % 1_000_000
	return fmt.Sprintf("%03d %03d", code/1000, code%1000)
}

// mac is HMAC-SHA256 over the label and length-prefixed fields, so no two
// different field lists can produce the same input.
func mac(key []byte, label string, fields ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	writeFields(h, label, fields)
	return h.Sum(nil)
}

func hash(label string, fields ...[]byte) []byte {
	h := sha256.New()
	writeFields(h, label, fields)
	return h.Sum(nil)
}

func writeFields(w io.Writer, label string, fields [][]byte) {
	var n [4]byte
	for _, f := range append([][]byte{[]byte(label)}, fields...) {
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		_, _ = w.Write(n[:])
		_, _ = w.Write(f)
	}
}
