package envelope

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EnrollKeySize is the length of the enroll key ek the CLI puts inside the
// sealed payload. See docs/pairing-protocol.md "Enroll uzantısı".
const EnrollKeySize = 32

const (
	labelEnrollRequest = "portlight/pair/v1/enroll/request"
	labelEnrollResult  = "portlight/pair/v1/enroll/result"
	labelEnrollClose   = "portlight/pair/v1/enroll/close"
)

// ErrBoxOpen means a sealed enroll message did not decrypt: it was not made
// with this session's enroll key, or it was changed on the way.
var ErrBoxOpen = errors.New("enroll message does not authenticate")

// Box is a sealed enroll message as it travels: base64url, no padding.
type Box struct {
	Nonce string `json:"nonce"`
	Box   string `json:"box"`
}

// EnrollRequestKey is K_req = HKDF-SHA256(ek, salt=sid, info=request label).
func EnrollRequestKey(ek, sessionID []byte) []byte {
	return derive(ek, sessionID, labelEnrollRequest)
}

// EnrollResultKey is K_res = HKDF-SHA256(ek, salt=sid, info=result label).
func EnrollResultKey(ek, sessionID []byte) []byte {
	return derive(ek, sessionID, labelEnrollResult)
}

// EnrollCloseMAC authenticates the phone's "no key this time": only the
// device that opened the envelope knows ek.
func EnrollCloseMAC(ek, sessionID []byte) []byte {
	return mac(ek, labelEnrollClose, sessionID)
}

// SealEnrollRequest seals the phone's request. The CLI never sends one;
// tests use it to play the phone.
func SealEnrollRequest(ek, sessionID, plaintext []byte) (Box, error) {
	nonce, err := Random(chacha20poly1305.NonceSize)
	if err != nil {
		return Box{}, err
	}
	return sealBox(EnrollRequestKey(ek, sessionID), labelEnrollRequest, sessionID, nonce, plaintext)
}

// OpenEnrollRequest opens the phone's request; ErrBoxOpen if it was not
// sealed with this session's ek.
func OpenEnrollRequest(ek, sessionID []byte, b Box) ([]byte, error) {
	return openBox(EnrollRequestKey(ek, sessionID), labelEnrollRequest, sessionID, b)
}

// SealEnrollResult seals the per-host results for the phone.
func SealEnrollResult(ek, sessionID, plaintext []byte) (Box, error) {
	nonce, err := Random(chacha20poly1305.NonceSize)
	if err != nil {
		return Box{}, err
	}
	return sealBox(EnrollResultKey(ek, sessionID), labelEnrollResult, sessionID, nonce, plaintext)
}

// OpenEnrollResult opens the results; tests use it to play the phone.
func OpenEnrollResult(ek, sessionID []byte, b Box) ([]byte, error) {
	return openBox(EnrollResultKey(ek, sessionID), labelEnrollResult, sessionID, b)
}

func derive(ek, sessionID []byte, label string) []byte {
	key, err := hkdf.Key(sha256.New, ek, sessionID, label, chacha20poly1305.KeySize)
	if err != nil {
		// Only possible for an output length HKDF-SHA256 cannot produce.
		panic(err)
	}
	return key
}

func aad(label string, sessionID []byte) []byte {
	h := &fieldBuffer{}
	writeFields(h, label, [][]byte{sessionID})
	return h.b
}

func sealBox(key []byte, label string, sessionID, nonce, plaintext []byte) (Box, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return Box{}, fmt.Errorf("enroll seal: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad(label, sessionID))
	enc := base64.RawURLEncoding
	return Box{Nonce: enc.EncodeToString(nonce), Box: enc.EncodeToString(sealed)}, nil
}

func openBox(key []byte, label string, sessionID []byte, b Box) ([]byte, error) {
	enc := base64.RawURLEncoding
	nonce, err1 := enc.DecodeString(b.Nonce)
	sealed, err2 := enc.DecodeString(b.Box)
	if err1 != nil || err2 != nil || len(nonce) != chacha20poly1305.NonceSize {
		return nil, ErrBoxOpen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrBoxOpen
	}
	plain, err := aead.Open(nil, nonce, sealed, aad(label, sessionID))
	if err != nil {
		return nil, ErrBoxOpen
	}
	return plain, nil
}

type fieldBuffer struct{ b []byte }

func (f *fieldBuffer) Write(p []byte) (int, error) {
	f.b = append(f.b, p...)
	return len(p), nil
}
