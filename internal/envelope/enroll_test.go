package envelope

import (
	"bytes"
	"errors"
	"testing"
)

func TestEnrollBoxRoundTripsAndBindsKeySessionAndDirection(t *testing.T) {
	ek := bytes.Repeat([]byte{7}, EnrollKeySize)
	sid := bytes.Repeat([]byte{9}, SessionIDSize)
	msg := []byte(`{"public_key":"ssh-ed25519 AAAA"}`)

	box, err := SealEnrollRequest(ek, sid, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenEnrollRequest(ek, sid, box)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("round trip: %q, %v", got, err)
	}

	otherKey := bytes.Repeat([]byte{8}, EnrollKeySize)
	otherSID := bytes.Repeat([]byte{1}, SessionIDSize)
	tampered := box
	tampered.Box = box.Box[:len(box.Box)-2] + "AA"
	for name, open := range map[string]func() ([]byte, error){
		"other ek":        func() ([]byte, error) { return OpenEnrollRequest(otherKey, sid, box) },
		"other session":   func() ([]byte, error) { return OpenEnrollRequest(ek, otherSID, box) },
		"other direction": func() ([]byte, error) { return OpenEnrollResult(ek, sid, box) },
		"tampered":        func() ([]byte, error) { return OpenEnrollRequest(ek, sid, tampered) },
		"bad nonce":       func() ([]byte, error) { return OpenEnrollRequest(ek, sid, Box{Nonce: "AAAA", Box: box.Box}) },
	} {
		if _, err := open(); !errors.Is(err, ErrBoxOpen) {
			t.Errorf("%s: err = %v, want ErrBoxOpen", name, err)
		}
	}
}

func TestEnrollKeysDifferPerDirection(t *testing.T) {
	ek := bytes.Repeat([]byte{7}, EnrollKeySize)
	sid := bytes.Repeat([]byte{9}, SessionIDSize)
	if bytes.Equal(EnrollRequestKey(ek, sid), EnrollResultKey(ek, sid)) {
		t.Fatal("request and result keys must differ")
	}
	if bytes.Equal(EnrollCloseMAC(ek, sid), EnrollCloseMAC(ek, bytes.Repeat([]byte{1}, SessionIDSize))) {
		t.Fatal("close MAC must depend on the session")
	}
}
