// Package pairing runs one single-use pairing session on the local network:
// the QR carries a session id and a secret that never crosses the network,
// the phone claims the session with a MAC over that secret, both sides
// derive a 6-digit SAS through a commit/reveal exchange, and only after the
// user confirms the codes match is the payload sealed to the phone's age
// recipient and handed over. Protocol: docs/pairing-protocol.md.
package pairing
