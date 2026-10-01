// Package envelope holds the pairing cryptography: age (X25519 +
// ChaCha20-Poly1305) sealing, the claim MAC, the nonce commitment and the
// SAS. The relay, when there is one, only ever sees the sealed form.
package envelope
