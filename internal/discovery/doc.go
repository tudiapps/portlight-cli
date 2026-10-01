// Package discovery helps the phone reach the CLI on the local network: it
// lists the addresses the QR offers and announces the session over mDNS
// (DNS-SD, _portlight._tcp) for when none of them works. The relay
// fallback will live next to it.
package discovery
