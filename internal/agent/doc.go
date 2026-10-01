// Package agent is the server side of Portlight's agent panels
// (docs/agents-protocol.md). It installs a Claude Code hook that parks every
// permission request in a file spool under ~/.portlight/agents/claude-code,
// and gives the phone a fixed set of commands — pending, decide, events,
// status — that it runs over the SSH connection it already trusts.
//
// There is no listener, daemon or relay. Whenever anything goes wrong the
// hook returns "no decision", so Claude Code asks in the terminal exactly as
// if Portlight were not installed.
package agent
