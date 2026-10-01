// Package putty reads PuTTY's saved sessions (Windows registry,
// HKCU\Software\SimonTatham\PuTTY\Sessions) as hosts, for Windows users
// who keep their servers in PuTTY rather than in ~/.ssh/config.
//
// Only SSH sessions are read. Passwords are never stored by PuTTY and so
// never read; a session's key file (.ppk) is handed on as IdentityFile and
// converted by sshconfig.LoadKeys like any other PuTTY key.
package putty
