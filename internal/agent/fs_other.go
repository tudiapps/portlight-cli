//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly)

package agent

import "os"

// The hook is meant for Linux and macOS servers. Elsewhere (Windows) the
// binary still builds and the spool still works, but POSIX modes, ownership
// and flock do not exist; symlinks are still refused through Lstat checks.
const oNoFollow = 0

func setMode(string, os.FileMode) error    { return nil }
func checkOwner(string, os.FileInfo) error { return nil }
func lockFile(*os.File) error              { return nil }
func unlockFile(*os.File) error            { return nil }
