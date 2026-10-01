//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// oNoFollow makes open fail on a symlink in the last path component.
const oNoFollow = syscall.O_NOFOLLOW

// setMode applies the exact permission bits; umask does not get a say.
func setMode(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// checkOwner refuses spool directories and files that belong to someone else.
func checkOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, not by this user", path, st.Uid)
	}
	return nil
}

func lockFile(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
