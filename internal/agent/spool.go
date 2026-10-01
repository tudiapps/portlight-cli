package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// Adapter names: the CLI argument and directory, and the "agent" field value.
const (
	adapterName = "claude-code"
	agentKind   = "claude_code"
)

const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600

	// maxSpoolFile bounds every spool file we read back.
	maxSpoolFile = 1 << 20
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var (
	errExists  = errors.New("already exists")
	errNotHome = errors.New("home directory is not known")
)

// validID reports whether id is safe to join into a spool path.
func validID(id string) bool { return idPattern.MatchString(id) }

// newID returns 16 random bytes as lowercase hex.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// spool is ~/.portlight/agents/claude-code and the paths inside it.
type spool struct {
	home string
}

func newSpool(home string) (spool, error) {
	if home == "" || !filepath.IsAbs(home) {
		return spool{}, errNotHome
	}
	return spool{home: home}, nil
}

func (s spool) chain() []string {
	base := filepath.Join(s.home, ".portlight")
	agents := filepath.Join(base, "agents")
	root := filepath.Join(agents, adapterName)
	return []string{base, agents, root, filepath.Join(root, "pending"), filepath.Join(root, "decisions")}
}

func (s spool) root() string         { return filepath.Join(s.home, ".portlight", "agents", adapterName) }
func (s spool) pendingDir() string   { return filepath.Join(s.root(), "pending") }
func (s spool) decisionsDir() string { return filepath.Join(s.root(), "decisions") }
func (s spool) eventsPath() string   { return filepath.Join(s.root(), "events.jsonl") }
func (s spool) lockPath() string     { return filepath.Join(s.root(), ".events.lock") }
func (s spool) installPath() string  { return filepath.Join(s.root(), "install.json") }

func (s spool) pendingPath(id string) (string, error) {
	if !validID(id) {
		return "", fmt.Errorf("invalid id %q", id)
	}
	return filepath.Join(s.pendingDir(), id+".json"), nil
}

func (s spool) decisionPath(id string) (string, error) {
	if !validID(id) {
		return "", fmt.Errorf("invalid id %q", id)
	}
	return filepath.Join(s.decisionsDir(), id+".json"), nil
}

// ensure creates the directory chain with mode 0700 and refuses any link in
// it that is a symlink, not a directory, or owned by someone else.
func (s spool) ensure() error {
	for _, dir := range s.chain() {
		if err := os.Mkdir(dir, dirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := checkDir(dir); err != nil {
			return err
		}
		if err := setMode(dir, dirMode); err != nil {
			return err
		}
	}
	return nil
}

// exists checks the chain without creating anything. It returns false with
// no error when the spool has never been created.
func (s spool) exists() (bool, error) {
	for _, dir := range s.chain() {
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err := checkDir(dir); err != nil {
			return false, err
		}
	}
	return true, nil
}

func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return checkOwner(dir, fi)
}

// writeAtomic writes data to dir/name through a fresh temp file (O_EXCL,
// 0600) and a rename, so readers never see a partial file and a symlink
// planted at the target is replaced, not followed.
func writeAtomic(dir, name string, data []byte) error {
	tmp, err := writeTemp(dir, name, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// createAtomic is writeAtomic that never replaces an existing file: the
// first writer wins and later ones get errExists.
func createAtomic(dir, name string, data []byte) error {
	tmp, err := writeTemp(dir, name, data)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	target := filepath.Join(dir, name)
	if err := os.Link(tmp, target); err != nil {
		if _, statErr := os.Lstat(target); statErr == nil {
			return errExists
		}
		// Filesystems without hard links: fall back to a rename after an
		// existence check (a tiny race, but still never a partial file).
		if err := os.Rename(tmp, target); err != nil {
			return err
		}
	}
	return nil
}

func writeTemp(dir, name string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := setMode(tmp, fileMode); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// readRegular reads a regular file that is not a symlink, up to limit bytes.
func readRegular(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// openNoFollow opens (creating if needed) a spool file for appending or
// locking, refusing symlinks.
func openNoFollow(path string, flag int) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.OpenFile(path, flag|oNoFollow, fileMode)
	if err != nil {
		return nil, err
	}
	if err := setMode(path, fileMode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// removeQuiet deletes a spool file, ignoring "not there".
func removeQuiet(path string) {
	_ = os.Remove(path)
}
