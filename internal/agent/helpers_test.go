package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// testBinary is an absolute path on every OS.
var testBinary = func() string {
	if runtime.GOOS == "windows" {
		return "C:/opt/portlight/bin/portlight"
	}
	return "/opt/portlight/bin/portlight"
}()

func testEnv(t *testing.T) Env {
	t.Helper()
	return Env{
		Home:       t.TempDir(),
		Version:    "test",
		Executable: func() (string, error) { return testBinary, nil },
		Poll:       10 * time.Millisecond,
	}
}

// run executes an agent command and returns exit code, stdout, stderr.
func run(t *testing.T, env Env, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(env, args, &out, &errb)
	return code, out.String(), errb.String()
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, data)
	}
	return m
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSpool(t *testing.T, env Env) spool {
	t.Helper()
	sp, err := newSpool(env.Home)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.ensure(); err != nil {
		t.Fatal(err)
	}
	return sp
}

// putPending writes a pending request directly, as the hook would.
func putPending(t *testing.T, sp spool, id string, created, expires int64) {
	t.Helper()
	p := Pending{V: 1, ID: id, Agent: agentKind, CreatedAt: created, ExpiresAt: expires,
		Tool: "Bash", Summary: "ls", Input: json.RawMessage(`{"command":"ls"}`)}
	data, _ := json.Marshal(p)
	if err := writeAtomic(sp.pendingDir(), id+".json", data); err != nil {
		t.Fatal(err)
	}
}

func hexID(c byte) string { return string(bytes.Repeat([]byte{c}, 32)) }
