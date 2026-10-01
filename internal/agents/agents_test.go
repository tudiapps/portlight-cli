package agents

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func setup(t *testing.T, dirs ...string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, p := range probes {
		t.Setenv(p.envVar, "")
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func kinds(agents []Agent) []string {
	out := make([]string, len(agents))
	for i, a := range agents {
		out[i] = a.Kind
	}
	return out
}

func TestDetectFindsEachAgentByItsDirectory(t *testing.T) {
	setup(t, ".hermes", ".claude", ".moltbot")

	if got := kinds(Detect()); !slices.Equal(got, []string{Hermes, ClaudeCode, OpenClaw}) {
		t.Fatalf("Detect = %v", got)
	}
}

func TestDetectFindsNothingOnACleanMachine(t *testing.T) {
	setup(t)
	got := Detect()
	if got == nil || len(got) != 0 {
		t.Fatalf("Detect = %#v, want an empty list", got)
	}
}

func TestAFileIsNotAnInstall(t *testing.T) {
	home := setup(t)
	if err := os.WriteFile(filepath.Join(home, ".hermes"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Detect(); len(got) != 0 {
		t.Fatalf("Detect = %v", got)
	}
}

func TestEnvironmentOverridesTheDefaultLocation(t *testing.T) {
	setup(t, ".claude")
	elsewhere := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(elsewhere, "missing"))
	t.Setenv("HERMES_HOME", elsewhere)

	if got := kinds(Detect()); !slices.Equal(got, []string{Hermes}) {
		t.Fatalf("Detect = %v", got)
	}
}
