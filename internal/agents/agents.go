package agents

import (
	"os"
	"path/filepath"
)

// Kinds of agent the app has (or will have) a panel for.
const (
	Hermes     = "hermes"
	ClaudeCode = "claude_code"
	OpenClaw   = "openclaw"
)

// Agent is an install found on this machine. Only the kind travels: no
// paths, no config contents and no credentials. Carrying agent tokens is a
// separate, later step (BACKLOG Faz 5) that each adapter will define.
type Agent struct {
	Kind string `json:"kind"`
}

// probe is one agent and the directories that betray it, in order. envVar,
// when set in the environment, replaces the default locations.
type probe struct {
	kind   string
	envVar string
	dirs   []string // relative to the home directory
}

var probes = []probe{
	{kind: Hermes, envVar: "HERMES_HOME", dirs: []string{".hermes"}},
	{kind: ClaudeCode, envVar: "CLAUDE_CONFIG_DIR", dirs: []string{".claude"}},
	// OpenClaw was called Clawdbot, then Moltbot; old installs keep the
	// old state directory.
	{kind: OpenClaw, envVar: "OPENCLAW_STATE_DIR", dirs: []string{".openclaw", ".clawdbot", ".moltbot"}},
}

// Detect lists the agents installed for the current user. It only checks
// that a directory exists; it opens no file inside it.
func Detect() []Agent {
	home, _ := os.UserHomeDir()
	found := []Agent{}
	for _, p := range probes {
		if p.found(home) {
			found = append(found, Agent{Kind: p.kind})
		}
	}
	return found
}

func (p probe) found(home string) bool {
	if dir := os.Getenv(p.envVar); dir != "" {
		return isDir(dir)
	}
	if home == "" {
		return false
	}
	for _, d := range p.dirs {
		if isDir(filepath.Join(home, d)) {
			return true
		}
	}
	return false
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
