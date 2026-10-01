package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// handlers returns the command handlers registered for event.
func handlers(t *testing.T, settings map[string]any, event string) []map[string]any {
	t.Helper()
	hooks, _ := settings["hooks"].(map[string]any)
	groups, _ := hooks[event].([]any)
	var out []map[string]any
	for _, g := range groups {
		gm := g.(map[string]any)
		for _, h := range gm["hooks"].([]any) {
			out = append(out, h.(map[string]any))
		}
	}
	return out
}

func ours(t *testing.T, settings map[string]any, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, h := range handlers(t, settings, event) {
		if isOurs(h) {
			out = append(out, h)
		}
	}
	return out
}

const unrelatedSettings = `{
  "model": "opus",
  "cleanupPeriodDays": 12345678901234567890,
  "permissions": {"allow": ["Bash(ls:*)"]},
  "hooks": {
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/guard.sh", "timeout": 5}]}],
    "PermissionRequest": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "notify-send edit"}]}],
    "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]
  }
}`

func TestInstallSettings(t *testing.T) {
	tests := []struct {
		name       string
		existing   *string // nil: no file
		wantBackup bool
		check      func(t *testing.T, s map[string]any, raw string)
	}{
		{name: "missing file", existing: nil, wantBackup: false},
		{name: "empty file", existing: ptr(""), wantBackup: true},
		{name: "whitespace file", existing: ptr("  \n"), wantBackup: true},
		{name: "empty object", existing: ptr("{}"), wantBackup: true},
		{
			name: "unrelated hooks and keys preserved", existing: ptr(unrelatedSettings), wantBackup: true,
			check: func(t *testing.T, s map[string]any, raw string) {
				if s["model"] != "opus" {
					t.Errorf("model lost: %v", s["model"])
				}
				if !strings.Contains(raw, "12345678901234567890") {
					t.Errorf("big number was not preserved exactly:\n%s", raw)
				}
				if got := handlers(t, s, "PreToolUse"); len(got) != 1 || got[0]["command"] != "/usr/local/bin/guard.sh" {
					t.Errorf("PreToolUse changed: %v", got)
				}
				pr := handlers(t, s, "PermissionRequest")
				if len(pr) != 2 || pr[0]["command"] != "notify-send edit" {
					t.Errorf("PermissionRequest: %v", pr)
				}
				if st := handlers(t, s, "Stop"); len(st) != 2 || st[0]["command"] != "say done" {
					t.Errorf("Stop: %v", st)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t)
			path := filepath.Join(env.Home, ".claude", "settings.json")
			if tt.existing != nil {
				writeFile(t, path, *tt.existing)
			}
			code, _, stderr := run(t, env, "install", adapterName, "--wait", "30s")
			if code != ExitOK {
				t.Fatalf("install exit %d: %s", code, stderr)
			}
			s := readJSON(t, path)
			raw, _ := os.ReadFile(path)
			for _, ev := range hookEvents {
				got := ours(t, s, ev.name)
				if len(got) != 1 {
					t.Fatalf("%s: want 1 portlight handler, got %v", ev.name, got)
				}
				if got[0]["command"] != testBinary+" agent hook claude-code" {
					t.Errorf("%s command = %v", ev.name, got[0]["command"])
				}
				want := "10"
				if ev.approval {
					want = "40"
				}
				if n := toString(got[0]["timeout"]); n != want {
					t.Errorf("%s timeout = %v, want %s", ev.name, n, want)
				}
			}
			bak, err := os.ReadFile(path + ".portlight-bak")
			if tt.wantBackup {
				if err != nil || string(bak) != *tt.existing {
					t.Errorf("backup = %q, %v; want the original", bak, err)
				}
			} else if err == nil {
				t.Errorf("unexpected backup")
			}
			inst := readJSON(t, filepath.Join(env.Home, ".portlight", "agents", "claude-code", "install.json"))
			if inst["binary"] != testBinary || toString(inst["wait_seconds"]) != "30" || toString(inst["v"]) != "1" {
				t.Errorf("install.json = %v", inst)
			}
			if tt.check != nil {
				tt.check(t, s, string(raw))
			}
		})
	}
}

func ptr(s string) *string { return &s }

func toString(v any) string { return fmt.Sprint(v) }

func TestReinstallIsIdempotent(t *testing.T) {
	env := testEnv(t)
	path := filepath.Join(env.Home, ".claude", "settings.json")
	writeFile(t, path, unrelatedSettings)
	for _, wait := range []string{"30s", "2m", "45s"} {
		if code, _, stderr := run(t, env, "install", adapterName, "--wait", wait); code != ExitOK {
			t.Fatalf("install %s: %s", wait, stderr)
		}
	}
	s := readJSON(t, path)
	for _, ev := range hookEvents {
		if got := ours(t, s, ev.name); len(got) != 1 {
			t.Fatalf("%s: %d portlight handlers after 3 installs", ev.name, len(got))
		}
	}
	if got := toString(ours(t, s, "PermissionRequest")[0]["timeout"]); got != "55" {
		t.Errorf("timeout = %s, want 55 (last --wait 45s + 10)", got)
	}
	if n := len(handlers(t, s, "PreToolUse")); n != 1 {
		t.Errorf("PreToolUse handlers = %d", n)
	}
}

func TestUninstallRemovesOnlyOurs(t *testing.T) {
	env := testEnv(t)
	path := filepath.Join(env.Home, ".claude", "settings.json")
	writeFile(t, path, unrelatedSettings)
	if code, _, stderr := run(t, env, "install", adapterName); code != ExitOK {
		t.Fatal(stderr)
	}
	if code, _, stderr := run(t, env, "uninstall", adapterName); code != ExitOK {
		t.Fatal(stderr)
	}
	s := readJSON(t, path)
	for _, ev := range hookEvents {
		if got := ours(t, s, ev.name); len(got) != 0 {
			t.Errorf("%s still has %v", ev.name, got)
		}
	}
	if got := handlers(t, s, "PreToolUse"); len(got) != 1 {
		t.Errorf("PreToolUse: %v", got)
	}
	if got := handlers(t, s, "PermissionRequest"); len(got) != 1 || got[0]["command"] != "notify-send edit" {
		t.Errorf("PermissionRequest: %v", got)
	}
	if got := handlers(t, s, "Stop"); len(got) != 1 {
		t.Errorf("Stop: %v", got)
	}
	hooks := s["hooks"].(map[string]any)
	if _, ok := hooks["Notification"]; ok {
		t.Errorf("empty Notification event left behind")
	}
	if _, err := os.Stat(filepath.Join(env.Home, ".portlight", "agents", "claude-code", "install.json")); err == nil {
		t.Errorf("install.json not removed")
	}

	// Second uninstall changes nothing.
	before, _ := os.ReadFile(path)
	if code, out, _ := run(t, env, "uninstall", adapterName); code != ExitOK || !strings.Contains(out, "No Portlight hook") {
		t.Errorf("second uninstall: %d %q", code, out)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Errorf("second uninstall rewrote settings")
	}
}

func TestUninstallDropsHooksKeyWhenOnlyOurs(t *testing.T) {
	env := testEnv(t)
	path := filepath.Join(env.Home, ".claude", "settings.json")
	writeFile(t, path, `{"model":"opus"}`)
	run(t, env, "install", adapterName)
	run(t, env, "uninstall", adapterName)
	s := readJSON(t, path)
	if _, ok := s["hooks"]; ok || s["model"] != "opus" {
		t.Errorf("settings after uninstall = %v", s)
	}
}

func TestInstallRefusesBadSettings(t *testing.T) {
	tests := map[string]string{
		"invalid JSON":      `{"model": "opus",`,
		"not an object":     `["a"]`,
		"trailing data":     `{} {}`,
		"hooks not object":  `{"hooks": []}`,
		"event not array":   `{"hooks": {"Stop": {"command": "x"}}}`,
		"comment (JSONC)":   "// mine\n{}",
		"single quote JSON": `{'a': 1}`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			env := testEnv(t)
			path := filepath.Join(env.Home, ".claude", "settings.json")
			writeFile(t, path, content)
			code, _, stderr := run(t, env, "install", adapterName)
			if code != ExitError {
				t.Fatalf("exit = %d, want %d (%s)", code, ExitError, stderr)
			}
			got, _ := os.ReadFile(path)
			if string(got) != content {
				t.Errorf("settings changed to %q", got)
			}
			if _, err := os.Stat(path + ".portlight-bak"); err == nil {
				t.Errorf("backup written for a refused install")
			}
			if _, err := os.Stat(filepath.Join(env.Home, ".portlight", "agents", "claude-code", "install.json")); err == nil {
				t.Errorf("install.json written for a refused install")
			}
		})
	}
}

func TestInstallHonoursClaudeConfigDir(t *testing.T) {
	env := testEnv(t)
	env.ClaudeConfigDir = filepath.Join(t.TempDir(), "claude-work")
	if code, _, stderr := run(t, env, "install", adapterName); code != ExitOK {
		t.Fatal(stderr)
	}
	s := readJSON(t, filepath.Join(env.ClaudeConfigDir, "settings.json"))
	if len(ours(t, s, "PermissionRequest")) != 1 {
		t.Errorf("hook not in CLAUDE_CONFIG_DIR settings")
	}
	if _, err := os.Stat(filepath.Join(env.Home, ".claude", "settings.json")); err == nil {
		t.Errorf("~/.claude/settings.json written despite CLAUDE_CONFIG_DIR")
	}
	// Install state still lives under the home directory.
	if _, err := os.Stat(filepath.Join(env.Home, ".portlight", "agents", "claude-code", "install.json")); err != nil {
		t.Errorf("install.json: %v", err)
	}
}

func TestInstallFlagValidation(t *testing.T) {
	env := testEnv(t)
	for _, args := range [][]string{
		{"install"},
		{"install", "hermes"},
		{"install", adapterName, "--wait", "1s"},
		{"install", adapterName, "--wait", "20m"},
		{"install", adapterName, "--wait", "soon"},
		{"install", adapterName, adapterName},
	} {
		if code, _, _ := run(t, env, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestHookCommandQuoting(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/usr/local/bin/portlight", "/usr/local/bin/portlight agent hook claude-code"},
		{"/home/a b/portlight", "'/home/a b/portlight' agent hook claude-code"},
		{"/home/o'neil/portlight", `'/home/o'\''neil/portlight' agent hook claude-code`},
		{"/x/$(rm -rf ~)/portlight", "'/x/$(rm -rf ~)/portlight' agent hook claude-code"},
	}
	for _, tt := range tests {
		if got := hookCommand(tt.in); got != tt.want {
			t.Errorf("hookCommand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
