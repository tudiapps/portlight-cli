package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// hookMarker identifies the handlers Portlight owns in settings.json.
const hookMarker = "agent hook " + adapterName

// hookEvents are the Claude Code events Portlight registers for, with the
// matcher it uses ("" means the key is omitted) and whether the handler is
// the long-waiting approval hook.
var hookEvents = []struct {
	name     string
	matcher  string
	approval bool
}{
	{name: "PermissionRequest", matcher: "*", approval: true},
	{name: "Notification"},
	{name: "Stop"},
}

// settingsPath is Claude Code's user settings file, honouring
// CLAUDE_CONFIG_DIR.
func settingsPath(home, configDir string) (string, error) {
	if configDir != "" {
		return filepath.Join(configDir, "settings.json"), nil
	}
	if home == "" {
		return "", errNotHome
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

var safeUnquoted = regexp.MustCompile(`^[A-Za-z0-9._/+:@%-]+$`)

// hookCommand is the shell-form command line Claude Code runs. A path made
// only of safe characters is left bare (valid in sh, Git Bash and
// PowerShell); anything else is single-quoted for sh.
func hookCommand(binary string) string {
	if runtime.GOOS == "windows" {
		binary = filepath.ToSlash(binary)
	}
	if !safeUnquoted.MatchString(binary) {
		binary = "'" + strings.ReplaceAll(binary, "'", `'\''`) + "'"
	}
	return binary + " " + hookMarker
}

// settingsFile is a parsed settings.json. Unknown keys survive untouched
// (numbers stay json.Number); only key order is not preserved.
type settingsFile struct {
	path   string // the real file, symlinks resolved
	exists bool
	mode   os.FileMode
	raw    []byte
	root   map[string]any
}

func loadSettings(path string) (*settingsFile, error) {
	sf := &settingsFile{path: path, mode: fileMode, root: map[string]any{}}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		sf.path = real
	}
	fi, err := os.Stat(sf.path)
	if errors.Is(err, os.ErrNotExist) {
		return sf, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	sf.exists, sf.mode = true, fi.Mode().Perm()
	sf.raw, err = os.ReadFile(sf.path)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(sf.raw)) == 0 {
		return sf, nil
	}
	dec := json.NewDecoder(bytes.NewReader(sf.raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON (%w); fix it first, nothing was changed", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s has trailing data after the JSON object; nothing was changed", path)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object; nothing was changed", path)
	}
	sf.root = obj
	if _, err := sf.hooks(false); err != nil {
		return nil, err
	}
	return sf, nil
}

// hooks returns the "hooks" object, creating it when create is set.
func (sf *settingsFile) hooks(create bool) (map[string]any, error) {
	h, ok := sf.root["hooks"]
	if !ok || h == nil {
		if !create {
			return nil, nil
		}
		m := map[string]any{}
		sf.root["hooks"] = m
		return m, nil
	}
	m, ok := h.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: \"hooks\" is not an object; nothing was changed", sf.path)
	}
	for event, groups := range m {
		if _, ok := groups.([]any); !ok && groups != nil {
			return nil, fmt.Errorf("%s: hooks.%s is not an array; nothing was changed", sf.path, event)
		}
	}
	return m, nil
}

func isOurs(handler any) bool {
	h, ok := handler.(map[string]any)
	if !ok {
		return false
	}
	cmd, _ := h["command"].(string)
	return h["type"] == "command" && strings.Contains(cmd, hookMarker)
}

// removeOurs strips Portlight handlers from every event. Groups left empty
// by that are dropped, and events left empty by that are dropped too.
func removeOurs(hooks map[string]any) bool {
	changed := false
	for event, g := range hooks {
		groups, _ := g.([]any)
		var kept []any
		touchedEvent := false
		for _, group := range groups {
			gm, ok := group.(map[string]any)
			if !ok {
				kept = append(kept, group)
				continue
			}
			handlers, ok := gm["hooks"].([]any)
			if !ok {
				kept = append(kept, group)
				continue
			}
			var keptH []any
			for _, h := range handlers {
				if isOurs(h) {
					changed, touchedEvent = true, true
					continue
				}
				keptH = append(keptH, h)
			}
			if len(keptH) == len(handlers) {
				kept = append(kept, group)
				continue
			}
			if len(keptH) == 0 {
				continue
			}
			gm["hooks"] = keptH
			kept = append(kept, gm)
		}
		if !touchedEvent {
			continue
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	return changed
}

// hasOurs reports whether settings already carry a Portlight handler.
func (sf *settingsFile) hasOurs() bool {
	hooks, err := sf.hooks(false)
	if err != nil || hooks == nil {
		return false
	}
	for _, g := range hooks {
		groups, _ := g.([]any)
		for _, group := range groups {
			gm, _ := group.(map[string]any)
			handlers, _ := gm["hooks"].([]any)
			for _, h := range handlers {
				if isOurs(h) {
					return true
				}
			}
		}
	}
	return false
}

// install replaces any Portlight handlers with fresh ones for binary.
func (sf *settingsFile) install(binary string, waitSeconds int) error {
	hooks, err := sf.hooks(true)
	if err != nil {
		return err
	}
	removeOurs(hooks)
	cmd := hookCommand(binary)
	for _, ev := range hookEvents {
		timeout := shortTimeout
		if ev.approval {
			timeout = waitSeconds + hookSlack
		}
		group := map[string]any{
			"hooks": []any{map[string]any{
				"type":    "command",
				"command": cmd,
				"timeout": timeout,
			}},
		}
		if ev.matcher != "" {
			group["matcher"] = ev.matcher
		}
		existing, _ := hooks[ev.name].([]any)
		hooks[ev.name] = append(existing, group)
	}
	return nil
}

// uninstall removes Portlight handlers; it reports whether anything changed.
func (sf *settingsFile) uninstall() (bool, error) {
	hooks, err := sf.hooks(false)
	if err != nil || hooks == nil {
		return false, err
	}
	if !removeOurs(hooks) {
		return false, nil
	}
	if len(hooks) == 0 {
		delete(sf.root, "hooks")
	}
	return true, nil
}

// save writes a backup of the previous contents, then the new settings,
// both atomically. The file keeps its mode; a new one gets 0600.
func (sf *settingsFile) save() error {
	dir := filepath.Dir(sf.path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	name := filepath.Base(sf.path)
	if sf.exists {
		if err := writeAtomic(dir, name+".portlight-bak", sf.raw); err != nil {
			return fmt.Errorf("writing backup: %w", err)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sf.root); err != nil {
		return err
	}
	out := buf.Bytes()
	if err := writeAtomic(dir, name, out); err != nil {
		return err
	}
	if sf.exists && sf.mode != fileMode {
		return setMode(sf.path, sf.mode)
	}
	return nil
}
