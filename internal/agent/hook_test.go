package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const permissionEvent = `{
  "session_id": "abc123",
  "transcript_path": "/home/u/.claude/projects/x/t.jsonl",
  "cwd": "/srv/app",
  "permission_mode": "default",
  "hook_event_name": "PermissionRequest",
  "tool_name": "Bash",
  "tool_input": {"command": "npm ci && rm -rf ./build", "description": "Clean build"},
  "permission_suggestions": [{"type": "addRules", "rules": [{"toolName": "Bash", "ruleContent": "npm ci"}], "behavior": "allow", "destination": "localSettings"}]
}`

// waitForPending blocks until the hook has parked exactly one request.
func waitForPending(t *testing.T, sp spool) Pending {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		list, err := sp.listPending(time.Now().Unix())
		if err == nil && len(list) == 1 {
			return list[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("no pending request appeared")
	return Pending{}
}

func setWait(t *testing.T, sp spool, seconds int) {
	t.Helper()
	data, _ := json.Marshal(Install{V: 1, Binary: testBinary, Version: "test", WaitSeconds: seconds})
	if err := writeAtomic(sp.root(), "install.json", data); err != nil {
		t.Fatal(err)
	}
}

func eventTypes(t *testing.T, sp spool) []string {
	t.Helper()
	evs, err := sp.readEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		out = append(out, e.Type)
	}
	return out
}

func TestHookApproval(t *testing.T) {
	tests := []struct {
		name       string
		wait       int
		respond    func(t *testing.T, env Env, sp spool, p Pending)
		wantOut    string // "" means no decision (Claude Code asks)
		wantEvents []string
	}{
		{
			name: "allow",
			wait: 30,
			respond: func(t *testing.T, env Env, _ spool, p Pending) {
				if code, _, stderr := run(t, env, "decide", p.ID, "allow"); code != ExitOK {
					t.Errorf("decide: %s", stderr)
				}
			},
			wantOut:    `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`,
			wantEvents: []string{evRequest, evAllow},
		},
		{
			name: "deny with reason",
			wait: 30,
			respond: func(t *testing.T, env Env, _ spool, p Pending) {
				if code, _, stderr := run(t, env, "decide", p.ID, "deny", "--reason", "not on prod\nplease"); code != ExitOK {
					t.Errorf("decide: %s", stderr)
				}
			},
			wantOut:    `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"not on prod please"}}}`,
			wantEvents: []string{evRequest, evDeny},
		},
		{
			name: "deny default reason",
			wait: 30,
			respond: func(t *testing.T, env Env, _ spool, p Pending) {
				run(t, env, "decide", p.ID, "deny")
			},
			wantOut:    `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Reddedildi: Portlight"}}}`,
			wantEvents: []string{evRequest, evDeny},
		},
		{
			name:       "timeout asks",
			wait:       1,
			respond:    func(*testing.T, Env, spool, Pending) {},
			wantEvents: []string{evRequest, evExpired},
		},
		{
			name: "corrupt decision asks",
			wait: 30,
			respond: func(t *testing.T, _ Env, sp spool, p Pending) {
				if err := writeAtomic(sp.decisionsDir(), p.ID+".json", []byte(`{"v":1,"decision":`)); err != nil {
					t.Error(err)
				}
			},
			wantEvents: []string{evRequest, evExpired},
		},
		{
			name: "unknown decision value asks",
			wait: 30,
			respond: func(t *testing.T, _ Env, sp spool, p Pending) {
				data := `{"v":1,"id":"` + p.ID + `","decision":"always","reason":"","decided_at":1}`
				if err := writeAtomic(sp.decisionsDir(), p.ID+".json", []byte(data)); err != nil {
					t.Error(err)
				}
			},
			wantEvents: []string{evRequest, evExpired},
		},
		{
			name: "decision for another id asks",
			wait: 30,
			respond: func(t *testing.T, _ Env, sp spool, p Pending) {
				data := `{"v":1,"id":"` + hexID('0') + `","decision":"allow","reason":"","decided_at":1}`
				if err := writeAtomic(sp.decisionsDir(), p.ID+".json", []byte(data)); err != nil {
					t.Error(err)
				}
			},
			wantEvents: []string{evRequest, evExpired},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t)
			sp := mustSpool(t, env)
			setWait(t, sp, tt.wait)
			done := make(chan struct{})
			go func() {
				defer close(done)
				p := waitForPending(t, sp)
				if p.ID == "" {
					return
				}
				if p.Tool != "Bash" || p.Summary != "npm ci && rm -rf ./build" || p.Cwd != "/srv/app" ||
					p.SessionID != "abc123" || p.Agent != agentKind || p.ExpiresAt-p.CreatedAt != int64(tt.wait) {
					t.Errorf("pending = %+v", p)
				}
				tt.respond(t, env, sp, p)
			}()
			var out bytes.Buffer
			start := time.Now()
			code := runHook(context.Background(), env, strings.NewReader(permissionEvent), &out)
			<-done
			if code != 0 {
				t.Errorf("exit = %d", code)
			}
			if got := strings.TrimSpace(out.String()); got != tt.wantOut {
				t.Errorf("stdout = %q\nwant     %q", got, tt.wantOut)
			}
			if tt.wait > 1 && time.Since(start) > 5*time.Second {
				t.Errorf("hook took %v", time.Since(start))
			}
			if got := eventTypes(t, sp); strings.Join(got, ",") != strings.Join(tt.wantEvents, ",") {
				t.Errorf("events = %v, want %v", got, tt.wantEvents)
			}
			for _, dir := range []string{sp.pendingDir(), sp.decisionsDir()} {
				if entries, _ := os.ReadDir(dir); len(entries) != 0 {
					t.Errorf("%s not cleaned: %v", dir, entries)
				}
			}
		})
	}
}

func TestHookFallsBackWithoutDecision(t *testing.T) {
	tests := []struct {
		name  string
		home  func(t *testing.T) string
		stdin string
	}{
		{name: "missing HOME", home: func(*testing.T) string { return "" }, stdin: permissionEvent},
		{name: "relative HOME", home: func(*testing.T) string { return "relative/home" }, stdin: permissionEvent},
		{name: "invalid JSON", home: func(t *testing.T) string { return t.TempDir() }, stdin: `{"hook_event_name":`},
		{name: "empty stdin", home: func(t *testing.T) string { return t.TempDir() }, stdin: ``},
		{name: "unknown event", home: func(t *testing.T) string { return t.TempDir() }, stdin: `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`},
		{
			name: "spool is a file",
			home: func(t *testing.T) string {
				h := t.TempDir()
				writeFile(t, filepath.Join(h, ".portlight"), "x")
				return h
			},
			stdin: permissionEvent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t)
			env.Home = tt.home(t)
			var out bytes.Buffer
			done := make(chan int)
			go func() { done <- runHook(context.Background(), env, strings.NewReader(tt.stdin), &out) }()
			select {
			case code := <-done:
				if code != 0 || out.Len() != 0 {
					t.Errorf("exit %d stdout %q; want 0 and nothing", code, out.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("hook blocked")
			}
		})
	}
}

func TestHookCancelledAsks(t *testing.T) {
	env := testEnv(t)
	sp := mustSpool(t, env)
	setWait(t, sp, 60)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		waitForPending(t, sp)
		cancel()
	}()
	var out bytes.Buffer
	runHook(ctx, env, strings.NewReader(permissionEvent), &out)
	<-done
	if out.Len() != 0 {
		t.Errorf("stdout = %q", out.String())
	}
	if got := eventTypes(t, sp); strings.Join(got, ",") != "request,expired" {
		t.Errorf("events = %v", got)
	}
}

func TestHookNonApprovalEvents(t *testing.T) {
	tests := []struct {
		name, stdin, typ, summary string
	}{
		{
			name:    "notification",
			stdin:   `{"session_id":"s1","cwd":"/srv","hook_event_name":"Notification","message":"Claude needs your permission to use Bash","title":"Permission needed","notification_type":"permission_prompt"}`,
			typ:     evNotification,
			summary: "Claude needs your permission to use Bash",
		},
		{
			name:    "stop",
			stdin:   `{"session_id":"s1","hook_event_name":"Stop","stop_hook_active":false,"last_assistant_message":"  All tests pass.\nDetails follow…","background_tasks":[],"session_crons":[]}`,
			typ:     evStop,
			summary: "All tests pass.",
		},
		{
			name:    "session end",
			stdin:   `{"session_id":"s1","hook_event_name":"SessionEnd","reason":"logout"}`,
			typ:     evStop,
			summary: "session end: logout",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testEnv(t)
			var out bytes.Buffer
			start := time.Now()
			if code := runHook(context.Background(), env, strings.NewReader(tt.stdin), &out); code != 0 || out.Len() != 0 {
				t.Errorf("exit %d stdout %q", code, out.String())
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("non-approval hook took %v", d)
			}
			sp, _ := newSpool(env.Home)
			evs, _ := sp.readEvents(0)
			if len(evs) != 1 || evs[0].Type != tt.typ || evs[0].Summary != tt.summary || evs[0].SessionID != "s1" || evs[0].ID != "" {
				t.Errorf("events = %+v", evs)
			}
			if entries, _ := os.ReadDir(sp.pendingDir()); len(entries) != 0 {
				t.Errorf("pending written for %s", tt.name)
			}
		})
	}
}

func TestHookTruncatesLargeInput(t *testing.T) {
	env := testEnv(t)
	sp := mustSpool(t, env)
	setWait(t, sp, 30)
	big := strings.Repeat("A", 40<<10)
	in, _ := json.Marshal(map[string]any{
		"hook_event_name": "PermissionRequest", "session_id": "s", "cwd": "/w", "tool_name": "Write",
		"tool_input": map[string]any{"file_path": "/w/big.txt", "content": big},
	})
	var raw []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		p := waitForPending(t, sp)
		path, _ := sp.pendingPath(p.ID)
		raw, _ = os.ReadFile(path)
		run(t, env, "decide", p.ID, "deny")
	}()
	var out bytes.Buffer
	runHook(context.Background(), env, bytes.NewReader(in), &out)
	<-done
	var p Pending
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("pending: %v", err)
	}
	if !p.InputTruncated || len(p.Input) > maxInput || p.Summary != "/w/big.txt" {
		t.Errorf("truncated=%v len=%d summary=%q", p.InputTruncated, len(p.Input), p.Summary)
	}
	var fields map[string]string
	if err := json.Unmarshal(p.Input, &fields); err != nil || fields["file_path"] != "/w/big.txt" {
		t.Errorf("input not a usable object: %v %v", err, fields)
	}
}
