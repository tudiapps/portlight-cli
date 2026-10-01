package agent

// Claude Code hook contract, as verified on 26 September 2026 against the
// current official documentation:
//
//   - https://code.claude.com/docs/en/hooks  (docs.claude.com/en/docs/claude-code/hooks
//     301-redirects here; raw markdown at https://code.claude.com/docs/en/hooks.md)
//   - https://code.claude.com/docs/en/env-vars  (CLAUDE_CONFIG_DIR)
//   - https://code.claude.com/docs/en/settings  (~/.claude/settings.json)
//
// Event. We use PermissionRequest, not PreToolUse. PermissionRequest "runs
// when Claude Code is about to ask you for permission to use a tool", only
// then — calls that allow rules or the permission mode already approve never
// reach it, so the phone is not asked about them. PreToolUse fires before
// every tool call regardless of permissions and would need its own copy of
// the permission rules. PermissionRequest does not fire in `-p` mode, nor in
// dontAsk / bypassPermissions modes, and in auto mode only when the
// classifier is uncertain. It is matched on tool name ("*" = all).
//
// Input (stdin, JSON): common fields session_id, transcript_path, cwd,
// permission_mode, hook_event_name, plus tool_name, tool_input and an
// optional permission_suggestions array. Unlike PreToolUse there is no
// tool_use_id.
//
// Output (stdout, exit 0):
//
//	{"hookSpecificOutput":{"hookEventName":"PermissionRequest",
//	  "decision":{"behavior":"allow"}}}
//	{"hookSpecificOutput":{"hookEventName":"PermissionRequest",
//	  "decision":{"behavior":"deny","message":"<reason shown to Claude>"}}}
//
// There is no "ask" behavior on this event: the documented way to leave the
// normal permission prompt in place is to return no decision — exit 0 with
// empty stdout. Exit code 2 is explicitly not honored for PermissionRequest,
// other non-zero codes are "non-blocking errors" that show a hook-error
// notice, and a hook killed at its timeout also renders no decision. So the
// "ask" of docs/agents-protocol.md is: print nothing, exit 0. (In sessions
// that cannot show a prompt, e.g. background subagents in -p, Claude Code
// denies when no hook decides.) Deny and ask rules are still evaluated after
// a hook's "allow".
//
// Notification: common fields plus message, optional title and
// notification_type (permission_prompt, idle_prompt, auth_success, …);
// cannot block, output ignored. Stop: common fields plus stop_hook_active,
// last_assistant_message, background_tasks, session_crons; exit 2 would keep
// Claude going, so we always exit 0 silently. SessionEnd (reason: clear,
// resume, logout, prompt_input_exit, other) has a 1.5 s default budget; we
// do not register it, but map it to a "stop" event if it is ever wired up.
//
// settings.json: {"hooks": {"<Event>": [{"matcher": "...", "hooks":
// [{"type": "command", "command": "...", "timeout": <seconds>}]}]}}.
// timeout is in seconds, default 600 for command hooks. Without "args" the
// command runs in a shell (sh -c on macOS/Linux, Git Bash or PowerShell on
// Windows). User settings live in ~/.claude/settings.json (on Windows
// %USERPROFILE%\.claude); CLAUDE_CONFIG_DIR replaces ~/.claude entirely.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// maxHookStdin bounds how much of the hook event we read. Anything larger is
// treated like any other failure: no decision.
const maxHookStdin = 32 << 20

// hookInput holds the fields we use from any of the registered events.
type hookInput struct {
	HookEventName        string          `json:"hook_event_name"`
	SessionID            string          `json:"session_id"`
	Cwd                  string          `json:"cwd"`
	ToolName             string          `json:"tool_name"`
	ToolInput            json.RawMessage `json:"tool_input"`
	Message              string          `json:"message"`
	Title                string          `json:"title"`
	NotificationType     string          `json:"notification_type"`
	LastAssistantMessage string          `json:"last_assistant_message"`
	Reason               string          `json:"reason"`
}

type permissionOutput struct {
	HookSpecificOutput struct {
		HookEventName string `json:"hookEventName"`
		Decision      struct {
			Behavior string `json:"behavior"`
			Message  string `json:"message,omitempty"`
		} `json:"decision"`
	} `json:"hookSpecificOutput"`
}

// runHook is `portlight agent hook claude-code`. It always returns exit
// code 0: Claude Code must never see the hook crash, and "no decision"
// (empty stdout) is the fallback for every failure.
func runHook(ctx context.Context, env Env, stdin io.Reader, stdout io.Writer) (code int) {
	defer func() {
		if recover() != nil {
			code = 0
		}
	}()
	data, err := io.ReadAll(io.LimitReader(stdin, maxHookStdin+1))
	if err != nil || len(data) > maxHookStdin {
		return 0
	}
	var in hookInput
	if err := json.Unmarshal(data, &in); err != nil {
		return 0
	}
	sp, err := newSpool(env.Home)
	if err != nil {
		return 0
	}
	switch in.HookEventName {
	case "PermissionRequest":
		if out := approve(ctx, env, sp, in); out != nil {
			_ = json.NewEncoder(stdout).Encode(out)
		}
	case "Notification":
		msg := in.Message
		if msg == "" {
			msg = in.Title
		}
		logEvent(env, sp, Event{Type: evNotification, SessionID: in.SessionID, Summary: oneLine(msg, maxSummary)})
	case "Stop":
		logEvent(env, sp, Event{Type: evStop, SessionID: in.SessionID, Summary: oneLine(firstLine(in.LastAssistantMessage), maxSummary)})
	case "SessionEnd":
		logEvent(env, sp, Event{Type: evStop, SessionID: in.SessionID, Summary: oneLine("session end: "+in.Reason, maxSummary)})
	}
	return 0
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func logEvent(env Env, sp spool, ev Event) {
	if sp.ensure() != nil {
		return
	}
	ev.TS = env.now().Unix()
	_ = sp.appendEvent(ev)
}

// approve parks the request for the phone and waits for its decision. A nil
// result means "no decision": Claude Code shows its own prompt.
func approve(ctx context.Context, env Env, sp spool, in hookInput) *permissionOutput {
	if err := sp.ensure(); err != nil {
		return nil
	}
	now := env.now()
	sp.sweep(now.Unix())

	wait := defaultWait
	if inst, err := sp.readInstall(); err == nil && inst.WaitSeconds > 0 {
		wait = min(max(inst.WaitSeconds, 1), maxWait)
	}
	id, err := newID()
	if err != nil {
		return nil
	}
	input, truncated := capInput(in.ToolInput)
	tool := oneLine(in.ToolName, 128)
	p := Pending{
		V: 1, ID: id, Agent: agentKind,
		CreatedAt: now.Unix(), ExpiresAt: now.Unix() + int64(wait),
		SessionID: in.SessionID, Cwd: in.Cwd, Tool: tool,
		Summary: summarize(tool, input),
		Input:   input, InputTruncated: truncated,
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	pendingPath, _ := sp.pendingPath(id)
	decisionPath, _ := sp.decisionPath(id)
	if err := writeAtomic(sp.pendingDir(), id+".json", data); err != nil {
		removeQuiet(pendingPath)
		return nil
	}
	defer func() {
		removeQuiet(pendingPath)
		removeQuiet(decisionPath)
	}()
	ev := Event{ID: id, SessionID: in.SessionID, Summary: p.Summary}
	logWith := func(typ string) {
		ev.Type, ev.TS = typ, env.now().Unix()
		_ = sp.appendEvent(ev)
	}
	logWith(evRequest)

	d, ok := waitDecision(ctx, env, sp, id, time.Duration(wait)*time.Second)
	if !ok {
		logWith(evExpired)
		return nil
	}
	out := &permissionOutput{}
	out.HookSpecificOutput.HookEventName = "PermissionRequest"
	out.HookSpecificOutput.Decision.Behavior = d.Decision
	if d.Decision == evDeny {
		reason := oneLine(d.Reason, maxReason)
		if reason == "" {
			reason = defaultDenyReason
		}
		out.HookSpecificOutput.Decision.Message = reason
	}
	logWith(d.Decision)
	return out
}

// waitDecision polls decisions/<id>.json until a valid decision arrives, the
// wait runs out, the context ends, or the file turns out to be unreadable.
func waitDecision(ctx context.Context, env Env, sp spool, id string, wait time.Duration) (Decision, bool) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(env.poll())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return Decision{}, false
		case <-timer.C:
			return Decision{}, false
		case <-ticker.C:
			d, err := sp.readDecision(id)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return Decision{}, false
			}
			return d, true
		}
	}
}
