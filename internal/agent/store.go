package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxSummary   = 200      // runes
	maxInput     = 16 << 10 // bytes of tool input kept in the pending file
	maxEvents    = 1000     // lines kept in events.jsonl
	maxReason    = 500      // runes of a decision reason
	minEventLine = 64       // no event line is shorter; lets us skip counting
	maxEventsLog = 16 << 20 // hard read limit for events.jsonl
	defaultWait  = 120      // seconds
	minWait      = 5        // seconds, --wait lower bound
	maxWait      = 590      // seconds; hook timeout = wait+10 stays within 600
	hookSlack    = 10       // seconds added to wait for Claude Code's timeout
	shortTimeout = 10       // seconds, Notification/Stop hooks
)

// Event types in events.jsonl.
const (
	evRequest      = "request"
	evAllow        = "allow"
	evDeny         = "deny"
	evExpired      = "expired"
	evNotification = "notification"
	evStop         = "stop"
)

// Pending is pending/<id>.json.
type Pending struct {
	V              int             `json:"v"`
	ID             string          `json:"id"`
	Agent          string          `json:"agent"`
	CreatedAt      int64           `json:"created_at"`
	ExpiresAt      int64           `json:"expires_at"`
	SessionID      string          `json:"session_id"`
	Cwd            string          `json:"cwd"`
	Tool           string          `json:"tool"`
	Summary        string          `json:"summary"`
	Input          json.RawMessage `json:"input"`
	InputTruncated bool            `json:"input_truncated,omitempty"`
}

// Decision is decisions/<id>.json.
type Decision struct {
	V         int    `json:"v"`
	ID        string `json:"id"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	DecidedAt int64  `json:"decided_at"`
}

// Event is one line of events.jsonl. Every field is always present; id is
// empty for notification and stop events.
type Event struct {
	V         int    `json:"v"`
	TS        int64  `json:"ts"`
	Type      string `json:"type"`
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Summary   string `json:"summary"`
}

// Install is install.json.
type Install struct {
	V           int    `json:"v"`
	Binary      string `json:"binary"`
	Version     string `json:"version"`
	WaitSeconds int    `json:"wait_seconds"`
	InstalledAt int64  `json:"installed_at"`
}

// oneLine collapses whitespace and control characters into single spaces
// and cuts the result to max runes, ending in "…" when cut.
func oneLine(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsSpace(r) || unicode.IsControl(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if utf8.RuneCountInString(out) <= max {
		return out
	}
	r := []rune(out)
	return string(r[:max-1]) + "…"
}

// summarize is the one-line, ≤200 character description of a tool call:
// the command for Bash, the path for file tools, otherwise the most telling
// field, falling back to the compact input.
func summarize(tool string, input json.RawMessage) string {
	var fields map[string]any
	_ = json.Unmarshal(input, &fields)
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := fields[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	var s string
	switch tool {
	case "Bash", "PowerShell":
		s = str("command")
	case "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "NotebookRead":
		s = str("file_path", "notebook_path", "path")
	case "WebFetch":
		s = str("url")
	case "WebSearch":
		s = str("query")
	case "Glob", "Grep":
		s = str("pattern")
	default:
		s = str("command", "file_path", "path", "url", "query", "pattern", "description", "prompt")
	}
	if s == "" {
		var buf bytes.Buffer
		if json.Compact(&buf, input) == nil && buf.Len() > 0 && buf.String() != "null" {
			s = tool + " " + buf.String()
		} else {
			s = tool
		}
	}
	return oneLine(s, maxSummary)
}

// capInput returns the tool input as a JSON object of at most maxInput
// bytes. Oversized input has its strings shortened step by step; if that is
// still not enough the raw text is kept as one shortened string.
func capInput(raw json.RawMessage) (json.RawMessage, bool) {
	var buf bytes.Buffer
	if len(raw) == 0 || json.Compact(&buf, raw) != nil || buf.Len() == 0 || buf.Bytes()[0] != '{' {
		if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
			return json.RawMessage(`{}`), false
		}
		return wrapRaw(raw), true
	}
	if buf.Len() <= maxInput {
		return json.RawMessage(buf.Bytes()), false
	}
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return wrapRaw(raw), true
	}
	for _, limit := range []int{4096, 1024, 256, 64} {
		out, err := json.Marshal(shrink(v, limit))
		if err == nil && len(out) <= maxInput {
			return out, true
		}
	}
	return wrapRaw(raw), true
}

func wrapRaw(raw json.RawMessage) json.RawMessage {
	s := string(raw)
	if len(s) > maxInput/4 {
		s = s[:maxInput/4]
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
		s += "…"
	}
	out, _ := json.Marshal(map[string]string{"_raw": s})
	return out
}

func shrink(v any, limit int) any {
	switch t := v.(type) {
	case string:
		if utf8.RuneCountInString(t) > limit {
			return string([]rune(t)[:limit]) + "…"
		}
		return t
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = shrink(e, limit)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = shrink(e, limit)
		}
		return out
	default:
		return v
	}
}

func marshalLine(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// appendEvent adds one line to events.jsonl and trims the log to the last
// maxEvents lines. A lock file serializes concurrent hooks; the trim is a
// temp file + rename, so a reader never sees a half-written log.
func (s spool) appendEvent(ev Event) error {
	ev.V = 1
	line, err := marshalLine(ev)
	if err != nil {
		return err
	}
	lock, err := openNoFollow(s.lockPath(), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		return err
	}
	defer func() { _ = unlockFile(lock) }()

	f, err := openNoFollow(s.eventsPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	fi, serr := f.Stat()
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if serr != nil || fi.Size() <= maxEvents*minEventLine {
		return nil
	}
	return s.trimEvents()
}

func (s spool) trimEvents() error {
	data, err := readRegular(s.eventsPath(), maxEventsLog)
	if err != nil {
		return err
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	if len(lines) <= maxEvents {
		return nil
	}
	kept := bytes.Join(lines[len(lines)-maxEvents:], nil)
	return writeAtomic(s.root(), filepath.Base(s.eventsPath()), kept)
}

// readEvents returns the last limit well-formed events, oldest first.
func (s spool) readEvents(limit int) ([]Event, error) {
	data, err := readRegular(s.eventsPath(), maxEventsLog)
	if errors.Is(err, os.ErrNotExist) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	events := []Event{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), maxSpoolFile)
	for sc.Scan() {
		var ev Event
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.V != 1 || ev.Type == "" {
			continue
		}
		events = append(events, ev)
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

func (s spool) readPending(id string) (Pending, error) {
	path, err := s.pendingPath(id)
	if err != nil {
		return Pending{}, err
	}
	data, err := readRegular(path, maxSpoolFile)
	if err != nil {
		return Pending{}, err
	}
	var p Pending
	if err := json.Unmarshal(data, &p); err != nil {
		return Pending{}, err
	}
	if p.V != 1 || p.ID != id {
		return Pending{}, fmt.Errorf("pending %s is malformed", id)
	}
	return p, nil
}

// listPending returns requests that are still awaiting a decision, oldest
// first. Corrupt, foreign or expired files are skipped.
func (s spool) listPending(now int64) ([]Pending, error) {
	entries, err := os.ReadDir(s.pendingDir())
	if errors.Is(err, os.ErrNotExist) {
		return []Pending{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Pending{}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !validID(id) {
			continue
		}
		p, err := s.readPending(id)
		if err != nil || p.ExpiresAt < now {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// readDecision returns the decision for id. os.ErrNotExist means none yet;
// any other error means the file is there but unusable.
func (s spool) readDecision(id string) (Decision, error) {
	path, err := s.decisionPath(id)
	if err != nil {
		return Decision{}, err
	}
	data, err := readRegular(path, maxSpoolFile)
	if err != nil {
		return Decision{}, err
	}
	var d Decision
	if err := json.Unmarshal(data, &d); err != nil {
		return Decision{}, err
	}
	if d.V != 1 || d.ID != id || (d.Decision != evAllow && d.Decision != evDeny) {
		return Decision{}, fmt.Errorf("decision %s is malformed", id)
	}
	return d, nil
}

func (s spool) readInstall() (Install, error) {
	data, err := readRegular(s.installPath(), maxSpoolFile)
	if err != nil {
		return Install{}, err
	}
	var in Install
	if err := json.Unmarshal(data, &in); err != nil {
		return Install{}, err
	}
	if in.V != 1 {
		return Install{}, errors.New("install.json has an unknown version")
	}
	return in, nil
}

// sweep removes files that a killed hook or a late decide left behind.
func (s spool) sweep(now int64) {
	for _, dir := range []string{s.pendingDir(), s.decisionsDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			// Anything older than the longest possible wait plus slack is dead.
			if now-info.ModTime().Unix() > maxWait+2*hookSlack+60 {
				removeQuiet(filepath.Join(dir, e.Name()))
			}
		}
	}
}
