package agent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

// Exit codes of the agent commands.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitNotFound = 3 // decide: no such pending request, expired, or already decided
)

const (
	defaultAllowReason = "Onaylandı: Portlight"
	defaultDenyReason  = "Reddedildi: Portlight"
	defaultEventLimit  = 100
)

// phoneBinary is what the phone accepts as install.json "binary".
var phoneBinary = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+$`)

// Env is everything the commands take from the process, so tests can run
// them without touching the real home directory.
type Env struct {
	Home            string // "" when unknown
	ClaudeConfigDir string
	Version         string
	Executable      func() (string, error)
	Now             func() time.Time
	Poll            time.Duration // decision polling interval, default 500 ms
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e Env) poll() time.Duration {
	if e.Poll > 0 {
		return e.Poll
	}
	return 500 * time.Millisecond
}

// OSEnv builds an Env from the running process.
func OSEnv(version string) Env {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		home = ""
	}
	return Env{
		Home:            home,
		ClaudeConfigDir: os.Getenv("CLAUDE_CONFIG_DIR"),
		Version:         version,
		Executable: func() (string, error) {
			exe, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(exe)
		},
	}
}

// Main runs `portlight agent <args>` and returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	env := OSEnv(version)
	if len(args) >= 1 && args[0] == "hook" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if len(args) != 2 || args[1] != adapterName {
			return ExitOK // unknown adapter: no decision, never an error for Claude Code
		}
		return runHook(ctx, env, stdin, stdout)
	}
	return Run(env, args, stdout, stderr)
}

// Run dispatches every agent subcommand except the hook.
func Run(env Env, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return ExitUsage
	}
	c := &cmd{env: env, stdout: stdout, stderr: stderr}
	switch args[0] {
	case "install":
		return c.install(args[1:])
	case "uninstall":
		return c.uninstall(args[1:])
	case "status":
		return c.status(args[1:])
	case "pending":
		return c.pending(args[1:])
	case "decide":
		return c.decide(args[1:])
	case "events":
		return c.events(args[1:])
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return ExitOK
	default:
		return c.fail(ExitUsage, fmt.Errorf("unknown agent command %q", args[0]))
	}
}

const usageText = `Usage:
  portlight agent install claude-code [--wait 120s]
  portlight agent uninstall claude-code
  portlight agent hook claude-code          (run by Claude Code; reads the event on stdin)
  portlight agent status [--json]
  portlight agent pending [--json]
  portlight agent decide <id> allow|deny [--reason TEXT] [--json]
  portlight agent events [--json] [--limit N]
`

type cmd struct {
	env    Env
	stdout io.Writer
	stderr io.Writer
}

func (c *cmd) fail(code int, err error) int {
	fmt.Fprintln(c.stderr, "portlight agent:", err)
	return code
}

// parse accepts flags before, between and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func (c *cmd) spool() (spool, error) {
	return newSpool(c.env.Home)
}

func (c *cmd) writeJSON(v any) int {
	enc := json.NewEncoder(c.stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return c.fail(ExitError, err)
	}
	return ExitOK
}

func requireAdapter(pos []string) error {
	if len(pos) != 1 || pos[0] != adapterName {
		return fmt.Errorf("expected exactly one adapter: %s", adapterName)
	}
	return nil
}

func (c *cmd) install(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	wait := fs.Duration("wait", defaultWait*time.Second, "how long the hook waits for the phone")
	pos, err := parse(fs, args)
	if err != nil {
		return c.fail(ExitUsage, err)
	}
	if err := requireAdapter(pos); err != nil {
		return c.fail(ExitUsage, err)
	}
	waitSec := int(wait.Round(time.Second) / time.Second)
	if waitSec < minWait || waitSec > maxWait {
		return c.fail(ExitUsage, fmt.Errorf("--wait must be between %ds and %ds", minWait, maxWait))
	}
	if c.env.Executable == nil {
		return c.fail(ExitError, errors.New("cannot locate the portlight binary"))
	}
	binary, err := c.env.Executable()
	if err != nil || !filepath.IsAbs(binary) {
		return c.fail(ExitError, fmt.Errorf("cannot locate the portlight binary: %v", err))
	}
	sp, err := c.spool()
	if err != nil {
		return c.fail(ExitError, err)
	}
	path, err := settingsPath(c.env.Home, c.env.ClaudeConfigDir)
	if err != nil {
		return c.fail(ExitError, err)
	}
	sf, err := loadSettings(path)
	if err != nil {
		return c.fail(ExitError, err)
	}
	if err := sp.ensure(); err != nil {
		return c.fail(ExitError, err)
	}
	if err := sf.install(binary, waitSec); err != nil {
		return c.fail(ExitError, err)
	}
	if err := sf.save(); err != nil {
		return c.fail(ExitError, err)
	}
	inst := Install{V: 1, Binary: binary, Version: c.env.Version, WaitSeconds: waitSec, InstalledAt: c.env.now().Unix()}
	data, err := json.Marshal(inst)
	if err != nil {
		return c.fail(ExitError, err)
	}
	if err := writeAtomic(sp.root(), "install.json", append(data, '\n')); err != nil {
		return c.fail(ExitError, err)
	}
	fmt.Fprintf(c.stdout, "Claude Code hook installed in %s\n", sf.path)
	if sf.exists {
		fmt.Fprintf(c.stdout, "Previous settings saved to %s.portlight-bak\n", sf.path)
	}
	fmt.Fprintf(c.stdout, "Permission requests wait up to %ds for the phone, then Claude Code asks here as usual.\n", waitSec)
	if !phoneBinary.MatchString(binary) {
		fmt.Fprintf(c.stderr, "warning: the phone only accepts binary paths matching %s; %q does not, so the app will not find this install\n",
			phoneBinary.String(), binary)
	}
	return ExitOK
}

func (c *cmd) uninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return c.fail(ExitUsage, err)
	}
	if err := requireAdapter(pos); err != nil {
		return c.fail(ExitUsage, err)
	}
	path, err := settingsPath(c.env.Home, c.env.ClaudeConfigDir)
	if err != nil {
		return c.fail(ExitError, err)
	}
	sf, err := loadSettings(path)
	if err != nil {
		return c.fail(ExitError, err)
	}
	changed, err := sf.uninstall()
	if err != nil {
		return c.fail(ExitError, err)
	}
	if changed {
		if err := sf.save(); err != nil {
			return c.fail(ExitError, err)
		}
		fmt.Fprintf(c.stdout, "Claude Code hook removed from %s\n", sf.path)
	} else {
		fmt.Fprintf(c.stdout, "No Portlight hook in %s\n", sf.path)
	}
	if sp, err := c.spool(); err == nil {
		if ok, err := sp.exists(); err == nil && ok {
			removeQuiet(sp.installPath())
		}
	}
	return ExitOK
}

// StatusAdapter is one entry of `status --json`.
type StatusAdapter struct {
	Agent       string `json:"agent"`
	Name        string `json:"name"`
	Installed   bool   `json:"installed"`
	HookPresent bool   `json:"hook_present"`
	Binary      string `json:"binary"`
	Version     string `json:"version"`
	WaitSeconds int    `json:"wait_seconds"`
	InstalledAt int64  `json:"installed_at"`
	Pending     int    `json:"pending"`
}

// Status is the output of `status --json`.
type Status struct {
	V        int             `json:"v"`
	Version  string          `json:"version"`
	Adapters []StatusAdapter `json:"adapters"`
	Pending  int             `json:"pending"`
}

func (c *cmd) status(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return c.fail(ExitUsage, errors.New("usage: portlight agent status [--json]"))
	}
	sp, err := c.spool()
	if err != nil {
		return c.fail(ExitError, err)
	}
	a := StatusAdapter{Agent: agentKind, Name: adapterName}
	if ok, err := sp.exists(); err != nil {
		return c.fail(ExitError, err)
	} else if ok {
		if inst, err := sp.readInstall(); err == nil {
			a.Installed = true
			a.Binary, a.Version, a.WaitSeconds, a.InstalledAt = inst.Binary, inst.Version, inst.WaitSeconds, inst.InstalledAt
		}
		if list, err := sp.listPending(c.env.now().Unix()); err == nil {
			a.Pending = len(list)
		}
	}
	if path, err := settingsPath(c.env.Home, c.env.ClaudeConfigDir); err == nil {
		if sf, err := loadSettings(path); err == nil {
			a.HookPresent = sf.hasOurs()
		}
	}
	st := Status{V: 1, Version: c.env.Version, Adapters: []StatusAdapter{a}, Pending: a.Pending}
	if *asJSON {
		return c.writeJSON(st)
	}
	fmt.Fprintf(c.stdout, "portlight %s\n%s: installed=%t hook=%t pending=%d wait=%ds\n",
		st.Version, a.Name, a.Installed, a.HookPresent, a.Pending, a.WaitSeconds)
	return ExitOK
}

func (c *cmd) pending(args []string) int {
	fs := flag.NewFlagSet("pending", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return c.fail(ExitUsage, errors.New("usage: portlight agent pending [--json]"))
	}
	sp, err := c.spool()
	if err != nil {
		return c.fail(ExitError, err)
	}
	list := []Pending{}
	if ok, err := sp.exists(); err != nil {
		return c.fail(ExitError, err)
	} else if ok {
		if list, err = sp.listPending(c.env.now().Unix()); err != nil {
			return c.fail(ExitError, err)
		}
	}
	if *asJSON {
		return c.writeJSON(list)
	}
	if len(list) == 0 {
		fmt.Fprintln(c.stdout, "No pending requests.")
	}
	for _, p := range list {
		fmt.Fprintf(c.stdout, "%s  %-10s %s\n", p.ID, p.Tool, p.Summary)
	}
	return ExitOK
}

func (c *cmd) decide(args []string) int {
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	reason := fs.String("reason", "", "reason shown to Claude (deny) or logged (allow)")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 2 {
		return c.fail(ExitUsage, errors.New("usage: portlight agent decide <id> allow|deny [--reason TEXT]"))
	}
	id, decision := pos[0], pos[1]
	if !validID(id) {
		return c.fail(ExitUsage, errors.New("invalid id: expected 32 lowercase hex characters"))
	}
	if decision != evAllow && decision != evDeny {
		return c.fail(ExitUsage, errors.New("decision must be allow or deny"))
	}
	sp, err := c.spool()
	if err != nil {
		return c.fail(ExitError, err)
	}
	if ok, err := sp.exists(); err != nil {
		return c.fail(ExitError, err)
	} else if !ok {
		return c.fail(ExitNotFound, fmt.Errorf("no pending request %s", id))
	}
	now := c.env.now().Unix()
	p, err := sp.readPending(id)
	if err != nil {
		return c.fail(ExitNotFound, fmt.Errorf("no pending request %s", id))
	}
	if p.ExpiresAt < now {
		return c.fail(ExitNotFound, fmt.Errorf("request %s has expired", id))
	}
	r := oneLine(*reason, maxReason)
	if r == "" {
		r = defaultAllowReason
		if decision == evDeny {
			r = defaultDenyReason
		}
	}
	d := Decision{V: 1, ID: id, Decision: decision, Reason: r, DecidedAt: now}
	data, err := json.Marshal(d)
	if err != nil {
		return c.fail(ExitError, err)
	}
	if err := createAtomic(sp.decisionsDir(), id+".json", data); err != nil {
		if errors.Is(err, errExists) {
			return c.fail(ExitNotFound, fmt.Errorf("request %s is already decided", id))
		}
		return c.fail(ExitError, err)
	}
	if *asJSON {
		return c.writeJSON(d)
	}
	fmt.Fprintf(c.stdout, "%s: %s\n", id, decision)
	return ExitOK
}

func (c *cmd) events(args []string) int {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	limit := fs.Int("limit", defaultEventLimit, "number of most recent events (1-1000)")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return c.fail(ExitUsage, errors.New("usage: portlight agent events [--json] [--limit N]"))
	}
	if *limit < 1 || *limit > maxEvents {
		return c.fail(ExitUsage, fmt.Errorf("--limit must be between 1 and %d", maxEvents))
	}
	sp, err := c.spool()
	if err != nil {
		return c.fail(ExitError, err)
	}
	list := []Event{}
	if ok, err := sp.exists(); err != nil {
		return c.fail(ExitError, err)
	} else if ok {
		if list, err = sp.readEvents(*limit); err != nil {
			return c.fail(ExitError, err)
		}
	}
	if *asJSON {
		return c.writeJSON(list)
	}
	for _, e := range list {
		fmt.Fprintf(c.stdout, "%s  %-12s %s %s\n", time.Unix(e.TS, 0).Format(time.RFC3339), e.Type, e.ID, e.Summary)
	}
	return ExitOK
}
