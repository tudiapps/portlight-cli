package sshconfig

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
)

// HostConfig represents a parsed host entry from SSH configuration.
type HostConfig struct {
	Alias    string `json:"alias"`
	HostName string `json:"host_name"`
	User     string `json:"user"`
	Port     int    `json:"port"`
	// IdentityFile is the desktop path; it stays on the desktop. Key names
	// the entry in the payload's key list instead.
	IdentityFile string   `json:"-"`
	Key          string   `json:"key,omitempty"`
	ProxyJump    string   `json:"proxy_jump,omitempty"`
	Group        string   `json:"group,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

// DefaultConfigPath returns ~/.ssh/config for the current user.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "config")
}

// DefaultSshDir returns ~/.ssh for the current user.
func DefaultSshDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh")
}

// ParseConfigFile parses the SSH config at path (default ~/.ssh/config).
//
// Include directives are expanded in place, as OpenSSH does, so hosts from
// included files are found and first-match order is kept. Match blocks the
// parser cannot evaluate (exec, user, ...) are skipped rather than failing
// the whole file; each skip is reported in warnings. A missing file is not
// an error: it yields an empty list.
func ParseConfigFile(path string) (hosts []HostConfig, warnings []string, err error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return []HostConfig{}, nil, nil
	}

	var text strings.Builder
	if err := inline(path, 0, &text, &warnings); err != nil {
		return nil, warnings, err
	}

	cfg, err := ssh_config.Decode(strings.NewReader(text.String()))
	if err != nil {
		return nil, warnings, fmt.Errorf("failed to decode ssh config: %w", err)
	}

	hosts, err = ExtractHosts(cfg)
	return hosts, warnings, err
}

// OpenSSH allows 16 levels of Include; deeper is almost surely a loop.
const maxIncludeDepth = 16

// inline appends the config at path to out with every Include replaced by
// the files it names, and every unsupported Match block neutralised.
func inline(path string, depth int, out *strings.Builder, warnings *[]string) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("ssh config: Include nested deeper than %d levels at %s", maxIncludeDepth, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to open ssh config: %w", err)
	}

	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		keyword, args := directive(line)
		switch keyword {
		case "include":
			for _, pattern := range args {
				matches, err := filepath.Glob(includePath(pattern))
				if err != nil {
					return fmt.Errorf("ssh config: bad Include pattern %q: %w", pattern, err)
				}
				for _, m := range matches {
					if err := inline(m, depth+1, out, warnings); err != nil {
						return err
					}
				}
			}
			continue
		case "match":
			if !supportedMatch(args) {
				*warnings = append(*warnings, fmt.Sprintf(
					"%s:%d: skipped \"Match %s\" (only \"Match all\" and \"Match host\" are understood)",
					path, i+1, strings.Join(args, " ")))
				// A block that matches no host, so its settings are dropped.
				out.WriteString("Host !*\n")
				continue
			}
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	return nil
}

// directive splits a config line into its lower-cased keyword and arguments.
// Blank lines and comments yield an empty keyword.
func directive(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	// "Keyword=value" is as valid as "Keyword value".
	if i := strings.IndexAny(line, " \t="); i > 0 {
		rest := strings.TrimLeft(line[i:], " \t=")
		return strings.ToLower(line[:i]), strings.Fields(rest)
	}
	return strings.ToLower(line), nil
}

// includePath resolves an Include argument the way OpenSSH does for a user
// config: absolute, ~-relative, or relative to ~/.ssh.
func includePath(p string) string {
	switch {
	case filepath.IsAbs(p):
		return p
	case strings.HasPrefix(p, "~/"):
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	default:
		return filepath.Join(DefaultSshDir(), p)
	}
}

// matchCriteria are the Match keywords other than host/all; any of them in
// a Match line means the block depends on something the parser cannot know.
var matchCriteria = map[string]bool{
	"canonical": true, "final": true, "exec": true, "localnetwork": true,
	"originalhost": true, "tagged": true, "command": true, "user": true,
	"localuser": true, "version": true, "sessiontype": true, "all": true,
	"host": true,
}

func supportedMatch(args []string) bool {
	if len(args) == 1 && strings.EqualFold(args[0], "all") {
		return true
	}
	if len(args) < 2 || !strings.EqualFold(args[0], "host") {
		return false
	}
	for _, a := range args[1:] {
		if matchCriteria[strings.ToLower(a)] {
			return false
		}
	}
	return true
}

// currentUser is what OpenSSH uses when a host sets no User. A variable so
// tests can pin it.
var currentUser = func() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	// Windows reports DOMAIN\name; ssh sends just the name.
	name := u.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// ExtractHosts extracts distinct HostConfig entries from a decoded Config.
//
// Only literal aliases become hosts: wildcard and negated patterns only
// supply defaults to them. The first block naming an alias fixes its place.
func ExtractHosts(cfg *ssh_config.Config) ([]HostConfig, error) {
	results := []HostConfig{}
	seen := map[string]bool{}

	for _, host := range cfg.Hosts {
		for _, pattern := range host.Patterns {
			alias := pattern.String()
			if alias == "" || strings.ContainsAny(alias, "*?!") || seen[alias] {
				continue
			}
			seen[alias] = true

			hostname, _ := cfg.Get(alias, "HostName")
			if hostname == "" {
				hostname = alias
			}
			hostname = expandTokens(hostname, alias)

			user, _ := cfg.Get(alias, "User")
			if user == "" {
				user = currentUser()
			}

			portStr, _ := cfg.Get(alias, "Port")
			port := 22
			if portStr != "" {
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
					port = p
				}
			}

			identityFile, _ := cfg.Get(alias, "IdentityFile")
			proxyJump, _ := cfg.Get(alias, "ProxyJump")
			if strings.EqualFold(proxyJump, "none") {
				proxyJump = ""
			}

			group := "servers"
			if strings.HasPrefix(alias, "prod") {
				group = "prod"
			} else if strings.HasPrefix(alias, "stage") || strings.HasPrefix(alias, "staging") {
				group = "staging"
			} else if strings.Contains(alias, "home") || strings.Contains(alias, "lab") {
				group = "home-lab"
			}

			results = append(results, HostConfig{
				Alias:        alias,
				HostName:     hostname,
				User:         user,
				Port:         port,
				IdentityFile: identityFile,
				ProxyJump:    proxyJump,
				Group:        group,
				Tags:         []string{},
			})
		}
	}

	return results, nil
}

// expandTokens resolves the HostName tokens that depend only on the alias:
// %h (the alias) and %% (a literal percent).
func expandTokens(value, alias string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+1 < len(value) {
			switch value[i+1] {
			case 'h':
				b.WriteString(alias)
				i++
				continue
			case '%':
				b.WriteByte('%')
				i++
				continue
			}
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

// ReadKnownHosts reads known host entries from ~/.ssh/known_hosts.
func ReadKnownHosts(path string) ([]string, error) {
	if path == "" {
		path = filepath.Join(DefaultSshDir(), "known_hosts")
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
