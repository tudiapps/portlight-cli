package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHome points ~ at a temp dir with an empty .ssh and pins the local
// user name, so Include resolution and User defaults are deterministic.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	prev := currentUser
	currentUser = func() string { return "localuser" }
	t.Cleanup(func() { currentUser = prev })
	return home
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

func parse(t *testing.T, path string) ([]HostConfig, []string) {
	t.Helper()
	hosts, warnings, err := ParseConfigFile(path)
	if err != nil {
		t.Fatalf("ParseConfigFile: %v", err)
	}
	return hosts, warnings
}

func aliases(hosts []HostConfig) string {
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.Alias
	}
	return strings.Join(names, ",")
}

func byAlias(t *testing.T, hosts []HostConfig, alias string) HostConfig {
	t.Helper()
	for _, h := range hosts {
		if h.Alias == alias {
			return h
		}
	}
	t.Fatalf("no host %q in %s", alias, aliases(hosts))
	return HostConfig{}
}

func TestMissingFileYieldsNothing(t *testing.T) {
	fakeHome(t)
	hosts, warnings, err := ParseConfigFile(filepath.Join(t.TempDir(), "nope"))
	if err != nil || hosts == nil || len(hosts) != 0 || warnings != nil {
		t.Fatalf("got %v, %v, %v", hosts, warnings, err)
	}
}

func TestIncludeRelativeToSshDirInlinesHosts(t *testing.T) {
	home := fakeHome(t)
	ssh := filepath.Join(home, ".ssh")
	writeFile(t, filepath.Join(ssh, "config"), "Include conf.d/*.conf\n\nHost main\n    HostName main.example.com\n")
	writeFile(t, filepath.Join(ssh, "conf.d", "a.conf"), "Host alpha\n    HostName 10.0.0.1\n    User ops\n")
	writeFile(t, filepath.Join(ssh, "conf.d", "b.conf"), "Host beta\n    HostName 10.0.0.2\n")

	hosts, _ := parse(t, filepath.Join(ssh, "config"))

	if got := aliases(hosts); got != "alpha,beta,main" {
		t.Fatalf("aliases = %s", got)
	}
	if a := byAlias(t, hosts, "alpha"); a.HostName != "10.0.0.1" || a.User != "ops" {
		t.Errorf("alpha = %+v", a)
	}
}

func TestIncludeAbsoluteAndNested(t *testing.T) {
	fakeHome(t)
	dir := t.TempDir()
	inner := filepath.Join(dir, "inner.conf")
	middle := filepath.Join(dir, "middle.conf")
	writeFile(t, inner, "Host deep\n    Port 2200\n")
	writeFile(t, middle, "Include "+inner+"\n")
	writeFile(t, filepath.Join(dir, "config"), "Include "+middle+"\n")

	hosts, _ := parse(t, filepath.Join(dir, "config"))

	if d := byAlias(t, hosts, "deep"); d.Port != 2200 {
		t.Errorf("deep = %+v", d)
	}
}

func TestIncludeKeepsFirstMatchOrder(t *testing.T) {
	fakeHome(t)
	dir := t.TempDir()
	early := filepath.Join(dir, "early.conf")
	writeFile(t, early, "Host web\n    User from-include\n")
	writeFile(t, filepath.Join(dir, "config"), "Include "+early+"\nHost web\n    User from-main\n")

	hosts, _ := parse(t, filepath.Join(dir, "config"))

	if w := byAlias(t, hosts, "web"); w.User != "from-include" {
		t.Errorf("User = %q, want the first match", w.User)
	}
}

func TestIncludeLoopFails(t *testing.T) {
	fakeHome(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	writeFile(t, config, "Include "+config+"\nHost x\n")

	if _, _, err := ParseConfigFile(config); err == nil {
		t.Fatal("expected an error for a self-including config")
	}
}

func TestUnsupportedMatchIsSkippedWithWarning(t *testing.T) {
	fakeHome(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	writeFile(t, config, strings.Join([]string{
		"Host app",
		"    HostName app.internal",
		"Match exec \"test -f /tmp/x\"",
		"    User hijacked",
		"Match user root",
		"    Port 9999",
		"Host db",
		"    HostName db.internal",
	}, "\n"))

	hosts, warnings := parse(t, config)

	if got := aliases(hosts); got != "app,db" {
		t.Fatalf("aliases = %s", got)
	}
	if a := byAlias(t, hosts, "app"); a.User != "localuser" || a.Port != 22 {
		t.Errorf("settings from skipped Match leaked: %+v", a)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], ":3:") {
		t.Errorf("warnings = %q", warnings)
	}
}

func TestMatchHostIsApplied(t *testing.T) {
	fakeHome(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	writeFile(t, config, "Host api\n    HostName api.internal\nMatch host api\n    User deploy\n")

	hosts, warnings := parse(t, config)

	if a := byAlias(t, hosts, "api"); a.User != "deploy" {
		t.Errorf("api = %+v", a)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %q", warnings)
	}
}

func TestDefaultsAndTokens(t *testing.T) {
	fakeHome(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	writeFile(t, config, strings.Join([]string{
		"Host box !skip",
		"    HostName %h.lan",
		"    ProxyJump none",
		"Host box",
		"    User second-block",
		"Host *",
		"    ProxyJump bastion",
	}, "\r\n"))

	hosts, _ := parse(t, config)

	if got := aliases(hosts); got != "box" {
		t.Fatalf("aliases = %s", got)
	}
	b := hosts[0]
	if b.HostName != "box.lan" {
		t.Errorf("HostName = %q", b.HostName)
	}
	if b.User != "second-block" {
		t.Errorf("User = %q, want the value from the later block", b.User)
	}
	if b.ProxyJump != "" {
		t.Errorf("ProxyJump = %q, want none", b.ProxyJump)
	}
}

func TestDirective(t *testing.T) {
	for _, tc := range []struct {
		line, keyword, args string
	}{
		{"  Include a b", "include", "a,b"},
		{"include=a", "include", "a"},
		{"Match\thost x", "match", "host,x"},
		{"# Include a", "", ""},
		{"", "", ""},
	} {
		keyword, args := directive(tc.line)
		if keyword != tc.keyword || strings.Join(args, ",") != tc.args {
			t.Errorf("directive(%q) = %q %q", tc.line, keyword, args)
		}
	}
}
