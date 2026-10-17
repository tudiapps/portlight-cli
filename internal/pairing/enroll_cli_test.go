package pairing

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/tudiapps/portlight-cli/internal/enroll"
	"github.com/tudiapps/portlight-cli/internal/sshconfig"
	"golang.org/x/crypto/ssh/agent"
)

func desktopFor(t *testing.T, answer string) (*desktopEnroll, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	in := strings.NewReader(answer)
	d := &desktopEnroll{in: in, stdin: bufio.NewReader(in), out: out}
	d.dist = &enroll.Distributor{
		Hosts:          []sshconfig.HostConfig{{Alias: "prod", HostName: "10.0.0.1", Port: 22, User: "ubuntu"}},
		KnownHostsPath: t.TempDir() + "/known_hosts",
		Agent:          func() (agent.Agent, io.Closer, error) { return nil, nil, nil },
		Progress:       d.progress,
	}
	return d, out
}

func TestDesktopListsTheHostsAndWritesNothingWhenTheUserSaysNo(t *testing.T) {
	d, out := desktopFor(t, "n\n")
	_, pub := phonePublicKey(t)
	req := enroll.Request{Hosts: []enroll.Host{
		{Alias: "prod", HostName: "10.0.0.1", User: "root", Port: 22},
		{Alias: "stranger", HostName: "203.0.113.5", User: "root", Port: 22},
	}}

	results, approved := d.handle(context.Background(), req, pub)
	if approved || results != nil {
		t.Fatalf("handle = %v, %v; want declined", results, approved)
	}
	text := out.String()
	for _, want := range []string{"root@10.0.0.1:22", "stranger", "SHA256:"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
}

func TestDesktopDoesNotAskWhenNoHostIsKnown(t *testing.T) {
	d, out := desktopFor(t, "")
	_, pub := phonePublicKey(t)
	req := enroll.Request{Hosts: []enroll.Host{{Alias: "x", HostName: "203.0.113.5", User: "root", Port: 22}}}

	results, approved := d.handle(context.Background(), req, pub)
	if !approved || len(results) != 1 || results[0].Reason != enroll.ReasonNotKnown {
		t.Fatalf("handle = %+v, %v", results, approved)
	}
	if strings.Contains(out.String(), "[y/N]") || strings.Contains(out.String(), "[e/H]") {
		t.Fatal("asked although nothing can be done")
	}
}

func TestEnrollModeFromEnv(t *testing.T) {
	for value, want := range map[string]EnrollMode{"": EnrollOffer, "only": EnrollOnly, "1": EnrollOnly, "off": EnrollOff, "0": EnrollOff, "junk": EnrollOffer} {
		t.Setenv(EnrollEnv, value)
		if got := EnrollModeFromEnv(); got != want {
			t.Errorf("%s=%q → %v, want %v", EnrollEnv, value, got, want)
		}
	}
}
