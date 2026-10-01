package sshconfig

import (
	"strings"
	"testing"

	"github.com/kevinburke/ssh_config"
)

const sampleConfig = `
Host prod-1
    HostName 10.0.0.1
    User ubuntu
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host staging-api
    HostName staging.internal
    User deploy
    ProxyJump bastion

Host *
    ServerAliveInterval 60
`

func TestExtractHosts(t *testing.T) {
	cfg, err := ssh_config.Decode(strings.NewReader(sampleConfig))
	if err != nil {
		t.Fatalf("failed to decode sample config: %v", err)
	}

	hosts, err := ExtractHosts(cfg)
	if err != nil {
		t.Fatalf("unexpected error extracting hosts: %v", err)
	}

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts (ignoring wildcard), got %d", len(hosts))
	}

	h1 := hosts[0]
	if h1.Alias != "prod-1" || h1.HostName != "10.0.0.1" || h1.User != "ubuntu" || h1.Port != 2222 {
		t.Errorf("unexpected host 1 values: %+v", h1)
	}
	if h1.Group != "prod" {
		t.Errorf("expected group 'prod', got %q", h1.Group)
	}

	h2 := hosts[1]
	if h2.Alias != "staging-api" || h2.HostName != "staging.internal" || h2.ProxyJump != "bastion" {
		t.Errorf("unexpected host 2 values: %+v", h2)
	}
	if h2.Group != "staging" {
		t.Errorf("expected group 'staging', got %q", h2.Group)
	}
}
