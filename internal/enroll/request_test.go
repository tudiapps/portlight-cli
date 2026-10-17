package enroll

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestValidateAcceptsAPlainKeyAndSaneHosts(t *testing.T) {
	pub := phoneKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " phone@portlight"
	req := Request{PublicKey: line, Hosts: []Host{{Alias: "prod 1", HostName: "10.0.0.1", User: "root", Port: 22}}}
	got, err := req.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if AuthorizedLine(got) != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))+" "+KeyComment {
		t.Fatalf("line = %q: the phone's comment must not reach the server", AuthorizedLine(got))
	}
}

func TestValidateRejects(t *testing.T) {
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(phoneKey(t))))
	host := Host{Alias: "a", HostName: "h", User: "u", Port: 22}
	many := make([]Host, MaxHosts+1)
	for i := range many {
		many[i] = Host{Alias: itoa(i), HostName: "h", User: "u", Port: 22}
	}
	for name, req := range map[string]Request{
		"options":          {PublicKey: `command="sh" ` + key, Hosts: []Host{host}},
		"two lines":        {PublicKey: key + "\n" + key, Hosts: []Host{host}},
		"garbage":          {PublicKey: "ssh-ed25519 notbase64", Hosts: []Host{host}},
		"no hosts":         {PublicKey: key},
		"too many hosts":   {PublicKey: key, Hosts: many},
		"port 0":           {PublicKey: key, Hosts: []Host{{Alias: "a", HostName: "h", User: "u"}}},
		"user with @":      {PublicKey: key, Hosts: []Host{{Alias: "a", HostName: "h", User: "u@x", Port: 22}}},
		"host with space":  {PublicKey: key, Hosts: []Host{{Alias: "a", HostName: "h x", User: "u", Port: 22}}},
		"option-like host": {PublicKey: key, Hosts: []Host{{Alias: "a", HostName: "-oProxyCommand=x", User: "u", Port: 22}}},
		"control in alias": {PublicKey: key, Hosts: []Host{{Alias: "a\x1b[2J", HostName: "h", User: "u", Port: 22}}},
		"duplicate alias":  {PublicKey: key, Hosts: []Host{host, host}},
	} {
		if _, err := req.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (Request{PublicKey: `restrict ` + key, Hosts: []Host{host}}).Validate(); !errors.Is(err, ErrKeyOptions) {
		t.Errorf("options: err = %v, want ErrKeyOptions", err)
	}
}
