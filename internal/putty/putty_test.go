package putty

import (
	"reflect"
	"testing"

	"github.com/tudiapps/portlight-cli/internal/sshconfig"
)

func TestHost(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		values Values
		want   sshconfig.HostConfig
		ok     bool
	}{
		{
			name: "plain session with key",
			key:  "web%201",
			values: Values{
				"HostName": "web-1.example.com", "UserName": "deploy",
				"PortNumber": uint64(2222), "Protocol": "ssh",
				"PublicKeyFile": `C:\keys\web.ppk`,
			},
			want: sshconfig.HostConfig{
				Alias: "web 1", HostName: "web-1.example.com", User: "deploy",
				Port: 2222, IdentityFile: `C:\keys\web.ppk`, Group: Group,
			},
			ok: true,
		},
		{
			name:   "user in the host name, default port",
			key:    "db",
			values: Values{"HostName": "root@10.0.0.5", "Protocol": "ssh"},
			want: sshconfig.HostConfig{
				Alias: "db", HostName: "10.0.0.5", User: "root", Port: 22, Group: Group,
			},
			ok: true,
		},
		{
			name:   "an explicit user wins over user@host",
			key:    "db",
			values: Values{"HostName": "root@10.0.0.5", "UserName": "admin"},
			want: sshconfig.HostConfig{
				Alias: "db", HostName: "10.0.0.5", User: "admin", Port: 22, Group: Group,
			},
			ok: true,
		},
		{name: "default settings", key: "Default%20Settings", values: Values{"HostName": "x"}},
		{name: "telnet", key: "old", values: Values{"HostName": "x", "Protocol": "telnet"}},
		{name: "serial", key: "com1", values: Values{"HostName": "COM1", "Protocol": "serial"}},
		{name: "no host", key: "empty", values: Values{"Protocol": "ssh"}},
		{name: "bad port falls back", key: "p", values: Values{"HostName": "h", "PortNumber": uint64(70000)},
			want: sshconfig.HostConfig{Alias: "p", HostName: "h", Port: 22, Group: Group}, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Host(tt.key, tt.values)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMergeKeepsSSHConfigHosts(t *testing.T) {
	hosts := []sshconfig.HostConfig{{Alias: "web", HostName: "a", Port: 22}}
	merged, warnings := Merge(hosts, map[string]Values{
		"web":   {"HostName": "b"},
		"db":    {"HostName": "c"},
		"alpha": {"HostName": "d"},
	})
	var aliases []string
	for _, h := range merged {
		aliases = append(aliases, h.Alias)
	}
	if want := []string{"web", "alpha", "db"}; !reflect.DeepEqual(aliases, want) {
		t.Fatalf("aliases = %v, want %v", aliases, want)
	}
	if merged[0].HostName != "a" {
		t.Fatalf("ssh config host was replaced: %+v", merged[0])
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one", warnings)
	}
}
