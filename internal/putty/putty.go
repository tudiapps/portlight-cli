package putty

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/tudiapps/portlight-cli/internal/sshconfig"
)

// Group is the group PuTTY sessions land in on the phone.
const Group = "putty"

// Values is one session's registry values: strings for REG_SZ,
// uint64 for REG_DWORD.
type Values map[string]any

func (v Values) str(name string) string {
	s, _ := v[name].(string)
	return strings.TrimSpace(s)
}

func (v Values) num(name string) (int, bool) {
	n, ok := v[name].(uint64)
	return int(n), ok
}

// Host turns the session stored under the registry key name into a host.
// ok is false for anything that is not a usable SSH session: PuTTY's
// "Default Settings", other protocols, sessions without a host name.
func Host(name string, v Values) (host sshconfig.HostConfig, ok bool) {
	alias, err := url.PathUnescape(name)
	if err != nil {
		alias = name
	}
	alias = strings.TrimSpace(alias)
	if alias == "" || alias == "Default Settings" {
		return sshconfig.HostConfig{}, false
	}
	if p := v.str("Protocol"); p != "" && p != "ssh" {
		return sshconfig.HostConfig{}, false
	}
	hostName := v.str("HostName")
	user := v.str("UserName")
	// PuTTY accepts "user@host" in the host name field.
	if at := strings.LastIndex(hostName, "@"); at >= 0 {
		if user == "" {
			user = hostName[:at]
		}
		hostName = hostName[at+1:]
	}
	if hostName == "" || strings.ContainsAny(hostName, " \t") {
		return sshconfig.HostConfig{}, false
	}
	port, ok := v.num("PortNumber")
	if !ok || port <= 0 || port > 65535 {
		port = 22
	}
	return sshconfig.HostConfig{
		Alias:        alias,
		HostName:     hostName,
		User:         user,
		Port:         port,
		IdentityFile: v.str("PublicKeyFile"),
		Group:        Group,
	}, true
}

// Merge adds the PuTTY sessions to hosts from ~/.ssh/config. A session
// whose alias is already taken is left out with a warning: the ssh config
// is what the user maintains on purpose.
func Merge(hosts []sshconfig.HostConfig, sessions map[string]Values) ([]sshconfig.HostConfig, []string) {
	taken := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		taken[h.Alias] = true
	}
	names := make([]string, 0, len(sessions))
	for name := range sessions {
		names = append(names, name)
	}
	sort.Strings(names)

	var warnings []string
	for _, name := range names {
		h, ok := Host(name, sessions[name])
		if !ok {
			continue
		}
		if taken[h.Alias] {
			warnings = append(warnings, fmt.Sprintf("PuTTY session %q skipped: ~/.ssh/config already has a host with that name", h.Alias))
			continue
		}
		taken[h.Alias] = true
		hosts = append(hosts, h)
	}
	return hosts, warnings
}
