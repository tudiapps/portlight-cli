//go:build windows

package putty

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

const sessionsKey = `Software\SimonTatham\PuTTY\Sessions`

// Sessions reads every saved session from the current user's registry.
// No PuTTY installed is not an error: the result is empty.
func Sessions() (map[string]Values, error) {
	root, err := registry.OpenKey(registry.CURRENT_USER, sessionsKey, registry.READ)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Values, len(names))
	for _, name := range names {
		k, err := registry.OpenKey(root, name, registry.READ)
		if err != nil {
			continue
		}
		v := Values{}
		for _, field := range []string{"HostName", "UserName", "Protocol", "PublicKeyFile"} {
			if s, _, err := k.GetStringValue(field); err == nil {
				v[field] = s
			}
		}
		if n, _, err := k.GetIntegerValue("PortNumber"); err == nil {
			v["PortNumber"] = n
		}
		k.Close()
		out[name] = v
	}
	return out, nil
}
