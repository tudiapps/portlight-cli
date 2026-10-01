//go:build !windows

package putty

// Sessions returns nothing: PuTTY keeps its sessions in the registry only
// on Windows.
func Sessions() (map[string]Values, error) { return nil, nil }
