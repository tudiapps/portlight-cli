package pairing

import (
	"os"
	"testing"

	"github.com/tudiapps/portlight-cli/internal/putty"
)

// TestMain keeps every test off this machine's real PuTTY sessions.
func TestMain(m *testing.M) {
	puttySessions = func() (map[string]putty.Values, error) { return nil, nil }
	os.Exit(m.Run())
}
