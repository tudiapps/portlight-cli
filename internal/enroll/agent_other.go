//go:build !windows

package enroll

import (
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

// systemAgent connects to $SSH_AUTH_SOCK; no variable means no agent.
func systemAgent() (agent.Agent, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, err
	}
	return agent.NewClient(conn), conn, nil
}
