//go:build windows

package enroll

import (
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/agent"
)

// openSSHAgentPipe is where Windows' OpenSSH agent service listens.
const openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// systemAgent connects to $SSH_AUTH_SOCK (a named pipe or an AF_UNIX
// socket), else to the OpenSSH agent service's pipe. No agent is not an
// error.
func systemAgent() (agent.Agent, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock != "" && !strings.HasPrefix(sock, `\\.\pipe\`) {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, nil, err
		}
		return agent.NewClient(conn), conn, nil
	}
	if sock == "" {
		sock = openSSHAgentPipe
	}
	// A named pipe opens like a file and reads/writes synchronously.
	pipe, err := os.OpenFile(sock, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil
	}
	return agent.NewClient(pipe), pipe, nil
}
