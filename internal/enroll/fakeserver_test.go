package enroll

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeServer is an in-process sshd that understands exactly the two
// commands enroll sends, keeps authorized_keys in memory, and can forward
// direct-tcpip channels so it also works as a jump host.
type fakeServer struct {
	t        *testing.T
	addr     string
	hostKey  ssh.Signer
	allowed  ssh.PublicKey // client key accepted for login
	mu       sync.Mutex
	files    map[string][]byte // authorized_keys per user; absent = no file
	commands []string
	failApp  bool // the append command exits 1
	logins   int
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startFakeServer(t *testing.T, allowed ssh.PublicKey) *fakeServer {
	t.Helper()
	s := &fakeServer{t: t, hostKey: newSigner(t), allowed: allowed, files: map[string][]byte{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s.addr = ln.Addr().String()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), s.allowed.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(s.hostKey)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, cfg)
		}
	}()
	return s
}

func (s *fakeServer) port() int {
	_, p, _ := net.SplitHostPort(s.addr)
	n, _ := strconv.Atoi(p)
	return n
}

// knownHostsLine is the server's entry, as ssh-keyscan would write it.
func (s *fakeServer) knownHostsLine() string {
	return "[127.0.0.1]:" + strconv.Itoa(s.port()) + " " + string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(s.hostKey.PublicKey())))
}

func (s *fakeServer) file(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.files[user])
}

func (s *fakeServer) setFile(user, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[user] = []byte(content)
}

func (s *fakeServer) seenCommands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func (s *fakeServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, reqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go s.session(sc.User(), ch, reqs)
		case "direct-tcpip":
			s.forward(nc)
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "no")
		}
	}
}

func (s *fakeServer) forward(nc ssh.NewChannel) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "bad request")
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { _, _ = io.Copy(ch, target); _ = ch.CloseWrite() }()
	go func() { _, _ = io.Copy(target, ch); _ = target.Close() }()
}

func (s *fakeServer) session(user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		s.mu.Lock()
		s.commands = append(s.commands, payload.Command)
		s.mu.Unlock()

		status := uint32(0)
		switch payload.Command {
		case readCommand:
			s.mu.Lock()
			content := s.files[user]
			s.mu.Unlock()
			_, _ = ch.Write(content)
		case appendCommand:
			data, _ := io.ReadAll(ch)
			s.mu.Lock()
			if s.failApp {
				status = 1
			} else {
				s.files[user] = append(s.files[user], data...)
			}
			s.mu.Unlock()
		default:
			status = 127
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], status)
		_, _ = ch.SendRequest("exit-status", false, b[:])
		return
	}
}
