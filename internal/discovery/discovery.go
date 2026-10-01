package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strings"

	"github.com/hashicorp/mdns"
)

// Service is the DNS-SD service type a pairing session is announced under.
const Service = "_portlight._tcp"

// maxAddrs caps the addresses put in the QR, which grows with each one.
const maxAddrs = 4

// Tag identifies a session in the mDNS announcement without revealing its
// id: the phone computes the same tag from the sid in the QR and picks the
// matching instance. 8 bytes of SHA-256, hex.
func Tag(sessionID []byte) string {
	sum := sha256.Sum256(append([]byte("portlight/pair/v1/mdns\x00"), sessionID...))
	return hex.EncodeToString(sum[:8])
}

// InstanceName is the DNS-SD instance for a session. It carries neither the
// machine's host name nor the user's.
func InstanceName(sessionID []byte) string {
	return "portlight-" + Tag(sessionID)
}

// Advertisement is a running mDNS announcement; Stop ends it.
type Advertisement struct {
	server *mdns.Server
}

// Stop withdraws the announcement.
func (a *Advertisement) Stop() {
	if a != nil && a.server != nil {
		_ = a.server.Shutdown()
	}
}

// Advertise announces the session on the local network so the phone can
// find the CLI when none of the QR's addresses is reachable (another NIC,
// a VPN in the way). The TXT record carries the protocol version and the
// session tag, nothing else.
func Advertise(sessionID []byte, port int, ips []net.IP) (*Advertisement, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no local addresses to advertise")
	}
	instance := InstanceName(sessionID)
	svc, err := mdns.NewMDNSService(
		instance, Service, "", instance+".local.", port, ips,
		[]string{"v=1", "tag=" + Tag(sessionID)},
	)
	if err != nil {
		return nil, fmt.Errorf("mdns service: %w", err)
	}
	server, err := mdns.NewServer(&mdns.Config{
		Zone:   svc,
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		return nil, fmt.Errorf("mdns server: %w", err)
	}
	return &Advertisement{server: server}, nil
}

// LocalAddrs lists the IPv4 addresses a phone on the same network could
// reach this machine on, preferred first: the one the default route uses,
// then other private addresses on interfaces that are up. Loopback,
// point-to-point (most VPN tunnels) and link-local addresses are left out.
func LocalAddrs() []net.IP {
	var addrs []net.IP
	if ip := routeAddr(); ip != nil {
		addrs = append(addrs, ip)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 ||
			isVirtual(iface.Name) {
			continue
		}
		ifAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifAddrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || !ip.IsPrivate() {
				continue
			}
			if !slices.ContainsFunc(addrs, ip.Equal) {
				addrs = append(addrs, ip)
			}
		}
	}
	if len(addrs) > maxAddrs {
		addrs = addrs[:maxAddrs]
	}
	return addrs
}

// virtualPrefixes name host-only adapters (WSL, Hyper-V, Docker, VMs) whose
// private addresses a phone can never reach.
var virtualPrefixes = []string{
	"vethernet", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet",
	"virtualbox", "utun", "tailscale", "zt", "wg",
}

func isVirtual(name string) bool {
	name = strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// routeAddr is the source address the OS would use for the default route.
// The UDP "dial" sends no packet.
func routeAddr() net.IP {
	conn, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1, never routed
	if err != nil {
		return nil
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	return ip
}
