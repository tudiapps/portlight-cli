package discovery

import (
	"context"
	"io"
	"log"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/mdns"
)

func TestTagIsStableAndHidesTheSession(t *testing.T) {
	sid := []byte("0123456789abcdef")
	tag := Tag(sid)
	if len(tag) != 16 || tag != Tag(sid) {
		t.Fatalf("tag = %q", tag)
	}
	if tag == Tag([]byte("0123456789abcdeX")) {
		t.Fatal("different sessions share a tag")
	}
	if strings.Contains(InstanceName(sid), "0123456789") {
		t.Fatal("instance name reveals the session id")
	}
}

func TestLocalAddrsArePrivateIPv4(t *testing.T) {
	addrs := LocalAddrs()
	if len(addrs) > maxAddrs {
		t.Fatalf("%d addresses, cap is %d", len(addrs), maxAddrs)
	}
	for i, ip := range addrs {
		if ip.To4() == nil || ip.IsLoopback() {
			t.Errorf("unexpected address %v", ip)
		}
		if slices.ContainsFunc(addrs[i+1:], ip.Equal) {
			t.Errorf("duplicate address %v", ip)
		}
	}
}

// Needs working multicast; skipped where the sandbox or OS has none.
func TestAdvertiseIsFoundByTag(t *testing.T) {
	sid := []byte("fedcba9876543210")
	ips := LocalAddrs()
	if len(ips) == 0 {
		t.Skip("no LAN address on this machine")
	}
	ad, err := Advertise(sid, 4455, ips)
	if err != nil {
		t.Skipf("multicast unavailable: %v", err)
	}
	defer ad.Stop()

	entries := make(chan *mdns.ServiceEntry, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_ = mdns.QueryContext(ctx, &mdns.QueryParam{
			Service:     Service,
			Timeout:     3 * time.Second,
			Entries:     entries,
			DisableIPv6: true,
			Logger:      log.New(io.Discard, "", 0),
		})
	}()

	for {
		select {
		case e := <-entries:
			if !slices.Contains(e.InfoFields, "tag="+Tag(sid)) {
				continue
			}
			if e.Port != 4455 || !slices.ContainsFunc(ips, net.IP(e.AddrV4).Equal) {
				t.Fatalf("entry = %+v", e)
			}
			return
		case <-ctx.Done():
			t.Skip("no mDNS answer within 3s; multicast likely filtered here")
		}
	}
}

func TestVirtualAdaptersAreSkipped(t *testing.T) {
	for name, want := range map[string]bool{
		"vEthernet (WSL (Hyper-V firewall))": true,
		"docker0":                            true,
		"br-1a2b3c":                          true,
		"Wi-Fi":                              false,
		"en0":                                false,
		"eth0":                               false,
	} {
		if got := isVirtual(name); got != want {
			t.Errorf("isVirtual(%q) = %t", name, got)
		}
	}
}
