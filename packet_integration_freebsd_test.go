//go:build freebsd
// +build freebsd

package packet_test

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
)

const testEthPAll = 0x0003

func newPacketTestLink(t *testing.T) packetTestLink {
	t.Helper()

	name, err := ifconfigOutput("epair", "create")
	if err != nil {
		t.Skipf("skipping, failed to create epair: %v", err)
	}
	name = strings.TrimSpace(name)
	if !strings.HasSuffix(name, "a") {
		t.Fatalf("unexpected epair name: %q", name)
	}

	t.Cleanup(func() {
		if _, err := ifconfigOutput(name, "destroy"); err != nil {
			t.Logf("failed to destroy %s: %v", name, err)
		}
	})

	peer := strings.TrimSuffix(name, "a") + "b"
	disableIPv6(t, name)
	disableIPv6(t, peer)

	if _, err := ifconfigOutput(name, "up"); err != nil {
		t.Fatalf("failed to bring up %s: %v", name, err)
	}
	if _, err := ifconfigOutput(peer, "up"); err != nil {
		t.Fatalf("failed to bring up %s: %v", peer, err)
	}

	tx := lookupPacketTestInterface(t, name)
	rx := lookupPacketTestInterface(t, peer)

	return packetTestLink{tx: tx, rx: rx}
}

func disableIPv6(t *testing.T, name string) {
	t.Helper()

	if _, err := ifconfigOutput(name, "inet6", "ifdisabled"); err != nil {
		t.Fatalf("failed to disable IPv6 on %s: %v", name, err)
	}
}

func ifconfigOutput(args ...string) (string, error) {
	out, err := exec.Command("/sbin/ifconfig", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}

	return string(out), nil
}

func lookupPacketTestInterface(t *testing.T, name string) *net.Interface {
	t.Helper()

	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("failed to look up %s: %v", name, err)
	}
	if len(ifi.HardwareAddr) != 6 {
		t.Fatalf("%s has unexpected hardware address %s", ifi.Name, ifi.HardwareAddr)
	}

	return ifi
}
