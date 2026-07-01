//go:build linux
// +build linux

package packet_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testEthPAll = unix.ETH_P_ALL

func newPacketTestLink(t *testing.T) packetTestLink {
	t.Helper()

	txName, rxName := linuxVethNames()
	if _, err := ipOutput("link", "add", txName, "type", "veth", "peer", "name", rxName); err != nil {
		t.Skipf("skipping, failed to create veth pair: %v", err)
	}

	t.Cleanup(func() {
		if _, err := ipOutput("link", "del", txName); err != nil {
			t.Logf("failed to delete %s: %v", txName, err)
		}
	})

	disableIPv6(t, txName)
	disableIPv6(t, rxName)

	if _, err := ipOutput("link", "set", txName, "up"); err != nil {
		t.Fatalf("failed to bring up %s: %v", txName, err)
	}
	if _, err := ipOutput("link", "set", rxName, "up"); err != nil {
		t.Fatalf("failed to bring up %s: %v", rxName, err)
	}

	tx := lookupPacketTestInterface(t, txName)
	rx := lookupPacketTestInterface(t, rxName)

	return packetTestLink{tx: tx, rx: rx}
}

func linuxVethNames() (string, string) {
	suffix := fmt.Sprintf("%010x", (uint64(time.Now().UnixNano())^uint64(os.Getpid()))&0xffffffffff)
	return "pkt" + suffix + "a", "pkt" + suffix + "b"
}

func disableIPv6(t *testing.T, name string) {
	t.Helper()

	path := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		if os.IsNotExist(err) {
			return
		}

		t.Fatalf("failed to disable IPv6 on %s: %v", name, err)
	}
}

func ipOutput(args ...string) (string, error) {
	out, err := exec.Command("ip", args...).CombinedOutput()
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
