//go:build freebsd
// +build freebsd

package packet_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
)

const (
	freebsdEthPAll   = 0x0003
	ethernetHeader   = 14
	ethernetMinFrame = 60

	testEtherType   = 0x88b5
	testOtherType   = 0x88b6
	testMarker      = 0xa5
	testOtherMarker = 0x5a
)

func TestFreeBSD(t *testing.T) {
	t.Run("ProtocolFilter", testFreeBSDProtocolFilter)
	t.Run("UserFilter", testFreeBSDUserFilter)
	t.Run("StatsReset", testFreeBSDStatsReset)
}

func testFreeBSDProtocolFilter(t *testing.T) {
	pt := newPacketTest(t, testEtherType, nil)

	// The first frame would be delivered if the FreeBSD backend did not
	// compose the Conn protocol into the installed BPF program.
	pt.writeFrame(t, testOtherType, testMarker)
	pt.writeFrame(t, testEtherType, testMarker)

	got := pt.readFrame(t)
	if et := binary.BigEndian.Uint16(got[12:14]); et != testEtherType {
		t.Fatalf("unexpected EtherType: got %#04x, want %#04x", et, testEtherType)
	}
}

func testFreeBSDUserFilter(t *testing.T) {
	filter, err := payloadMarkerFilter(testMarker)
	if err != nil {
		t.Fatalf("failed to assemble marker filter: %v", err)
	}

	pt := newPacketTest(t, testEtherType, &packet.Config{
		Filter: filter,
	})

	// Both frames match the Conn protocol. Only the second matches the caller's
	// BPF filter.
	pt.writeFrame(t, testEtherType, testOtherMarker)
	pt.writeFrame(t, testEtherType, testMarker)

	got := pt.readFrame(t)
	if got[ethernetHeader] != testMarker {
		t.Fatalf("unexpected payload marker: got %#02x, want %#02x", got[ethernetHeader], testMarker)
	}
}

func testFreeBSDStatsReset(t *testing.T) {
	pt := newPacketTest(t, testEtherType, nil)

	pt.writeFrame(t, testEtherType, testMarker)
	_ = pt.readFrame(t)

	stats, err := pt.rx.Stats()
	if err != nil {
		t.Fatalf("failed to fetch stats: %v", err)
	}
	if stats.Packets == 0 {
		t.Fatal("stats indicated 0 received packets")
	}

	stats, err = pt.rx.Stats()
	if err != nil {
		t.Fatalf("failed to fetch stats again: %v", err)
	}
	if stats.Packets != 0 || stats.Drops != 0 {
		t.Fatalf("stats did not reset: packets=%d drops=%d", stats.Packets, stats.Drops)
	}
}

func TestFreeBSDDatagramUnsupported(t *testing.T) {
	_, err := packet.Listen(&net.Interface{}, packet.Datagram, freebsdEthPAll, nil)
	if err == nil {
		t.Fatal("expected an error, but none occurred")
	}
	if !strings.Contains(err.Error(), "Datagram is not supported on freebsd") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type epair struct {
	a *net.Interface
	b *net.Interface
}

type packetTest struct {
	epair epair
	rx    *packet.Conn
	tx    *packet.Conn
}

func newPacketTest(t *testing.T, protocol int, cfg *packet.Config) *packetTest {
	t.Helper()

	epair := newEpair(t)
	rx := listenPacket(t, epair.b, protocol, cfg)
	tx := listenPacket(t, epair.a, freebsdEthPAll, nil)

	return &packetTest{
		epair: epair,
		rx:    rx,
		tx:    tx,
	}
}

func listenPacket(t *testing.T, ifi *net.Interface, protocol int, cfg *packet.Config) *packet.Conn {
	t.Helper()

	c, err := packet.Listen(ifi, packet.Raw, protocol, cfg)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping, permission denied: %v", err)
		}

		t.Fatalf("failed to listen on %s: %v", ifi.Name, err)
	}
	t.Cleanup(func() { _ = c.Close() })

	return c
}

func (pt *packetTest) writeFrame(t *testing.T, etherType uint16, marker byte) {
	t.Helper()

	frame := ethernetFrame(pt.epair.b.HardwareAddr, pt.epair.a.HardwareAddr, etherType, marker)
	if _, err := pt.tx.WriteTo(frame, &packet.Addr{HardwareAddr: pt.epair.b.HardwareAddr}); err != nil {
		t.Fatalf("failed to write Ethernet frame: %v", err)
	}
}

func (pt *packetTest) readFrame(t *testing.T) []byte {
	t.Helper()

	if err := pt.rx.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}

	buf := make([]byte, ethernetMinFrame)
	n, _, err := pt.rx.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read Ethernet frame: %v", err)
	}

	got := buf[:n]
	if len(got) < ethernetHeader+1 {
		t.Fatalf("short frame: got %d bytes, want at least %d", len(got), ethernetHeader+1)
	}

	return got
}

func newEpair(t *testing.T) epair {
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
	if _, err := ifconfigOutput(name, "up"); err != nil {
		t.Fatalf("failed to bring up %s: %v", name, err)
	}
	if _, err := ifconfigOutput(peer, "up"); err != nil {
		t.Fatalf("failed to bring up %s: %v", peer, err)
	}

	a, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("failed to look up %s: %v", name, err)
	}
	b, err := net.InterfaceByName(peer)
	if err != nil {
		t.Fatalf("failed to look up %s: %v", peer, err)
	}
	if len(a.HardwareAddr) != 6 {
		t.Fatalf("%s has unexpected hardware address %s", a.Name, a.HardwareAddr)
	}
	if len(b.HardwareAddr) != 6 {
		t.Fatalf("%s has unexpected hardware address %s", b.Name, b.HardwareAddr)
	}

	return epair{a: a, b: b}
}

func ifconfigOutput(args ...string) (string, error) {
	out, err := exec.Command("/sbin/ifconfig", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}

	return string(out), nil
}

func payloadMarkerFilter(marker byte) ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: ethernetHeader, Size: 1},
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      uint32(marker),
			SkipTrue: 1,
		},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: math.MaxUint32},
	})
}

func ethernetFrame(dst, src net.HardwareAddr, etherType uint16, marker byte) []byte {
	frame := make([]byte, ethernetMinFrame)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	frame[ethernetHeader] = marker

	return frame
}
