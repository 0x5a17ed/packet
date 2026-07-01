//go:build linux || freebsd
// +build linux freebsd

package packet_test

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
)

const (
	ethernetHeader   = 14
	ethernetMinFrame = 60

	testEtherType   = 0x88b5
	testOtherType   = 0x88b6
	testMarker      = 0xa5
	testOtherMarker = 0x5a
)

func TestPacketConn(t *testing.T) {
	t.Run("AllProtocolReceive", testPacketConnAllProtocolReceive)
	t.Run("ProtocolFilter", testPacketConnProtocolFilter)
	t.Run("UserFilter", testPacketConnUserFilter)
	t.Run("StatsReset", testPacketConnStatsReset)
}

func testPacketConnAllProtocolReceive(t *testing.T) {
	pt := newPacketTest(t, testEthPAll, nil)

	pt.writeFrame(t, testOtherType, testMarker)

	got := pt.readFrame(t)
	if et := binary.BigEndian.Uint16(got[12:14]); et != testOtherType {
		t.Fatalf("unexpected EtherType: got %#04x, want %#04x", et, testOtherType)
	}
}

func testPacketConnProtocolFilter(t *testing.T) {
	pt := newPacketTest(t, testEtherType, nil)

	// The first frame would be delivered if the platform backend did not
	// compose the Conn protocol into the kernel-level packet filter.
	pt.writeFrame(t, testOtherType, testMarker)
	pt.writeFrame(t, testEtherType, testMarker)

	got := pt.readFrame(t)
	if et := binary.BigEndian.Uint16(got[12:14]); et != testEtherType {
		t.Fatalf("unexpected EtherType: got %#04x, want %#04x", et, testEtherType)
	}
}

func testPacketConnUserFilter(t *testing.T) {
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

func testPacketConnStatsReset(t *testing.T) {
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

type packetTestLink struct {
	tx *net.Interface
	rx *net.Interface
}

type packetTest struct {
	link packetTestLink
	rx   *packet.Conn
	tx   *packet.Conn
}

func newPacketTest(t *testing.T, protocol int, cfg *packet.Config) *packetTest {
	t.Helper()

	link := newPacketTestLink(t)
	rx := listenPacket(t, link.rx, protocol, cfg)
	tx := listenPacket(t, link.tx, testEthPAll, nil)

	return &packetTest{
		link: link,
		rx:   rx,
		tx:   tx,
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

	frame := ethernetFrame(pt.link.rx.HardwareAddr, pt.link.tx.HardwareAddr, etherType, marker)
	if _, err := pt.tx.WriteTo(frame, &packet.Addr{HardwareAddr: pt.link.rx.HardwareAddr}); err != nil {
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
