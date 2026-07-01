//go:build freebsd
// +build freebsd

package packet_test

import (
	"net"
	"strings"
	"testing"

	"github.com/mdlayher/packet"
)

func TestFreeBSDDatagramUnsupported(t *testing.T) {
	_, err := packet.Listen(&net.Interface{}, packet.Datagram, testEthPAll, nil)
	if err == nil {
		t.Fatal("expected an error, but none occurred")
	}
	if !strings.Contains(err.Error(), "Datagram is not supported on freebsd") {
		t.Fatalf("unexpected error: %v", err)
	}
}
