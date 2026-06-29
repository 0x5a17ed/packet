//go:build linux
// +build linux

package packet

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/josharian/native"
	"golang.org/x/net/bpf"
)

func Test_htons(t *testing.T) {
	tests := []struct {
		name     string
		i        int
		vLE, vBE uint16
		ok       bool
	}{
		{
			name: "negative",
			i:    -1,
		},
		{
			name: "too large",
			i:    math.MaxUint16 + 1,
		},
		{
			name: "IPv4",
			i:    0x0800,
			vLE:  0x0008,
			vBE:  0x0800,
			ok:   true,
		},
		{
			name: "IPv6",
			i:    0x86dd,
			vLE:  0xdd86,
			vBE:  0x86dd,
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := htons(tt.i)
			if tt.ok && err != nil {
				t.Fatalf("failed to perform htons: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			// Depending on our GOARCH, the result may be big or little endian.
			var want uint16
			if native.Endian == binary.ByteOrder(binary.LittleEndian) {
				want = tt.vLE
			} else {
				want = tt.vBE
			}

			if diff := cmp.Diff(hex(want), hex(v)); diff != "" {
				t.Fatalf("unexpected output for %s GOARCH (-want +got):\n%s", native.Endian.String(), diff)
			}
		})
	}
}

func hex(v uint16) string {
	return fmt.Sprintf("%#04x", v)
}

func TestEthernetProtocolBPF(t *testing.T) {
	const ipv4 = 0x0800

	userFilter, err := bpf.Assemble([]bpf.Instruction{
		bpf.RetConstant{Val: 64},
	})
	if err != nil {
		t.Fatalf("failed to assemble user filter: %v", err)
	}

	filter, err := ethernetProtocolBPF(ipv4, userFilter)
	if err != nil {
		t.Fatalf("failed to assemble Ethernet protocol filter: %v", err)
	}

	tests := []struct {
		name      string
		etherType uint16
		want      int
	}{
		{
			name:      "match",
			etherType: ipv4,
			want:      64,
		},
		{
			name:      "mismatch",
			etherType: 0x0806,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := make([]byte, ethernetHeaderLen)
			binary.BigEndian.PutUint16(frame[12:14], tt.etherType)

			got := runBPF(t, filter, frame)
			if got != tt.want {
				t.Fatalf("unexpected filter verdict: got %d, want %d", got, tt.want)
			}
		})
	}

	if got := runBPF(t, filter, make([]byte, ethernetHeaderLen-1)); got != 0 {
		t.Fatalf("short frame accepted: got verdict %d, want 0", got)
	}
}

func TestEthernetProtocolBPFResetsAccumulator(t *testing.T) {
	const ipv4 = 0x0800

	userFilter, err := bpf.Assemble([]bpf.Instruction{
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      0,
			SkipTrue: 1,
		},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 64},
	})
	if err != nil {
		t.Fatalf("failed to assemble user filter: %v", err)
	}

	filter, err := ethernetProtocolBPF(ipv4, userFilter)
	if err != nil {
		t.Fatalf("failed to assemble Ethernet protocol filter: %v", err)
	}

	frame := make([]byte, ethernetHeaderLen)
	binary.BigEndian.PutUint16(frame[12:14], ipv4)

	if got := runBPF(t, filter, frame); got != 64 {
		t.Fatalf("unexpected filter verdict: got %d, want 64", got)
	}
}

func TestDefaultBPF(t *testing.T) {
	userFilter, err := bpf.Assemble([]bpf.Instruction{
		bpf.RetConstant{Val: 64},
	})
	if err != nil {
		t.Fatalf("failed to assemble user filter: %v", err)
	}

	filter, err := defaultBPF(userFilter)
	if err != nil {
		t.Fatalf("failed to build default filter: %v", err)
	}
	if diff := cmp.Diff(userFilter, filter); diff != "" {
		t.Fatalf("unexpected user filter (-want +got):\n%s", diff)
	}

	filter, err = defaultBPF(nil)
	if err != nil {
		t.Fatalf("failed to build default filter: %v", err)
	}
	if len(filter) != 1 || filter[0].K != math.MaxUint32 {
		t.Fatalf("unexpected default filter: %#v", filter)
	}
}

func TestDropAllBPF(t *testing.T) {
	filter, err := dropAllBPF()
	if err != nil {
		t.Fatalf("failed to build drop-all filter: %v", err)
	}
	if got := runBPF(t, filter, nil); got != 0 {
		t.Fatalf("drop-all filter accepted packet: got verdict %d, want 0", got)
	}
}

func runBPF(t *testing.T, filter []bpf.RawInstruction, frame []byte) int {
	t.Helper()

	instructions := make([]bpf.Instruction, len(filter))
	for i, insn := range filter {
		instructions[i] = insn.Disassemble()
	}

	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatalf("failed to create BPF VM: %v", err)
	}

	n, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("failed to run BPF VM: %v", err)
	}

	return n
}
