package packet

import (
	"math"

	"golang.org/x/net/bpf"
)

const ethernetHeaderLen = 14

// acceptAllBPF accepts the full packet.
func acceptAllBPF() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.RetConstant{Val: math.MaxUint32},
	})
}

// dropAllBPF rejects every packet.
func dropAllBPF() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.RetConstant{Val: 0},
	})
}

// defaultBPF uses the caller's filter, or an accept-all filter if none was
// provided.
func defaultBPF(filter []bpf.RawInstruction) ([]bpf.RawInstruction, error) {
	if len(filter) > 0 {
		return filter, nil
	}

	return acceptAllBPF()
}

// ethernetProtocolBPF composes an Ethernet protocol check with the caller's
// filter. This matches Linux packet sockets, where both the bound protocol and
// any installed BPF program must accept a packet before userspace can read it.
func ethernetProtocolBPF(protocol uint16, filter []bpf.RawInstruction) ([]bpf.RawInstruction, error) {
	prefix, err := bpf.Assemble(ethernetProtocolPrefixBPFSource(protocol))
	if err != nil {
		return nil, err
	}

	return appendDefaultBPF(prefix, filter)
}

// ethernetProtocolPrefixBPFSource returns a BPF program prefix that accepts only
// Ethernet frames whose EtherType field matches protocol. Short frames and
// protocol mismatches are rejected immediately; matches fall through to the
// next instruction appended by the caller.
func ethernetProtocolPrefixBPFSource(protocol uint16) []bpf.Instruction {
	// Offset | Length | Description
	// -----------------------------
	//      0 |      6 | Ethernet destination MAC address
	//      6 |      6 | Ethernet source MAC address
	//     12 |      2 | Ethernet EtherType
	const (
		etherTypeOffset = 12
		etherTypeLength = 2
	)

	return []bpf.Instruction{
		// Reject frames too short to contain an Ethernet header.
		bpf.LoadExtension{Num: bpf.ExtLen},
		bpf.JumpIf{
			Cond:     bpf.JumpGreaterOrEqual,
			Val:      ethernetHeaderLen,
			SkipTrue: 1,
		},
		bpf.RetConstant{Val: 0},

		// Load EtherType value from Ethernet header.
		bpf.LoadAbsolute{
			Off:  etherTypeOffset,
			Size: etherTypeLength,
		},
		// If `EtherType` is equal to the protocol we are using,
		// jump to instructions added outside this function.
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      uint32(protocol),
			SkipTrue: 1,
		},
		// EtherType does not match our protocol.
		bpf.RetConstant{Val: 0},

		// Match: restore the initial accumulator state before running the
		// caller's filter.
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},
	}
}

// appendDefaultBPF appends the caller's filter to prefix, or appends an
// accept-all filter when no caller filter was provided.
func appendDefaultBPF(prefix []bpf.RawInstruction, filter []bpf.RawInstruction) ([]bpf.RawInstruction, error) {
	tail, err := defaultBPF(filter)
	if err != nil {
		return nil, err
	}

	return append(prefix, tail...), nil
}
