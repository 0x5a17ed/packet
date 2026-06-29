//go:build freebsd
// +build freebsd

package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/josharian/native"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	freebsdBPFDevices = 256

	// ETH_P_ALL is Linux-specific and is not defined by x/sys/unix on
	// FreeBSD, but callers still use the protocol value to request all
	// Ethernet frames.
	freebsdEthPAll = 0x0003

	ifNameSize = 16
	ifReqSize  = 32
)

const (
	// FreeBSD's bh_hdrlen reports the bytes through the bh_hdrlen field, not
	// sizeof(struct bpf_hdr), which includes trailing padding on 64-bit
	// platforms.
	bpfCaplenOffset = int(unsafe.Offsetof(unix.BpfHdr{}.Caplen))
	bpfHdrlenOffset = int(unsafe.Offsetof(unix.BpfHdr{}.Hdrlen))
	bpfHdrlenSize   = 2
	bpfHdrMinLen    = bpfHdrlenOffset + bpfHdrlenSize
)

// A conn is the net.PacketConn implementation for FreeBSD BPF devices.
type conn struct {
	file *os.File

	protocol uint16
	dlt      int

	readBuf []byte
	off     int
	n       int

	statsMu      sync.Mutex
	statsBase    unix.BpfStat
	statsPending unix.BpfStat
}

// readFrom implements the net.PacketConn ReadFrom method using read(2) on
// /dev/bpf. A single BPF read can contain several frames, so conn keeps cursor
// state between calls.
func (c *Conn) readFrom(b []byte) (int, net.Addr, error) {
	for {
		frame, err := c.c.nextFrame()
		if err != nil {
			return 0, nil, c.opError(opRead, err)
		}
		// The installed BPF program should already enforce the Conn protocol.
		// Keep this check as a defensive backstop if the kernel ever returns a
		// frame that does not match the descriptor's effective filter.
		if !c.acceptFrame(frame) {
			continue
		}

		return copy(b, frame), c.addrFromFrame(frame), nil
	}
}

// writeTo implements the net.PacketConn WriteTo method using write(2) on
// /dev/bpf.
func (c *Conn) writeTo(b []byte, addr net.Addr) (int, error) {
	a, ok := addr.(*Addr)
	if !ok || a.HardwareAddr == nil {
		return 0, c.opError(opWrite, os.NewSyscallError("write", unix.EINVAL))
	}

	n, err := c.c.file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}

	return n, c.opError(opWrite, err)
}

// setPromiscuous wraps ioctl(2) for the BIOCPROMISC option.
func (c *Conn) setPromiscuous(enable bool) error {
	if !enable {
		// FreeBSD BPF only exposes an ioctl to enable promiscuous mode for this
		// descriptor. The kernel drops the reference when the descriptor closes.
		return c.opError(opSet, os.NewSyscallError("ioctl", unix.EOPNOTSUPP))
	}

	return c.opError(opSet, c.c.ioctl(unix.BIOCPROMISC, nil))
}

// stats retrieves BPF descriptor statistics and reports deltas since the last
// call, mirroring Linux's reset-on-read behavior.
func (c *Conn) stats() (*Stats, error) {
	stats, err := c.c.stats()
	if err != nil {
		return nil, c.opError(opGetsockopt, err)
	}

	return stats, nil
}

// stats wraps ioctl(2) for BIOCGSTATS.
func (c *conn) stats() (*Stats, error) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	stats, err := c.bpfStats()
	if err != nil {
		return nil, err
	}

	// FreeBSD's BIOCGSTATS reports cumulative descriptor counters, unlike
	// Linux's PACKET_STATISTICS getsockopt which resets counters on read.
	// Track the previous kernel snapshot and report only the delta so the
	// package-level Stats contract is the same on both platforms.
	delta := bpfStatsDelta(stats, c.statsBase)
	delta = bpfStatsAdd(delta, c.statsPending)

	c.statsBase = stats
	c.statsPending = unix.BpfStat{}

	return bpfStat(delta), nil
}

// listen is the entry point for Listen on FreeBSD.
func listen(ifi *net.Interface, socketType Type, protocol int, cfg *Config) (*Conn, error) {
	if cfg == nil {
		// Default configuration.
		cfg = &Config{}
	}

	p, err := parseListenArgs(socketType, protocol)
	if err != nil {
		return nil, err
	}

	bc, err := newBPFConn(p)
	if err != nil {
		return nil, err
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = bc.Close()
		}
	}()

	if err := bc.bind(ifi, cfg.Filter); err != nil {
		return nil, err
	}

	cleanup = false
	return newConn(bc, ifi, p), nil
}

// parseListenArgs validates Listen arguments and returns the FreeBSD protocol
// value used by conn.
func parseListenArgs(socketType Type, protocol int) (uint16, error) {
	switch socketType {
	case Raw:
		return freebsdProtocol(protocol)
	case Datagram:
		return 0, errors.New("packet: Datagram is not supported on freebsd")
	default:
		return 0, errors.New("packet: invalid Type value")
	}
}

// newBPFConn opens a BPF device and wraps it in conn.
func newBPFConn(protocol uint16) (*conn, error) {
	f, err := openBPF()
	if err != nil {
		return nil, err
	}

	return &conn{
		file:     f,
		protocol: protocol,
	}, nil
}

// bind attaches conn to ifi and finishes BPF descriptor setup.
func (c *conn) bind(ifi *net.Interface, filter []bpf.RawInstruction) error {
	// FreeBSD BPF starts capture when BIOCSETIF attaches the descriptor to an
	// interface, but BIOCGDLT only reports the data link type after that attach.
	// That ordering matters because a specific Conn protocol can only be
	// translated into a kernel BPF check once we know what link-layer header the
	// kernel will present. For example, ETH_P_IP is an Ethernet EtherType check
	// for DLT_EN10MB, but it has no correct Ethernet offset on another DLT.
	//
	// Install a temporary drop-all filter before BIOCSETIF so the unavoidable
	// setup window is inert. This keeps pre-Listen packets out of the read
	// buffer, prevents setup-window packets from being delivered after the final
	// filter is installed, and avoids counting those packets in descriptor
	// statistics. After BIOCGDLT, verify that the requested protocol can be
	// expressed for the descriptor's data link type, then replace the guard with
	// the effective filter: requested protocol AND caller's BPF filter.
	if err := c.configure(); err != nil {
		return err
	}

	if err := c.setInterface(ifi.Name); err != nil {
		return err
	}

	if err := c.readDataLinkType(); err != nil {
		return err
	}
	if err := c.validateDataLinkType(); err != nil {
		return err
	}

	return c.installEffectiveBPF(filter, false)
}

// configure prepares a BPF descriptor for packet I/O before it is attached to
// an interface.
func (c *conn) configure() error {
	if err := c.installDropAllFilter(); err != nil {
		return err
	}

	if err := c.enableImmediateMode(); err != nil {
		return err
	}

	return c.allocateReadBuffer()
}

// readDataLinkType records the data link type for parsing received frames.
func (c *conn) readDataLinkType() error {
	dlt, err := c.ioctlGetInt(unix.BIOCGDLT)
	if err != nil {
		return err
	}

	c.dlt = dlt
	return nil
}

// validateDataLinkType verifies that conn can express its requested protocol for
// the attached interface's data link type.
func (c *conn) validateDataLinkType() error {
	if c.protocol == freebsdEthPAll || c.dlt == unix.DLT_EN10MB {
		return nil
	}

	return fmt.Errorf("packet: protocol-specific capture is unsupported on dlt %d: %w",
		c.dlt,
		errors.ErrUnsupported)
}

// installDropAllFilter blocks packet capture during descriptor setup. It is an
// internal guard, not caller policy, so installing the final filter later should
// reset any counters from this phase rather than preserving them for Stats.
func (c *conn) installDropAllFilter() error {
	filter, err := dropAllBPF()
	if err != nil {
		return err
	}

	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	return c.setBPF(filter, false)
}

// enableImmediateMode makes reads return as soon as packets are available and
// makes writes expect complete link-layer frames.
func (c *conn) enableImmediateMode() error {
	if err := c.ioctlSetPointerInt(unix.BIOCIMMEDIATE, 1); err != nil {
		return err
	}

	return c.ioctlSetPointerInt(unix.BIOCSHDRCMPLT, 1)
}

// allocateReadBuffer allocates the kernel-requested BPF read buffer size.
func (c *conn) allocateReadBuffer() error {
	blen, err := c.ioctlGetInt(unix.BIOCGBLEN)
	if err != nil {
		return err
	}
	if blen <= 0 {
		return fmt.Errorf("packet: invalid BPF buffer length: %d", blen)
	}
	c.readBuf = make([]byte, blen)

	return nil
}

// newConn constructs a Conn from a configured BPF conn.
func newConn(bc *conn, ifi *net.Interface, protocol uint16) *Conn {
	addr := make(net.HardwareAddr, len(ifi.HardwareAddr))
	copy(addr, ifi.HardwareAddr)

	return &Conn{
		c: bc,

		addr:     &Addr{HardwareAddr: addr},
		ifIndex:  ifi.Index,
		protocol: protocol,
	}
}

// Close closes the underlying BPF device.
func (c *conn) Close() error { return c.file.Close() }

// SetDeadline implements deadline handling for BPF device I/O.
func (c *conn) SetDeadline(t time.Time) error { return c.file.SetDeadline(t) }

// SetReadDeadline implements read deadline handling for BPF device I/O.
func (c *conn) SetReadDeadline(t time.Time) error { return c.file.SetReadDeadline(t) }

// SetWriteDeadline implements write deadline handling for BPF device I/O.
func (c *conn) SetWriteDeadline(t time.Time) error { return c.file.SetWriteDeadline(t) }

// SyscallConn returns a raw connection for the underlying BPF device.
func (c *conn) SyscallConn() (syscall.RawConn, error) { return c.file.SyscallConn() }

// SetBPF attaches an assembled BPF program to the Conn.
func (c *conn) SetBPF(filter []bpf.RawInstruction) error {
	return c.installEffectiveBPF(filter, true)
}

// installEffectiveBPF composes and installs the caller's filter with the Conn
// protocol. preserveStats is true for public SetBPF calls because callers
// expect unreported counters to survive a filter change. Setup-time installs use
// false because the only previous filter is the internal drop-all guard, whose
// counters should not become visible through Stats.
func (c *conn) installEffectiveBPF(filter []bpf.RawInstruction, preserveStats bool) error {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	effective, err := c.effectiveBPF(filter)
	if err != nil {
		return err
	}

	return c.setBPF(effective, preserveStats)
}

// setBPF attaches an assembled BPF program to the Conn. The caller must hold
// c.statsMu because FreeBSD resets descriptor statistics on BIOCSETF. When
// preserveStats is true, any counters that reset would otherwise hide are added
// to statsPending so the package-level Stats contract remains reset-on-read.
func (c *conn) setBPF(filter []bpf.RawInstruction, preserveStats bool) error {
	var stats unix.BpfStat
	if preserveStats {
		var err error
		stats, err = c.bpfStats()
		if err != nil {
			return err
		}
	}

	insns := make([]unix.BpfInsn, len(filter))
	for i, insn := range filter {
		insns[i] = unix.BpfInsn{
			Code: insn.Op,
			Jt:   insn.Jt,
			Jf:   insn.Jf,
			K:    insn.K,
		}
	}

	program := unix.BpfProgram{
		Len: uint32(len(insns)),
	}
	if len(insns) > 0 {
		program.Insns = &insns[0]
	}

	err := c.ioctl(unix.BIOCSETF, unsafe.Pointer(&program))
	runtime.KeepAlive(insns)
	if err != nil {
		return err
	}

	if preserveStats {
		// FreeBSD resets descriptor counters on BIOCSETF, unlike Linux filter
		// attachment. Preserve any counts not yet reported by Stats so changing
		// the filter does not discard them from the package-level counters.
		c.statsPending = bpfStatsAdd(c.statsPending, bpfStatsDelta(stats, c.statsBase))
	} else {
		c.statsPending = unix.BpfStat{}
	}
	c.statsBase = unix.BpfStat{}
	return nil
}

// effectiveBPF produces the actual kernel BPF program installed on FreeBSD.
// Linux packet sockets apply the bound protocol in the kernel before userspace
// can read a packet, independently of any caller-supplied BPF. FreeBSD BPF has
// no separate protocol bind, so the FreeBSD backend must encode that protocol
// check directly into the installed BPF program.
//
// ETH_P_ALL means there is no internal protocol check. For Ethernet, a specific
// protocol becomes an EtherType check composed with the caller's filter.
func (c *conn) effectiveBPF(filter []bpf.RawInstruction) ([]bpf.RawInstruction, error) {
	if c.protocol == freebsdEthPAll {
		return defaultBPF(filter)
	}
	if err := c.validateDataLinkType(); err != nil {
		return nil, err
	}

	return ethernetProtocolBPF(c.protocol, filter)
}

// bpfStats wraps ioctl(2) for BIOCGSTATS.
func (c *conn) bpfStats() (unix.BpfStat, error) {
	var stats unix.BpfStat
	err := c.ioctl(unix.BIOCGSTATS, unsafe.Pointer(&stats))
	return stats, err
}

// bpfStatsDelta returns the uint32 delta between two BPF statistics snapshots.
func bpfStatsDelta(current, previous unix.BpfStat) unix.BpfStat {
	return unix.BpfStat{
		Recv: current.Recv - previous.Recv,
		Drop: current.Drop - previous.Drop,
	}
}

// bpfStatsAdd returns the sum of a and b.
func bpfStatsAdd(a, b unix.BpfStat) unix.BpfStat {
	return unix.BpfStat{
		Recv: a.Recv + b.Recv,
		Drop: a.Drop + b.Drop,
	}
}

// bpfStat converts a FreeBSD BPF statistics snapshot into public Stats.
func bpfStat(stats unix.BpfStat) *Stats {
	return &Stats{
		Packets: stats.Recv,
		Drops:   stats.Drop,
	}
}

// nextFrame returns the next frame from the BPF buffer, reading a new buffer
// from the kernel when all buffered frames have been consumed.
func (c *conn) nextFrame() ([]byte, error) {
	for {
		switch frame, ok, err := c.nextBufferedFrame(); {
		case err != nil:
			return nil, err
		case ok:
			return frame, nil
		}

		if err := c.readFrameBuffer(); err != nil {
			return nil, err
		}
	}
}

// nextBufferedFrame returns the next frame already read from BPF. If the buffer
// has been fully consumed, ok is false and the caller should read a new buffer.
func (c *conn) nextBufferedFrame() ([]byte, bool, error) {
	if c.off >= c.n {
		return nil, false, nil
	}

	if c.n-c.off < bpfHdrMinLen {
		c.discardReadBuffer()
		return nil, false, nil
	}

	frame, next, err := parseBPFRecord(c.readBuf, c.off, c.n)
	if err != nil {
		c.discardReadBuffer()
		return nil, false, err
	}

	c.off = next
	return frame, true, nil
}

// readFrameBuffer reads a fresh batch of one or more BPF records.
func (c *conn) readFrameBuffer() error {
	n, err := c.file.Read(c.readBuf)
	if err != nil {
		return err
	}
	if n == 0 {
		return io.ErrNoProgress
	}

	c.off = 0
	c.n = n
	return nil
}

// discardReadBuffer marks the current read buffer as consumed.
func (c *conn) discardReadBuffer() {
	c.off = c.n
}

// parseBPFRecord returns the packet bytes and next record offset for a BPF
// record starting at off.
func parseBPFRecord(buf []byte, off, n int) ([]byte, int, error) {
	headerFieldsEnd := off + bpfHdrMinLen
	headerFieldsWrapped := headerFieldsEnd < off
	headerFieldsTruncated := headerFieldsEnd > n
	if headerFieldsWrapped || headerFieldsTruncated {
		return nil, 0, io.ErrUnexpectedEOF
	}

	capLen := int(native.Endian.Uint32(buf[off+bpfCaplenOffset:][:4]))
	hdrLen := int(native.Endian.Uint16(buf[off+bpfHdrlenOffset:][:2]))
	frameStart := off + hdrLen
	frameEnd := frameStart + capLen
	next := off + bpfWordAlign(hdrLen+capLen)

	headerTooShort := hdrLen < bpfHdrMinLen
	frameStartWrapped := frameStart < off
	frameEndWrapped := frameEnd < frameStart
	frameExceedsBuffer := frameEnd > n
	nextRecordWrapped := next < frameEnd

	if headerTooShort || frameStartWrapped || frameEndWrapped || frameExceedsBuffer || nextRecordWrapped {
		return nil, 0, io.ErrUnexpectedEOF
	}

	return buf[frameStart:frameEnd], next, nil
}

// acceptFrame reports whether a BPF frame matches the Conn protocol.
func (c *Conn) acceptFrame(frame []byte) bool {
	if c.protocol == freebsdEthPAll {
		return true
	}
	if c.c.dlt != unix.DLT_EN10MB || len(frame) < ethernetHeaderLen {
		return false
	}

	return binary.BigEndian.Uint16(frame[12:14]) == c.protocol
}

// addrFromFrame returns the source hardware address for Ethernet frames.
func (c *Conn) addrFromFrame(frame []byte) net.Addr {
	if c.c.dlt != unix.DLT_EN10MB || len(frame) < ethernetHeaderLen {
		return &Addr{}
	}

	addr := make(net.HardwareAddr, 6)
	copy(addr, frame[6:12])
	return &Addr{HardwareAddr: addr}
}

// setInterface attaches a BPF descriptor to an interface.
func (c *conn) setInterface(name string) error {
	var req ifreq
	if err := req.setName(name); err != nil {
		return os.NewSyscallError("ioctl", err)
	}

	return c.ioctl(unix.BIOCSETIF, unsafe.Pointer(&req))
}

// ioctlGetInt wraps ioctl(2) requests which read a 32-bit integer.
func (c *conn) ioctlGetInt(req uint) (int, error) {
	var v int32
	if err := c.ioctl(req, unsafe.Pointer(&v)); err != nil {
		return 0, err
	}

	return int(v), nil
}

// ioctlSetPointerInt wraps ioctl(2) requests which write a 32-bit integer by
// pointer.
func (c *conn) ioctlSetPointerInt(req uint, v int) error {
	vv := int32(v)
	return c.ioctl(req, unsafe.Pointer(&vv))
}

// ioctl invokes ioctl(2) through syscall.RawConn to avoid File.Fd changing the
// descriptor back to blocking mode.
func (c *conn) ioctl(req uint, arg unsafe.Pointer) error {
	// Keep stack-backed ioctl arguments alive until the syscall has returned.
	defer runtime.KeepAlive(arg)

	rc, err := c.file.SyscallConn()
	if err != nil {
		return err
	}

	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(req), uintptr(arg))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}

	return nil
}

// ifreq is the FreeBSD struct ifreq size used by BIOCSETIF.
type ifreq struct {
	Name [ifNameSize]byte
	Data [ifReqSize - ifNameSize]byte
}

// setName stores name in req as a null-terminated interface name.
func (req *ifreq) setName(name string) error {
	n := len(name)
	if n >= len(req.Name) {
		return unix.ENAMETOOLONG
	}

	req.Name = [ifNameSize]byte{}
	copy(req.Name[:n], name)

	return nil
}

// openBPF opens a BPF clone device or falls back to numbered BPF devices.
func openBPF() (*os.File, error) {
	f, err := os.OpenFile("/dev/bpf", os.O_RDWR, 0)
	switch {
	case err == nil:
		return f, nil
	case isPermission(err):
		return nil, err
	}

	firstErr := err
	for i := 0; i < freebsdBPFDevices; i++ {
		switch f, err := os.OpenFile(fmt.Sprintf("/dev/bpf%d", i), os.O_RDWR, 0); {
		case err == nil:
			return f, nil
		case isPermission(err):
			return nil, err
		case firstErr == nil || errors.Is(firstErr, os.ErrNotExist):
			firstErr = err
		}
	}

	return nil, firstErr
}

func isPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}

// bpfWordAlign rounds n up to BPF_ALIGNMENT.
func bpfWordAlign(n int) int {
	align := int(unix.BPF_ALIGNMENT)
	return (n + (align - 1)) &^ (align - 1)
}

// freebsdProtocol converts a protocol argument to uint16.
func freebsdProtocol(i int) (uint16, error) {
	if i < 0 || i > math.MaxUint16 {
		return 0, errors.New("packet: protocol value out of range")
	}

	return uint16(i), nil
}
