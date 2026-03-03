//go:build linux || darwin || freebsd

package camouflage

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ecnMask selects the two ECN bits out of an IPv4 TOS byte or an IPv6 traffic
// class. Everything above them is DSCP, which this package deliberately does
// not carry; see appendECNOOB.
const ecnMask = 0x3

// ecnOOBSpace is how much appendECNOOB can add to a control message buffer.
// Not a constant because unix.CmsgSpace is a function of the platform's
// alignment. The IPv6 message is the larger of the two.
var ecnOOBSpace = unix.CmsgSpace(4)

// parseECNBits extracts the ECN codepoint a packet arrived with from its
// control message, reporting whether one was present at all.
//
// A packet that carries no ECN message is not the same as one marked Not-ECT:
// the first means the kernel was never asked to report the codepoint, and
// stamping Not-ECT on the forwarded copy would then be inventing a marking
// rather than relaying one. Only the second should be forwarded as Not-ECT,
// and it arrives here as (0, true).
func parseECNBits(oob []byte) (byte, bool) {
	for len(oob) > 0 {
		hdr, body, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return 0, false
		}
		switch {
		case hdr.Level == unix.IPPROTO_IP && hdr.Type == msgTypeIPTOS && len(body) == 1:
			return body[0] & ecnMask, true
		case hdr.Level == unix.IPPROTO_IPV6 && hdr.Type == unix.IPV6_TCLASS && len(body) == 4:
			return byte(binary.NativeEndian.Uint32(body)) & ecnMask, true
		}
		oob = remainder
	}
	return 0, false
}

// appendECNOOB appends to b the control message that marks an outgoing packet
// with the given codepoint, for a destination of the given address family.
//
// Only the two ECN bits cross the relay. The DSCP field above them is dropped
// rather than copied, because copying it would let a prober choose the DSCP
// this server stamps on its own egress, and nothing in QUIC's ECN validation
// -- the thing this function exists to keep working -- ever looks at it.
//
// The layout is quic-go's appendIPv4ECNMsg/appendIPv6ECNMsg, down to the
// native-endian uint32 the IPv6 message wants where the IPv4 one takes a single
// byte. It has to be: these messages and quic-go's are read by the same kernel
// on the same socket, and a relay that got the width wrong would be rejected
// with EINVAL on every send.
//
// macOS accepts this message and drops it on the floor -- sendmsg returns the
// full control length and no error, and a zero TOS byte goes on the wire, so
// the relay there forwards unmarked while every call reports success. That is
// the kernel's behaviour and not something callers can detect, which is why
// requireECNSendSupport probes for it rather than trusting the return value.
// Linux, where camouflage is deployed, honours it.
func appendECNOOB(b []byte, isIPv4 bool, bits byte) []byte {
	bits &= ecnMask
	startLen := len(b)
	if isIPv4 {
		b = append(b, make([]byte, unix.CmsgSpace(1))...)
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
		h.Level = unix.IPPROTO_IP
		h.Type = unix.IP_TOS
		h.SetLen(unix.CmsgLen(1))
		b[startLen+unix.CmsgSpace(0)] = bits
		return b
	}
	b = append(b, make([]byte, unix.CmsgSpace(4))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = unix.IPPROTO_IPV6
	h.Type = unix.IPV6_TCLASS
	h.SetLen(unix.CmsgLen(4))
	offset := startLen + unix.CmsgSpace(0)
	binary.NativeEndian.PutUint32(b[offset:offset+4], uint32(bits))
	return b
}

// enableECNRead asks the kernel to report the ECN codepoint of packets arriving
// on conn, which is what makes the decoy's own marking visible to the relay.
//
// Both address families are attempted and neither result is checked, because
// the socket is one or the other and the wrong one always fails. Losing both is
// not worth refusing to relay over: the failure degrades to forwarding without
// ECN, which is what this relay did before it propagated ECN at all.
func enableECNRead(conn *net.UDPConn) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rawConn.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
	})
}
