//go:build linux || darwin || freebsd

package camouflage

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The four ECN codepoints, as they appear in the low two bits of an IPv4 TOS
// byte or an IPv6 traffic class.
const (
	ecnNotECT = 0x0
	ecnECT1   = 0x1
	ecnECT0   = 0x2
	ecnCE     = 0x3
)

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readMarked reads one packet and reports the codepoint it arrived with.
//
// Nothing here synthesizes a received control message. The whole risk this
// covers is that a kernel reports an arriving TOS byte under a different cmsg
// type than the one used to set it -- IP_TOS on Linux, IP_RECVTOS on the BSDs
// -- so a message this package built itself would prove only that it agrees
// with itself. The bytes have to come back from the kernel, which is also why
// the raw control message is returned: RelayPacket is fed that, not a
// reconstruction of it.
func readMarked(t *testing.T, conn *net.UDPConn) (data []byte, bits byte, addr *net.UDPAddr, oob []byte) {
	t.Helper()
	buf := make([]byte, 2048)
	oobBuf := make([]byte, udpRelayOOBSize)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, oobn, _, addr, err := conn.ReadMsgUDP(buf, oobBuf)
	require.NoError(t, err)
	bits, ok := parseECNBits(oobBuf[:oobn])
	require.True(t, ok, "kernel reported no ECN control message; enableECNRead or msgTypeIPTOS is wrong for this platform")
	return buf[:n], bits, addr, oobBuf[:oobn]
}

// requireECNSendSupport establishes that this kernel actually applies the
// IP_TOS control message, before any test asserts that a marking survived one.
//
// macOS does not. It accepts the message, returns the full oob length from
// sendmsg and no error, and puts a zero TOS byte on the wire -- so a relay
// running there forwards every packet unmarked while every call it makes
// reports success. Loopback is not the culprit: the same probe run with
// setsockopt(IP_TOS) instead of a control message arrives intact.
//
// Skipping rather than failing there would be too generous on the platform
// that matters, so Linux -- where camouflage is deployed and where this must
// work -- treats a lost marking as a failure.
func requireECNSendSupport(t *testing.T) {
	t.Helper()
	rx := mustListenUDP(t)
	enableECNRead(rx)
	tx := mustListenUDP(t)

	_, _, err := tx.WriteMsgUDP([]byte("probe"), appendECNOOB(nil, true, ecnCE), rx.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	buf := make([]byte, 64)
	oob := make([]byte, udpRelayOOBSize)
	require.NoError(t, rx.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, oobn, _, _, err := rx.ReadMsgUDP(buf, oob)
	require.NoError(t, err)

	bits, ok := parseECNBits(oob[:oobn])
	if ok && bits == ecnCE {
		return
	}
	if runtime.GOOS == "linux" {
		t.Fatalf("kernel did not apply the IP_TOS control message on send (got %#02x, present=%v); "+
			"on Linux this must work -- without it the relay forwards every packet unmarked", bits, ok)
	}
	t.Skipf("%s accepts the IP_TOS control message on send and discards it (got %#02x, present=%v); "+
		"ECN propagation is inert here, so there is nothing to assert", runtime.GOOS, bits, ok)
}

// TestECNCmsgKernelRoundTrip pins appendECNOOB and parseECNBits against the
// running kernel: mark a packet, send it over loopback, and read the codepoint
// back off the arriving control message.
func TestECNCmsgKernelRoundTrip(t *testing.T) {
	requireECNSendSupport(t)

	for _, mark := range []byte{ecnNotECT, ecnECT1, ecnECT0, ecnCE} {
		rx := mustListenUDP(t)
		enableECNRead(rx)
		tx := mustListenUDP(t)

		_, _, err := tx.WriteMsgUDP([]byte("probe"), appendECNOOB(nil, true, mark), rx.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)

		data, bits, _, _ := readMarked(t, rx)
		assert.Equal(t, "probe", string(data))
		assert.Equal(t, mark, bits, "codepoint %#02x did not survive the round trip", mark)
	}
}

// TestUDPRelayPropagatesECN drives a probe packet through the relay to a decoy
// and the decoy's answer back, asserting the codepoint survives both crossings.
//
// The two directions fail differently and both matter. Strip the forward one
// and the decoy honestly reports, in its own ACK frames, that it counted no
// ECT -- so the prober's ECN validation fails on data the decoy signed. Strip
// the reverse one and the prober simply sees packets arrive Not-ECT from a
// server that ought to mark them, no measurement required.
func TestUDPRelayPropagatesECN(t *testing.T) {
	requireECNSendSupport(t)

	decoy := mustListenUDP(t)
	enableECNRead(decoy)

	// The socket facing the prober, standing in for the one quic-go listens on.
	// quic-go enables ECN reporting on it for its own purposes; here it is what
	// gives RelayPacket a control message to read the probe's marking out of.
	relayConn := mustListenUDP(t)
	enableECNRead(relayConn)

	relay, err := NewUDPRelay(decoy.LocalAddr().String(), relayConn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = relay.Close() })

	prober := mustListenUDP(t)
	enableECNRead(prober)

	// Probe -> relay, marked ECT(0) the way a QUIC client marks its packets.
	_, _, err = prober.WriteMsgUDP([]byte("client hello"), appendECNOOB(nil, true, ecnECT0), relayConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	data, bits, proberAddr, oob := readMarked(t, relayConn)
	require.Equal(t, byte(ecnECT0), bits)
	relay.RelayPacket(data, proberAddr, oob)

	// Relay -> decoy: the marking the probe chose must have crossed.
	fwd, fwdBits, upstreamAddr, _ := readMarked(t, decoy)
	assert.Equal(t, "client hello", string(fwd))
	assert.Equal(t, byte(ecnECT0), fwdBits, "probe's ECT(0) did not reach the decoy")

	// Decoy -> relay -> probe, marked CE, which is the codepoint a real path
	// would set and the one a client counts to detect congestion. This crossing
	// also exercises a reply whose control message carries a codepoint and no
	// packet info, the case that used to fall back to an unmarked write.
	_, _, err = decoy.WriteMsgUDP([]byte("server hello"), appendECNOOB(nil, true, ecnCE), upstreamAddr)
	require.NoError(t, err)

	back, backBits, _, _ := readMarked(t, prober)
	assert.Equal(t, "server hello", string(back))
	assert.Equal(t, byte(ecnCE), backBits, "decoy's CE marking was stripped on the way back")
}
