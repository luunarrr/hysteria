package camouflage

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

// A server generally answers at more than one address, and a client mints its
// token against whichever one it dialled. These pin the consequence: every
// configured address is accepted, not just the first one written down.
func TestProcessPacket_TokenForAnyConfiguredAddress(t *testing.T) {
	psk := DerivePSK("bear:hunter2")
	first := net.ParseIP("203.0.113.7")
	second := net.ParseIP("198.51.100.9")

	f := newTestFilter(FilterConfig{
		Secrets:   map[string][]byte{"bear": psk},
		ServerIPs: []net.IP{first, second},
	})

	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 5000}
	for _, ip := range []net.IP{first, second} {
		dcid, err := GenerateDCID(psk, ip, 0)
		require.NoError(t, err)
		assert.True(t, f.processPacket(initialPacket(dcid), src, nil),
			"a token minted against %s must be accepted: it is one of this server's addresses", ip)
	}

	// The check is still a check. An address this server does not answer at is
	// what cross-server replay looks like, and it stays rejected.
	elsewhere, err := GenerateDCID(psk, net.ParseIP("192.0.2.1"), 0)
	require.NoError(t, err)
	assert.False(t, f.processPacket(initialPacket(elsewhere), src, nil))
}

// Leaving serverAddr unset means the check is off, and it has to stay off:
// turning it on for an operator who never asked would reject clients silently.
func TestProcessPacket_NoConfiguredAddressSkipsCheck(t *testing.T) {
	psk := DerivePSK("bear:hunter2")
	f := newTestFilter(FilterConfig{Secrets: map[string][]byte{"bear": psk}})

	dcid, err := GenerateDCID(psk, net.ParseIP("192.0.2.1"), 0)
	require.NoError(t, err)
	assert.True(t, f.processPacket(initialPacket(dcid),
		&net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 5000}, nil))
}

func TestVerifyDCIDAny(t *testing.T) {
	psk := DerivePSK("bear:hunter2")
	mine := net.ParseIP("203.0.113.7")
	dcid, err := GenerateDCID(psk, mine, 0)
	require.NoError(t, err)
	secrets := map[string][]byte{"bear": psk}

	t.Run("matches a later entry", func(t *testing.T) {
		r := VerifyDCIDAny(secrets, []net.IP{net.ParseIP("192.0.2.1"), mine}, dcid, 0)
		assert.True(t, r.Matched())
		assert.True(t, r.ServerIDMatch)
	})
	t.Run("no entry matches", func(t *testing.T) {
		r := VerifyDCIDAny(secrets, []net.IP{net.ParseIP("192.0.2.1")}, dcid, 0)
		assert.True(t, r.Matched(), "the HMAC is still valid; only the address is wrong")
		assert.False(t, r.ServerIDMatch)
	})
	t.Run("empty skips the comparison", func(t *testing.T) {
		assert.True(t, VerifyDCIDAny(secrets, nil, dcid, 0).ServerIDMatch)
	})
	t.Run("nil entries are ignored, not treated as an address", func(t *testing.T) {
		assert.True(t, VerifyDCIDAny(secrets, []net.IP{nil}, dcid, 0).ServerIDMatch,
			"a slice holding only nils is no address at all, same as an empty one")
		assert.False(t, VerifyDCIDAny(secrets, []net.IP{nil, net.ParseIP("192.0.2.1")}, dcid, 0).ServerIDMatch)
	})
	t.Run("VerifyDCID keeps its single-address meaning", func(t *testing.T) {
		assert.True(t, VerifyDCID(secrets, mine, dcid, 0).ServerIDMatch)
		assert.False(t, VerifyDCID(secrets, net.ParseIP("192.0.2.1"), dcid, 0).ServerIDMatch)
		assert.True(t, VerifyDCID(secrets, nil, dcid, 0).ServerIDMatch)
	})
}

// loopbackOOB returns the control message a real datagram arrived with, and the
// address it says the datagram was sent to.
//
// A real socket rather than a hand-built cmsg, because the layout differs across
// kernels and a fixture would only test the fixture. ipv4.ControlMessage.Marshal
// is specifically not a substitute: it writes the address into ipi_spec_dst,
// while the field that says where a packet was addressed -- the one Parse reads
// back into Dst, and the one quic-go reads -- is ipi_addr, which Marshal leaves
// zero.
func loopbackOOB(t *testing.T) ([]byte, net.IP) {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	if err := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		t.Skipf("kernel will not report the destination address: %v", err)
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { sender.Close() })
	_, err = sender.WriteToUDP([]byte("x"), &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: conn.LocalAddr().(*net.UDPAddr).Port,
	})
	require.NoError(t, err)

	buf := make([]byte, 64)
	oob := make([]byte, 1024)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, oobn, _, _, err := conn.ReadMsgUDP(buf, oob)
	require.NoError(t, err)
	oob = oob[:oobn]

	arrival, _, _, ok := localDstFromOOB(oob)
	require.True(t, ok, "the read carried no packet info, so there is nothing to test")
	require.Equal(t, "127.0.0.1", arrival.String())
	return oob, arrival
}

// expectedServerIPs must not write the arrival address into the array backing
// the configured slice: every packet shares that array, and one appending into
// it would hand its address to the next.
func TestExpectedServerIPs_DoesNotAliasConfig(t *testing.T) {
	oob, arrival := loopbackOOB(t)

	configured := make([]net.IP, 1, 4) // spare capacity is what makes append reuse
	configured[0] = net.ParseIP("203.0.113.7")
	f := newTestFilter(FilterConfig{ServerIPs: configured})

	out := f.expectedServerIPs(oob)
	require.Len(t, out, 2)
	assert.Equal(t, arrival.String(), out[1].String())

	assert.Len(t, f.config.ServerIPs, 1, "the configured slice must be untouched")
	assert.Equal(t, "203.0.113.7", configured[:cap(configured)][0].String())
	assert.Nil(t, configured[:cap(configured)][1], "nothing may have been written past the length")

	assert.Len(t, f.expectedServerIPs(nil), 1, "no packet info leaves the configured set alone")
}

// The end this whole change exists for: a client that dialled an address the
// operator never wrote down is still recognised, because the kernel says which
// address the packet came in on.
func TestProcessPacket_TokenForArrivalAddress(t *testing.T) {
	oob, arrival := loopbackOOB(t)

	// The filter is configured with a different address entirely, so the token
	// below is accepted only on the strength of where it arrived.
	psk := DerivePSK("bear:hunter2")
	f := newTestFilter(FilterConfig{
		Secrets:   map[string][]byte{"bear": psk},
		ServerIPs: []net.IP{net.ParseIP("203.0.113.7")},
	})
	dcid, err := GenerateDCID(psk, arrival, 0)
	require.NoError(t, err)

	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 5000}
	assert.True(t, f.processPacket(initialPacket(dcid), src, oob),
		"a token minted against the address the packet arrived on must be accepted")
	assert.False(t, f.processPacket(initialPacket(dcid), src, nil),
		"without packet info there is nothing to accept it on")
}
