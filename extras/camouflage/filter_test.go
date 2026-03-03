package camouflage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

func TestSourceIP(t *testing.T) {
	assert.Equal(t, "203.0.113.9", sourceIP(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4433}))
	assert.Equal(t, "2001:db8::1", sourceIP(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4433}))
	assert.Equal(t, "203.0.113.9", sourceIP(&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 443}))
}

func newTestFilter(config FilterConfig) *Filter {
	if config.TimeBucketSize <= 0 {
		config.TimeBucketSize = DefaultTimeBucket
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 30 * time.Second
	}
	return &Filter{
		conn:      nil, // processPacket never touches the conn; relay is nil-guarded
		config:    config,
		replayMap: make(map[[DCIDLen]byte]string),
		authSet:   make(map[string]time.Time),
		done:      make(chan struct{}),
	}
}

// initialPacket is a QUIC Initial carrying the given 8-byte DCID.
func initialPacket(dcid []byte) []byte {
	p := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	p = append(p, dcid...)
	return append(p, 0x00)
}

// TestProcessPacket_RateLimitCountsPerIP pins the failure counter to the source
// IP. A scanner varying its source port must not get a fresh counter per
// packet, which is what keying on the full 4-tuple would have given it.
func TestProcessPacket_RateLimitCountsPerIP(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	f := newTestFilter(FilterConfig{
		Secrets:     map[string][]byte{"fleet": []byte("the-real-secret")},
		RateLimiter: rl,
	})

	packet := initialPacket([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	for port := 1000; port < 1003; port++ {
		src := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: port}
		assert.False(t, f.processPacket(packet, src, nil), "unauthenticated packet must not reach quic-go")
	}

	assert.True(t, rl.IsRateLimited("203.0.113.9"), "three failures from one IP should trip a threshold of 3")
	assert.False(t, rl.IsRateLimited("203.0.113.10"), "an unrelated source must be unaffected")
}

func TestProcessPacket_ValidDCIDAccepted(t *testing.T) {
	psk := DerivePSK("bear:hunter2")
	serverIP := net.ParseIP("203.0.113.7")
	f := newTestFilter(FilterConfig{
		Secrets:     map[string][]byte{"bear": psk},
		ServerIP:    serverIP,
		RateLimiter: NewRateLimiter(3, time.Minute),
	})

	dcid, err := GenerateDCID(psk, serverIP, 0)
	assert.NoError(t, err)

	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 5000}
	assert.True(t, f.processPacket(initialPacket(dcid), src, nil))

	// The source is now authenticated, so its short-header packets pass too.
	assert.True(t, f.processPacket([]byte{0x40, 0xAA, 0xBB}, src, nil))
	// A different source is not.
	other := &net.UDPAddr{IP: net.ParseIP("198.51.100.5"), Port: 5000}
	assert.False(t, f.processPacket([]byte{0x40, 0xAA, 0xBB}, other, nil))
}

// TestProcessPacket_RelayFuncReports covers the hook that makes a rejection
// visible at all: without it, a client the filter disagrees with and a passing
// scanner look identical from the server, which is silence.
func TestProcessPacket_RelayFuncReports(t *testing.T) {
	var got []string
	psk := DerivePSK("bear:hunter2")
	serverIP := net.ParseIP("203.0.113.7")
	f := newTestFilter(FilterConfig{
		Secrets:   map[string][]byte{"bear": psk},
		ServerIP:  serverIP,
		RelayFunc: func(_ net.Addr, reason string) { got = append(got, reason) },
	})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 5000}

	// A token for a different concentrator: the case that reads as an
	// unreachable server unless something says otherwise.
	elsewhere, err := GenerateDCID(psk, net.ParseIP("192.0.2.1"), 0)
	assert.NoError(t, err)
	assert.False(t, f.processPacket(initialPacket(elsewhere), src, nil))

	assert.False(t, f.processPacket(initialPacket([]byte{1, 2, 3, 4, 5, 6, 7, 8}), src, nil))
	assert.False(t, f.processPacket([]byte{0x40, 0xAA}, src, nil))
	assert.False(t, f.processPacket([]byte{}, src, nil))

	assert.Equal(t, []string{
		"token minted against a different address",
		"no configured secret matches the token",
		"short header from an unauthenticated source",
		"unparseable QUIC header",
	}, got)

	// An accepted packet must not be reported as relayed.
	got = nil
	ok, err := GenerateDCID(psk, serverIP, 0)
	assert.NoError(t, err)
	assert.True(t, f.processPacket(initialPacket(ok), src, nil))
	assert.Empty(t, got)
}

// quic-go chooses between its out-of-band path and basicConn once, at listener
// setup, purely by type-asserting the net.PacketConn it was handed. Failing that
// assertion is silent -- it logs at info on quic-go's own logger, not the
// server's -- and costs IP_PKTINFO, and with it the ability to answer from the
// address a datagram arrived on. A concentrator holding two addresses then
// answers every client from one of them.
//
// Asserted against quic-go's own interface rather than a local copy of the
// method set, so that a change on either side is a build failure here instead of
// a server that quietly replies from the wrong IP.
var _ quic.OOBCapablePacketConn = (*filterUDP)(nil)

func TestWrapPacketConn_KeepsOOBCapabilityOverAUDPSocket(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	wrapped := WrapPacketConn(conn, FilterConfig{Secrets: map[string][]byte{"bear": DerivePSK("bear:hunter2")}})
	defer wrapped.Close()

	_, ok := wrapped.(quic.OOBCapablePacketConn)
	assert.True(t, ok, "a wrapped UDP socket must still look OOB-capable to quic-go")
}

// A conn that is not a UDP socket has no OOB to preserve, and claiming
// otherwise would send quic-go down a path whose methods cannot work.
func TestWrapPacketConn_PlainPacketConnStaysPlain(t *testing.T) {
	wrapped := WrapPacketConn(nonUDPConn{}, FilterConfig{})
	defer wrapped.Close()

	_, ok := wrapped.(quic.OOBCapablePacketConn)
	assert.False(t, ok, "only a real UDP socket can honour the OOB interface")
}

type nonUDPConn struct{ net.PacketConn }

func (nonUDPConn) Close() error { return nil }

// The security half of the same change. Once quic-go takes the OOB path it
// never calls ReadFrom again, so a ReadMsgUDP that merely forwards to the socket
// would hand every probe straight to the QUIC stack while the filter sat in the
// call chain looking installed.
func TestFilterUDP_ReadMsgUDPAppliesTheFilter(t *testing.T) {
	psk := DerivePSK("bear:hunter2")

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	wrapped := WrapPacketConn(srv, FilterConfig{Secrets: map[string][]byte{"bear": psk}})
	defer wrapped.Close()

	oobConn, ok := wrapped.(quic.OOBCapablePacketConn)
	require.True(t, ok)

	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer cli.Close()

	// A probe first, then a real client. Only the second may ever surface.
	_, err = cli.Write(initialPacket([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	require.NoError(t, err)
	dcid, err := GenerateDCID(psk, net.ParseIP("203.0.113.7"), 0)
	require.NoError(t, err)
	_, err = cli.Write(initialPacket(dcid))
	require.NoError(t, err)

	require.NoError(t, srv.SetReadDeadline(time.Now().Add(5*time.Second)))
	b := make([]byte, 1500)
	oob := make([]byte, 1024)
	n, _, _, _, err := oobConn.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	assert.Equal(t, initialPacket(dcid), b[:n],
		"the probe must be swallowed; only the authenticated packet reaches quic-go")
}

// The decoy answers a probe on the same socket the probe hit, so on a server
// holding two addresses it must answer from the one that was dialled. Getting
// that wrong is not a broken relay so much as a broken disguise: an observer
// comparing both addresses sees a reply arrive from one it never contacted,
// which no ordinary web server does.
func TestReplySourceOOB(t *testing.T) {
	assert.Nil(t, replySourceOOB(nil), "no control message, nothing to pin")
	assert.Nil(t, replySourceOOB([]byte{}), "empty control message")
	// Not a cmsg. Must be refused rather than passed to the kernel or panicked on.
	assert.Nil(t, replySourceOOB([]byte{0xde, 0xad, 0xbe, 0xef}))
}

// oobRecorder stands in for the raw socket so the relay's choice of write path
// is observable without a multi-homed host to test on.
type oobRecorder struct {
	net.PacketConn
	msgOOB  []byte
	msgAddr *net.UDPAddr
	plain   int
}

func (o *oobRecorder) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	o.msgOOB = append([]byte(nil), oob...)
	o.msgAddr = addr
	return len(b), len(oob), nil
}

func (o *oobRecorder) WriteTo(b []byte, _ net.Addr) (int, error) {
	o.plain++
	return len(b), nil
}

func TestUDPRelay_WriteBackPrefersThePinnedSource(t *testing.T) {
	rec := &oobRecorder{}
	r := &UDPRelay{conn: rec, oobConn: rec}
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 5000}

	// With a control message, the answer goes back pinned to it.
	r.writeBack([]byte("hi"), src, []byte{1, 2, 3, 4})
	assert.Equal(t, []byte{1, 2, 3, 4}, rec.msgOOB)
	assert.Equal(t, src, rec.msgAddr)
	assert.Zero(t, rec.plain)

	// Without one there is nothing to pin, and an ordinary write is correct
	// rather than a silent drop.
	r.writeBack([]byte("hi"), src, nil)
	assert.Equal(t, 1, rec.plain)
}

// A socket that cannot carry control messages must still relay.
func TestUDPRelay_WriteBackFallsBackWithoutAnOOBSocket(t *testing.T) {
	rec := &oobRecorder{}
	r := &UDPRelay{conn: rec} // oobConn deliberately nil
	r.writeBack([]byte("hi"), &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 5000}, []byte{1, 2, 3, 4})
	assert.Equal(t, 1, rec.plain)
	assert.Nil(t, rec.msgOOB)
}

// The guard for the crash this shape caused once. quic-go's newConn hands any
// OOB-capable conn that is NOT a batchConn to ipv4.NewPacketConn, which asserts
// its argument to net.Conn without checking and panics on a plain
// net.PacketConn -- and had it not panicked it would have read through the raw
// descriptor, leaving camouflage installed but never consulted.
//
// Satisfying batchConn is what keeps quic-go from going there at all.
var _ interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
} = (*filterUDP)(nil)

func TestFilterUDP_ReadBatchAppliesTheFilter(t *testing.T) {
	psk := DerivePSK("bear:hunter2")

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	wrapped := WrapPacketConn(srv, FilterConfig{Secrets: map[string][]byte{"bear": psk}})
	defer wrapped.Close()

	batch, ok := wrapped.(interface {
		ReadBatch(ms []ipv4.Message, flags int) (int, error)
	})
	require.True(t, ok, "must satisfy quic-go's batchConn or quic-go reads past the filter")

	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer cli.Close()

	_, err = cli.Write(initialPacket([]byte{1, 2, 3, 4, 5, 6, 7, 8})) // probe
	require.NoError(t, err)
	dcid, err := GenerateDCID(psk, net.ParseIP("203.0.113.7"), 0)
	require.NoError(t, err)
	_, err = cli.Write(initialPacket(dcid)) // real client
	require.NoError(t, err)

	require.NoError(t, srv.SetReadDeadline(time.Now().Add(5*time.Second)))
	ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 1500)}, OOB: make([]byte, 1024)}}
	n, err := batch.ReadBatch(ms, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Equal(t, initialPacket(dcid), ms[0].Buffers[0][:ms[0].N],
		"the probe must be swallowed on the batch path too")
	assert.NotNil(t, ms[0].Addr, "quic-go reads Addr straight off the message")
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h3"},
	}
}

// The end-to-end guard, and the one that would have caught the crash instead of
// letting a server find it. Everything else here asserts what quic-go is
// believed to do with this connection; this hands it to quic-go and lets it
// decide. Twice now that belief has been wrong -- first that satisfying
// OOBCapablePacketConn was enough, then that the OOB read path went through
// ReadMsgUDP -- and both times the compile-time assertions were perfectly happy.
func TestWrapPacketConn_QuicGoAcceptsTheWrappedConn(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	wrapped := WrapPacketConn(conn, FilterConfig{Secrets: map[string][]byte{"bear": DerivePSK("bear:hunter2")}})
	defer wrapped.Close()

	ln, err := quic.Listen(wrapped, testTLSConfig(t), nil)
	require.NoError(t, err)
	defer ln.Close()
}
