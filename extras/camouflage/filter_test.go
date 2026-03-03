package camouflage

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
		assert.False(t, f.processPacket(packet, src), "unauthenticated packet must not reach quic-go")
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
	assert.True(t, f.processPacket(initialPacket(dcid), src))

	// The source is now authenticated, so its short-header packets pass too.
	assert.True(t, f.processPacket([]byte{0x40, 0xAA, 0xBB}, src))
	// A different source is not.
	other := &net.UDPAddr{IP: net.ParseIP("198.51.100.5"), Port: 5000}
	assert.False(t, f.processPacket([]byte{0x40, 0xAA, 0xBB}, other))
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
	assert.False(t, f.processPacket(initialPacket(elsewhere), src))

	assert.False(t, f.processPacket(initialPacket([]byte{1, 2, 3, 4, 5, 6, 7, 8}), src))
	assert.False(t, f.processPacket([]byte{0x40, 0xAA}, src))
	assert.False(t, f.processPacket([]byte{}, src))

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
	assert.True(t, f.processPacket(initialPacket(ok), src))
	assert.Empty(t, got)
}
