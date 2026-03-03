package camouflage

import (
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// AlertFunc is called when a suspicious event is detected.
// label identifies the matched secret partition (empty if no match).
type AlertFunc func(srcAddr net.Addr, reason, label string)

// FilterConfig configures the camouflage packet filter.
type FilterConfig struct {
	Secrets        map[string][]byte // label -> PSK
	ServerIP       net.IP            // nil = skip server_id check
	TimeBucketSize time.Duration     // 0 = DefaultTimeBucket
	RateLimiter    *RateLimiter
	UDPRelay       *UDPRelay
	AlertFunc      AlertFunc

	// RelayFunc, if set, is called for every packet handed to the decoy rather
	// than to quic-go. It exists because that decision is otherwise completely
	// silent: a client whose secret or address disagrees with this server is
	// treated exactly like a probe, so the operator sees an unreachable server
	// and the server sees nothing worth reporting. Called on the receive path
	// once per rejected packet, so it is meant for a debug-level log.
	RelayFunc func(srcAddr net.Addr, reason string)

	// IdleTimeout controls how long an authenticated source is remembered
	// after its last seen packet. Aligns with QUIC MaxIdleTimeout.
	IdleTimeout time.Duration
}

// Filter is a net.PacketConn wrapper that sits in front of quic-go.
// It verifies DCID-based authentication on Initial packets, tracks
// authenticated sources, and relays unrecognized traffic to a real server.
// Only used when Salamander is NOT configured.
type Filter struct {
	conn   net.PacketConn
	config FilterConfig

	// replay detection: DCID -> first source that used it
	replayMu     sync.Mutex
	replayMap    map[[DCIDLen]byte]string // DCID -> srcAddr string
	replayBucket uint64                   // current time bucket when map was last reset

	// authenticated source tracking
	authMu  sync.Mutex
	authSet map[string]time.Time // srcAddr string -> last seen

	done chan struct{}
}

// WrapPacketConn creates a camouflage filter wrapping conn.
// The returned net.PacketConn should be passed to quic.Listen.
func WrapPacketConn(conn net.PacketConn, config FilterConfig) net.PacketConn {
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 30 * time.Second
	}
	if config.TimeBucketSize <= 0 {
		config.TimeBucketSize = DefaultTimeBucket
	}
	f := &Filter{
		conn:      conn,
		config:    config,
		replayMap: make(map[[DCIDLen]byte]string),
		authSet:   make(map[string]time.Time),
		done:      make(chan struct{}),
	}
	go f.authCleanupLoop()
	if udpConn, ok := conn.(*net.UDPConn); ok {
		return &filterUDP{Filter: f, UDPConn: udpConn}
	}
	return f
}

// ReadFrom implements net.PacketConn. It reads from the underlying connection,
// applies the verification pipeline, and only returns packets destined for
// quic-go (accepted packets). Relayed/rejected packets are handled internally.
func (f *Filter) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := f.conn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		// No control message on this path: quic-go only calls ReadFrom when it
		// could not take the OOB path, and then there is no packet info to be
		// had. The decoy falls back to an ordinary write.
		if f.processPacket(p[:n], addr, nil) {
			return n, addr, nil
		}
	}
}

func (f *Filter) WriteTo(p []byte, addr net.Addr) (int, error) {
	return f.conn.WriteTo(p, addr)
}

func (f *Filter) Close() error {
	close(f.done)
	return f.conn.Close()
}

func (f *Filter) LocalAddr() net.Addr                { return f.conn.LocalAddr() }
func (f *Filter) SetDeadline(t time.Time) error      { return f.conn.SetDeadline(t) }
func (f *Filter) SetReadDeadline(t time.Time) error  { return f.conn.SetReadDeadline(t) }
func (f *Filter) SetWriteDeadline(t time.Time) error { return f.conn.SetWriteDeadline(t) }

// processPacket runs the full verification pipeline. Returns true if the
// packet should be delivered to quic-go, false if it was relayed/dropped.
//
// oob is the control message this packet arrived with, or nil. It is carried
// only so that a packet handed to the decoy can be answered from the address it
// was sent to; nothing in the verification itself looks at it.
func (f *Filter) processPacket(data []byte, src net.Addr, oob []byte) bool {
	srcKey := src.String()
	// The rate limiter counts per source IP while the auth set keys on the full
	// address. A 4-tuple is what identifies a QUIC connection, but it is also
	// free for a scanner to vary: keying failures the same way would hand every
	// probe packet a fresh counter that never reaches the threshold.
	rlKey := sourceIP(src)

	// Step 0: rate limit check
	if f.config.RateLimiter != nil && f.config.RateLimiter.IsRateLimited(rlKey) {
		f.relay(data, src, oob, "rate limited, not re-checked")
		return false
	}

	// Step 1: parse QUIC header
	dcid, isInitial, err := ParseDCID(data)
	if err != nil {
		f.recordFailure(rlKey)
		f.relay(data, src, oob, "unparseable QUIC header")
		return false
	}

	// Step 2: short-header packets -> check auth set
	if !isInitial {
		if dcid == nil {
			// Short header
			if f.isAuthenticated(srcKey) {
				return true
			}
			f.recordFailure(rlKey)
			f.relay(data, src, oob, "short header from an unauthenticated source")
			return false
		}
		// Long header but not Initial (Handshake, 0-RTT) from known source
		if f.isAuthenticated(srcKey) {
			return true
		}
		f.relay(data, src, oob, "non-Initial long header from an unauthenticated source")
		return false
	}

	// Step 3: Initial packet -> DCID verification
	result := VerifyDCID(f.config.Secrets, f.config.ServerIP, dcid, f.config.TimeBucketSize)

	if !result.Matched() {
		f.recordFailure(rlKey)
		f.relay(data, src, oob, "no configured secret matches the token")
		return false
	}

	// HMAC matched, so this is a holder of a real credential rather than a
	// probe. Name the configuration first: a token minted against a different
	// address is overwhelmingly a serverAddr that is not the address clients
	// actually reach, and only then a token replayed from another server.
	if !result.ServerIDMatch {
		if f.config.AlertFunc != nil {
			f.config.AlertFunc(src, "valid credential, but the token was minted against a different address -- check that serverAddr is the address clients reach this server at (otherwise: cross-server replay)", result.Label)
		}
		f.recordFailure(rlKey)
		f.relay(data, src, oob, "token minted against a different address")
		return false
	}

	// Step 4: replay detection
	var dcidKey [DCIDLen]byte
	copy(dcidKey[:], dcid)

	if f.isReplay(dcidKey, srcKey) {
		if f.config.AlertFunc != nil {
			f.config.AlertFunc(src, "DCID replay from different source", result.Label)
		}
		f.recordFailure(rlKey)
		f.relay(data, src, oob, "token already used by a different source")
		return false
	}

	// All checks passed -- authenticate this source
	f.markAuthenticated(srcKey)
	return true
}

func (f *Filter) relay(data []byte, src net.Addr, oob []byte, reason string) {
	if f.config.RelayFunc != nil {
		f.config.RelayFunc(src, reason)
	}
	if f.config.UDPRelay != nil {
		f.config.UDPRelay.RelayPacket(data, src, oob)
	}
}

func (f *Filter) recordFailure(srcIP string) {
	if f.config.RateLimiter != nil {
		f.config.RateLimiter.RecordFailure(srcIP)
	}
}

// sourceIP strips the port from a packet source, so failure counting survives
// a peer that varies it.
func sourceIP(addr net.Addr) string {
	if ua, ok := addr.(*net.UDPAddr); ok && ua.IP != nil {
		return ua.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (f *Filter) isAuthenticated(src string) bool {
	f.authMu.Lock()
	defer f.authMu.Unlock()
	t, ok := f.authSet[src]
	if ok {
		f.authSet[src] = time.Now()
		return time.Since(t) < f.config.IdleTimeout
	}
	return false
}

func (f *Filter) markAuthenticated(src string) {
	f.authMu.Lock()
	f.authSet[src] = time.Now()
	f.authMu.Unlock()
}

func (f *Filter) isReplay(dcidKey [DCIDLen]byte, srcKey string) bool {
	f.replayMu.Lock()
	defer f.replayMu.Unlock()

	curBucket := currentTimeBucket(f.config.TimeBucketSize)
	if curBucket != f.replayBucket {
		// Bucket rotated -- flush old entries
		f.replayMap = make(map[[DCIDLen]byte]string)
		f.replayBucket = curBucket
	}

	prev, ok := f.replayMap[dcidKey]
	if !ok {
		f.replayMap[dcidKey] = srcKey
		return false
	}
	return prev != srcKey
}

func (f *Filter) authCleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f.authMu.Lock()
			now := time.Now()
			for src, t := range f.authSet {
				if now.Sub(t) > f.config.IdleTimeout {
					delete(f.authSet, src)
				}
			}
			f.authMu.Unlock()
		case <-f.done:
			return
		}
	}
}

// filterUDP is what WrapPacketConn returns when the connection underneath is a
// real UDP socket, and the whole of its job is to keep quic-go on its
// out-of-band path.
//
// quic-go decides that once, at listener setup, by type assertion:
//
//	c, ok := pc.(OOBCapablePacketConn)
//	if !ok {
//		utils.DefaultLogger.Infof("PacketConn is not a net.UDPConn. ...")
//		return &basicConn{PacketConn: pc, supportsDF: supportsDF}, nil
//	}
//
// Landing on basicConn costs far more than "disabling optimizations" suggests.
// Without OOB there is no IP_PKTINFO, so quic-go never learns which local
// address a datagram arrived on and cannot send the reply from it; the kernel
// picks a source by route instead. On a single-homed server that is invisible,
// because the only available source is the right one. On a server holding two
// addresses it is fatal and completely silent -- a client dialling the second
// address receives answers from the first, discards them as coming from the
// wrong peer, and reports a timeout, while the server logs a healthy session
// throughout. Worse, the wrong source also stops the reply matching its own
// conntrack entry, so any policy routing keyed on a connection mark quietly
// stops applying too.
//
// A Multilink PPP bundle is that topology by construction: every link crosses a
// different concentrator address, so the deployment this feature exists to
// protect is precisely the one it breaks.
//
// UDPConn is a named field rather than embedded, deliberately. Embedding both
// it and *Filter would put ReadFrom, WriteTo, Close and the deadline setters at
// equal depth from two types, and Go then promotes neither -- the result
// satisfies net.PacketConn no better than it satisfies OOBCapablePacketConn.
type filterUDP struct {
	*Filter
	UDPConn *net.UDPConn
}

// SyscallConn exposes the raw socket, and the signature is the load-bearing
// part. quic-go asserts for "SyscallConn() (syscall.RawConn, error)" precisely;
// an earlier version of this returned (interface{}, error), which matches that
// assertion no better than having no method at all while reading, at a glance,
// as though the raw socket had been handed over.
func (f *filterUDP) SyscallConn() (syscall.RawConn, error) {
	return f.UDPConn.SyscallConn()
}

// SetReadBuffer and SetWriteBuffer are part of the same bargain: quic-go sizes
// the socket buffers through whichever of them the connection exposes, and a
// wrapper that hides them leaves the kernel defaults in place.
func (f *filterUDP) SetReadBuffer(bytes int) error  { return f.UDPConn.SetReadBuffer(bytes) }
func (f *filterUDP) SetWriteBuffer(bytes int) error { return f.UDPConn.SetWriteBuffer(bytes) }

// ReadMsgUDP is the out-of-band read path, and it runs the same verification
// ReadFrom does.
//
// Forwarding it straight to the socket is the obvious implementation and would
// disable camouflage outright: once quic-go has taken the OOB path it never
// calls ReadFrom again, so every probe would arrive at the QUIC stack
// unexamined while the filter sat in the call chain looking installed. The two
// read paths have to agree about what is allowed through, because which one is
// in use is quic-go's choice and not visible from here.
func (f *filterUDP) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	for {
		n, oobn, flags, addr, err = f.UDPConn.ReadMsgUDP(b, oob)
		if err != nil {
			return n, oobn, flags, addr, err
		}
		if f.Filter.processPacket(b[:n], addr, oob[:oobn]) {
			return n, oobn, flags, addr, nil
		}
	}
}

// WriteMsgUDP carries the control message quic-go built, which is where the
// source address for this reply is set -- the entire point of the exercise.
// Nothing is filtered on the way out; the send path has never been.
func (f *filterUDP) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return f.UDPConn.WriteMsgUDP(b, oob, addr)
}

// ReadBatch is how quic-go actually reads once it is on the OOB path, and
// implementing it is what keeps this filter in that path at all.
//
// oobConn.ReadPacket calls batchConn.ReadBatch and never ReadMsgUDP, so the
// obvious reading -- that satisfying OOBCapablePacketConn is enough -- is wrong.
// A conn that is OOB-capable but not a batchConn gets handed to
// ipv4.NewPacketConn instead, and that costs twice over:
//
//   - it reads through the raw file descriptor, so every packet would arrive at
//     the QUIC stack unexamined and camouflage would be off while still looking
//     installed, and
//   - it type-asserts its argument to net.Conn without checking
//     (x/net ipv4/endpoint.go: "socket.NewConn(c.(net.Conn))"), which a filter
//     that is only a net.PacketConn does not satisfy, so it panics at listener
//     setup before reaching the first of those.
//
// The panic is the reason this is written down. It is also why nothing here
// implements net.Conn to make that assertion succeed: a Read method that did
// not filter would turn a crash on the first packet into a filter that is
// quietly not there, and of the two, the crash is the one an operator can act
// on.
//
// One message per call rather than a real batch. The syscall amortisation is
// the whole point of batching and it is not available here -- verification is
// per packet, and reading a batch straight from the descriptor is precisely
// what must not happen. A server running camouflage already pays a per-packet
// cost for existing.
func (f *filterUDP) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if len(ms) == 0 || len(ms[0].Buffers) == 0 {
		return 0, nil
	}
	m := &ms[0]
	n, oobn, _, addr, err := f.ReadMsgUDP(m.Buffers[0], m.OOB)
	if err != nil {
		return 0, err
	}
	m.N = n
	m.NN = oobn
	m.Addr = addr
	return 1, nil
}
