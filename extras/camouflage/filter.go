package camouflage

import (
	"net"
	"sync"
	"time"
)

// AlertFunc is called when a suspicious event is detected.
// label identifies the matched secret partition (empty if no match).
type AlertFunc func(srcAddr net.Addr, reason string, label string)

// FilterConfig configures the camouflage packet filter.
type FilterConfig struct {
	Secrets        map[string][]byte // label -> PSK
	ServerIP       net.IP            // nil = skip server_id check
	TimeBucketSize time.Duration     // 0 = DefaultTimeBucket
	RateLimiter    *RateLimiter
	UDPRelay       *UDPRelay
	AlertFunc      AlertFunc

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
	replayBucket uint64                  // current time bucket when map was last reset

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
		if f.processPacket(p[:n], addr) {
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

func (f *Filter) LocalAddr() net.Addr              { return f.conn.LocalAddr() }
func (f *Filter) SetDeadline(t time.Time) error     { return f.conn.SetDeadline(t) }
func (f *Filter) SetReadDeadline(t time.Time) error  { return f.conn.SetReadDeadline(t) }
func (f *Filter) SetWriteDeadline(t time.Time) error { return f.conn.SetWriteDeadline(t) }

// processPacket runs the full verification pipeline. Returns true if the
// packet should be delivered to quic-go, false if it was relayed/dropped.
func (f *Filter) processPacket(data []byte, src net.Addr) bool {
	srcKey := src.String()

	// Step 0: rate limit check
	if f.config.RateLimiter != nil && f.config.RateLimiter.IsRateLimited(srcKey) {
		f.relay(data, src)
		return false
	}

	// Step 1: parse QUIC header
	dcid, isInitial, err := ParseDCID(data)
	if err != nil {
		f.recordFailure(srcKey)
		f.relay(data, src)
		return false
	}

	// Step 2: short-header packets -> check auth set
	if !isInitial {
		if dcid == nil {
			// Short header
			if f.isAuthenticated(srcKey) {
				return true
			}
			f.recordFailure(srcKey)
			f.relay(data, src)
			return false
		}
		// Long header but not Initial (Handshake, 0-RTT) from known source
		if f.isAuthenticated(srcKey) {
			return true
		}
		f.relay(data, src)
		return false
	}

	// Step 3: Initial packet -> DCID verification
	result := VerifyDCID(f.config.Secrets, f.config.ServerIP, dcid, f.config.TimeBucketSize)

	if !result.Matched() {
		f.recordFailure(srcKey)
		f.relay(data, src)
		return false
	}

	// HMAC matched
	if !result.ServerIDMatch {
		if f.config.AlertFunc != nil {
			f.config.AlertFunc(src, "server_id mismatch (cross-server replay?)", result.Label)
		}
		f.recordFailure(srcKey)
		f.relay(data, src)
		return false
	}

	// Step 4: replay detection
	var dcidKey [DCIDLen]byte
	copy(dcidKey[:], dcid)

	if f.isReplay(dcidKey, srcKey) {
		if f.config.AlertFunc != nil {
			f.config.AlertFunc(src, "DCID replay from different source", result.Label)
		}
		f.recordFailure(srcKey)
		f.relay(data, src)
		return false
	}

	// All checks passed -- authenticate this source
	f.markAuthenticated(srcKey)
	return true
}

func (f *Filter) relay(data []byte, src net.Addr) {
	if f.config.UDPRelay != nil {
		f.config.UDPRelay.RelayPacket(data, src)
	}
}

func (f *Filter) recordFailure(src string) {
	if f.config.RateLimiter != nil {
		f.config.RateLimiter.RecordFailure(src)
	}
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

// filterUDP preserves the raw *net.UDPConn so quic-go can use
// UDP-specific optimizations (SyscallConn, batch reads, etc.).
type filterUDP struct {
	*Filter
	UDPConn *net.UDPConn
}

// SyscallConn exposes the raw socket for quic-go optimizations.
func (f *filterUDP) SyscallConn() (interface{}, error) {
	return f.UDPConn.SyscallConn()
}
