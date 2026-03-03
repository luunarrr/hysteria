package camouflage

import (
	"net"
	"sync"
	"time"
)

const (
	udpRelayBufSize    = 4096
	udpRelayIdleExpiry = 120 * time.Second
)

// UDPRelay forwards UDP packets between probe clients and the real destination.
// Each unique source address gets its own upstream connection.
type UDPRelay struct {
	destAddr *net.UDPAddr
	conn     net.PacketConn // the raw socket used to send responses back

	mu       sync.Mutex
	sessions map[string]*relaySession
	done     chan struct{}
}

type relaySession struct {
	upstream *net.UDPConn
	lastSeen time.Time
}

// NewUDPRelay creates a relay that forwards probe traffic to dest.
// conn is the raw UDP socket used for sending responses back to probes.
func NewUDPRelay(dest string, conn net.PacketConn) (*UDPRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return nil, err
	}
	r := &UDPRelay{
		destAddr: addr,
		conn:     conn,
		sessions: make(map[string]*relaySession),
		done:     make(chan struct{}),
	}
	go r.cleanupLoop()
	return r, nil
}

// RelayPacket sends a packet from src to the real destination and starts
// a reverse relay goroutine if this is a new source.
func (r *UDPRelay) RelayPacket(data []byte, src net.Addr) {
	key := src.String()

	r.mu.Lock()
	sess, ok := r.sessions[key]
	if ok {
		sess.lastSeen = time.Now()
		r.mu.Unlock()
		_, _ = sess.upstream.Write(data)
		return
	}

	upstream, err := net.DialUDP("udp", nil, r.destAddr)
	if err != nil {
		r.mu.Unlock()
		return
	}
	sess = &relaySession{upstream: upstream, lastSeen: time.Now()}
	r.sessions[key] = sess
	r.mu.Unlock()

	_, _ = upstream.Write(data)
	go r.reverseRelay(upstream, src, key)
}

func (r *UDPRelay) reverseRelay(upstream *net.UDPConn, src net.Addr, key string) {
	buf := make([]byte, udpRelayBufSize)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(udpRelayIdleExpiry))
		n, err := upstream.Read(buf)
		if err != nil {
			break
		}
		_, _ = r.conn.WriteTo(buf[:n], src)

		r.mu.Lock()
		if s, ok := r.sessions[key]; ok {
			s.lastSeen = time.Now()
		}
		r.mu.Unlock()
	}

	r.mu.Lock()
	if s, ok := r.sessions[key]; ok && s.upstream == upstream {
		delete(r.sessions, key)
	}
	r.mu.Unlock()
	_ = upstream.Close()
}

func (r *UDPRelay) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.mu.Lock()
			now := time.Now()
			for key, sess := range r.sessions {
				if now.Sub(sess.lastSeen) > udpRelayIdleExpiry {
					_ = sess.upstream.Close()
					delete(r.sessions, key)
				}
			}
			r.mu.Unlock()
		case <-r.done:
			return
		}
	}
}

// Close shuts down the relay and all upstream connections.
func (r *UDPRelay) Close() error {
	close(r.done)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sess := range r.sessions {
		_ = sess.upstream.Close()
	}
	r.sessions = nil
	return nil
}
