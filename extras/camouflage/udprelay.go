package camouflage

import (
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	udpRelayBufSize    = 4096
	udpRelayIdleExpiry = 120 * time.Second
)

// oobWriter is a socket that can send a control message alongside a datagram.
// A real *net.UDPConn is one; anything wrapping it without forwarding this
// method is not, and the relay falls back to an ordinary write.
type oobWriter interface {
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

// UDPRelay forwards UDP packets between probe clients and the real destination.
// Each unique source address gets its own upstream connection.
type UDPRelay struct {
	destAddr *net.UDPAddr
	conn     net.PacketConn // the raw socket used to send responses back
	oobConn  oobWriter      // conn again when it can pin a reply's source, else nil

	mu       sync.Mutex
	sessions map[string]*relaySession
	done     chan struct{}
}

type relaySession struct {
	upstream *net.UDPConn
	lastSeen time.Time

	// replyOOB pins the decoy's answers to the local address and interface the
	// probe arrived on. Captured once, from the packet that opened the session:
	// sessions are keyed by source address, so every packet in one is the same
	// conversation arriving the same way.
	replyOOB []byte
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
	if w, ok := conn.(oobWriter); ok {
		r.oobConn = w
	}
	go r.cleanupLoop()
	return r, nil
}

// replySourceOOB turns the control message a probe arrived with into one that
// answers from the same local address and out of the same interface.
//
// It matters more here than anywhere else in this package. A server holding two
// addresses answers by whatever source the route table picks, so a probe sent to
// the second address gets its decoy response from the first -- and an observer
// comparing the two addresses sees a reply from somewhere it never dialled,
// which no ordinary web server does. The disguise is what leaks, which is the
// one failure this package exists to prevent.
//
// The local address is taken from ipi_addr, the header destination, rather than
// ipi_spec_dst -- the same field quic-go reads for the same purpose.
//
// Deliberately not the received buffer echoed back verbatim. That also carries
// the IP_TOS message quic-go's ECN request puts there, and returning a prober's
// own TOS to it is a behaviour nobody chose. Only the packet info crosses over.
func replySourceOOB(oob []byte) []byte {
	if len(oob) == 0 {
		return nil
	}
	var cm4 ipv4.ControlMessage
	if err := cm4.Parse(oob); err == nil && cm4.Dst != nil {
		return (&ipv4.ControlMessage{Src: cm4.Dst, IfIndex: cm4.IfIndex}).Marshal()
	}
	var cm6 ipv6.ControlMessage
	if err := cm6.Parse(oob); err == nil && cm6.Dst != nil {
		return (&ipv6.ControlMessage{Src: cm6.Dst, IfIndex: cm6.IfIndex}).Marshal()
	}
	return nil
}

// writeBack sends one decoy response to the probe, from the address it dialled
// where that is knowable and by the ordinary route where it is not.
func (r *UDPRelay) writeBack(b []byte, src net.Addr, oob []byte) {
	if r.oobConn != nil && len(oob) > 0 {
		if ua, ok := src.(*net.UDPAddr); ok {
			_, _, _ = r.oobConn.WriteMsgUDP(b, oob, ua)
			return
		}
	}
	_, _ = r.conn.WriteTo(b, src)
}

// RelayPacket sends a packet from src to the real destination and starts
// a reverse relay goroutine if this is a new source.
//
// oob is the control message the packet arrived with, empty when the read path
// had none to give. It is what lets the answer go back out the way the probe
// came in; see replySourceOOB.
func (r *UDPRelay) RelayPacket(data []byte, src net.Addr, oob []byte) {
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
	sess = &relaySession{
		upstream: upstream,
		lastSeen: time.Now(),
		replyOOB: replySourceOOB(oob),
	}
	r.sessions[key] = sess
	r.mu.Unlock()

	_, _ = upstream.Write(data)
	go r.reverseRelay(upstream, src, key, sess.replyOOB)
}

func (r *UDPRelay) reverseRelay(upstream *net.UDPConn, src net.Addr, key string, replyOOB []byte) {
	buf := make([]byte, udpRelayBufSize)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(udpRelayIdleExpiry))
		n, err := upstream.Read(buf)
		if err != nil {
			break
		}
		r.writeBack(buf[:n], src, replyOOB)

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
