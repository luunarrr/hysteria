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
	udpRelayOOBSize    = 128
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

	// destECNOOB holds, per codepoint, the control message that reproduces a
	// probe's ECN marking on the copy forwarded to the decoy. There are only
	// four codepoints and the decoy's address family never changes, so these are
	// built once: the forward path is what a scanner floods, and it should not
	// allocate per packet to say something it has already said.
	destECNOOB [4][]byte

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
	destIsIPv4 := addr.IP.To4() != nil
	for bits := range r.destECNOOB {
		r.destECNOOB[bits] = appendECNOOB(nil, destIsIPv4, byte(bits))
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
//
// A reply does carry an ECN codepoint, but the decoy's and not the prober's:
// reverseRelay reads it off the decoy's answer and appends it to what this
// returns. The two are captured on different schedules, which is why they are
// not built together -- the local address is a property of the session and is
// read once, while the codepoint is a property of each packet.
func replySourceOOB(oob []byte) []byte {
	ip, ifIndex, v4, ok := localDstFromOOB(oob)
	if !ok {
		return nil
	}
	if v4 {
		return (&ipv4.ControlMessage{Src: ip, IfIndex: ifIndex}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: ip, IfIndex: ifIndex}).Marshal()
}

// localDstFromOOB reads, out of a received datagram's control message, which of
// this host's addresses the datagram was actually sent to.
//
// Two callers want the same field for different reasons: the relay answers a
// probe from the address it dialled, and the filter checks a client's token
// against the address it dialled. Both are asking "which of our addresses was
// this?", and the kernel is the only thing that knows.
//
// Parse leaves Dst nil rather than failing when the message carries no packet
// info for that family, so the nil check and not the error is what decides.
// v4 reports which family answered, because the two control messages are not
// interchangeable on the way back out.
//
// ok is false when there is no packet info to be had: the socket is bound to
// one address, so quic-go never asked the kernel for it, or the read came in
// over a path that carries no control message at all.
func localDstFromOOB(oob []byte) (ip net.IP, ifIndex int, v4, ok bool) {
	if len(oob) == 0 {
		return nil, 0, false, false
	}
	var cm4 ipv4.ControlMessage
	if err := cm4.Parse(oob); err == nil && cm4.Dst != nil {
		return cm4.Dst, cm4.IfIndex, true, true
	}
	var cm6 ipv6.ControlMessage
	if err := cm6.Parse(oob); err == nil && cm6.Dst != nil {
		return cm6.Dst, cm6.IfIndex, false, true
	}
	return nil, 0, false, false
}

// writeBack sends one decoy response to the probe, from the address it dialled
// where that is knowable and by the ordinary route where it is not.
//
// oob may carry a source, an ECN codepoint, or both, and the ordinary write is
// the fallback for having neither -- a socket that cannot take a control
// message cannot be told either thing.
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
// came in and carries the codepoint forwarded to the decoy; see replySourceOOB
// and upstreamECNOOB.
func (r *UDPRelay) RelayPacket(data []byte, src net.Addr, oob []byte) {
	key := src.String()
	ecnOOB := r.upstreamECNOOB(oob)

	r.mu.Lock()
	sess, ok := r.sessions[key]
	if ok {
		sess.lastSeen = time.Now()
		r.mu.Unlock()
		_, _, _ = sess.upstream.WriteMsgUDP(data, ecnOOB, nil)
		return
	}

	upstream, err := net.DialUDP("udp", nil, r.destAddr)
	if err != nil {
		r.mu.Unlock()
		return
	}
	enableECNRead(upstream)
	sess = &relaySession{
		upstream: upstream,
		lastSeen: time.Now(),
		replyOOB: replySourceOOB(oob),
	}
	r.sessions[key] = sess
	r.mu.Unlock()

	_, _, _ = upstream.WriteMsgUDP(data, ecnOOB, nil)
	go r.reverseRelay(upstream, src, key, sess.replyOOB)
}

// upstreamECNOOB is the control message that reproduces, on the copy sent to
// the decoy, the ECN codepoint the probe arrived with.
//
// The forward direction is not the obvious half of this, but it is the half a
// prober can check without measuring anything. A QUIC client marks its packets
// ECT(0) and the server reports back, in ACK frames, how many of each codepoint
// it counted; those counts travel as payload and so arrive intact either way.
// Relay the packets unmarked and the decoy honestly reports zero, the client's
// ECN validation fails, and a server that ought to have supported ECN is seen
// not to -- from data the decoy itself signed off on.
//
// nil when the read path gave no control message, which is a request to send
// the packet unmarked rather than to mark it Not-ECT; see parseECNBits.
func (r *UDPRelay) upstreamECNOOB(oob []byte) []byte {
	bits, ok := parseECNBits(oob)
	if !ok {
		return nil
	}
	return r.destECNOOB[bits]
}

// addrIsIPv4 picks which of the two ECN control messages an address wants.
// Mapped v4 addresses count as v4 even on a dual-stack socket, which is the
// same test quic-go applies for the same choice.
func addrIsIPv4(addr net.Addr) bool {
	ua, ok := addr.(*net.UDPAddr)
	return ok && ua.IP.To4() != nil
}

// reverseRelay carries the decoy's answers back to the probe.
//
// Read through ReadMsgUDP rather than Read so the decoy's own ECN marking is
// visible. A real QUIC server marks the packets it sends; stripping that on the
// way through would let a prober see, in a single packet and with no timing to
// measure, a server whose traffic arrives Not-ECT when the thing it claims to
// be marks ECT(0).
//
// The reply control message is rebuilt per packet from two parts on different
// schedules: the session's local address, fixed at the packet that opened it,
// and the codepoint, which belongs to this packet alone. replyBuf is sized for
// both up front so that neither the append nor the marking allocates.
func (r *UDPRelay) reverseRelay(upstream *net.UDPConn, src net.Addr, key string, replyOOB []byte) {
	buf := make([]byte, udpRelayBufSize)
	oobBuf := make([]byte, udpRelayOOBSize)
	replyBuf := make([]byte, 0, len(replyOOB)+ecnOOBSpace)
	srcIsIPv4 := addrIsIPv4(src)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(udpRelayIdleExpiry))
		n, oobn, _, _, err := upstream.ReadMsgUDP(buf, oobBuf)
		if err != nil {
			break
		}
		reply := replyOOB
		if bits, ok := parseECNBits(oobBuf[:oobn]); ok {
			replyBuf = append(replyBuf[:0], replyOOB...)
			replyBuf = appendECNOOB(replyBuf, srcIsIPv4, bits)
			reply = replyBuf
		}
		r.writeBack(buf[:n], src, reply)

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
