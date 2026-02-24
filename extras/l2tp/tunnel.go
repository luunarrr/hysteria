package l2tp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	maxPacketSize      = 4096
	defaultRecvWindow  = 4
	tunnelSetupTimeout = 10 * time.Second
)

var errTunnelClosed = errors.New("l2tp: tunnel closed")

// Tunnel represents an L2TPv2 tunnel to a single LNS.
type Tunnel struct {
	conn   net.Conn // UDP connection to LNS
	logger *zap.Logger

	localTunnelID  uint16
	remoteTunnelID uint16
	hostname       string
	secret         []byte
	helloInterval  time.Duration

	// Sequence numbers for reliable control delivery
	ns atomic.Uint32 // next send sequence number
	nr atomic.Uint32 // next expected receive sequence number

	// Session registry
	mu       sync.RWMutex
	sessions map[uint16]*Session
	nextSID  uint16

	// Serializes all packet writes to prevent interleaving
	writeMu sync.Mutex

	// Channel for routing control responses (ICRP/CDN) from recvLoop
	// to session establishment goroutines, avoiding a race on conn reads.
	pendingCtrl   chan controlMsg
	pendingCtrlMu sync.Mutex

	// Lifecycle
	closed    chan struct{}
	closeOnce sync.Once
	onClose   func() // callback to manager when tunnel dies
}

type controlMsg struct {
	avps    []AVP
	msgType uint16
}

func newTunnel(conn net.Conn, localTID uint16, hostname string, secret []byte, helloInterval time.Duration, logger *zap.Logger) *Tunnel {
	return &Tunnel{
		conn:          conn,
		logger:        logger,
		localTunnelID: localTID,
		hostname:      hostname,
		secret:        secret,
		helloInterval: helloInterval,
		sessions:      make(map[uint16]*Session),
		nextSID:       1,
		closed:        make(chan struct{}),
	}
}

// Establish performs the tunnel setup handshake (SCCRQ -> SCCRP -> SCCCN).
func (t *Tunnel) Establish() error {
	// Generate challenge if we have a secret
	var challenge []byte
	if len(t.secret) > 0 {
		challenge = make([]byte, 16)
		if _, err := rand.Read(challenge); err != nil {
			return fmt.Errorf("generate challenge: %w", err)
		}
	}

	payload := BuildSCCRQ(t.hostname, t.localTunnelID, defaultRecvWindow, challenge)
	t.logger.Debug("sending SCCRQ",
		zap.Uint16("tunnelID", t.localTunnelID),
		zap.String("hostname", t.hostname),
		zap.String("remoteAddr", t.conn.RemoteAddr().String()))
	if err := t.sendControl(0, 0, payload); err != nil {
		return fmt.Errorf("send SCCRQ: %w", err)
	}

	t.logger.Debug("waiting for SCCRP")
	avps, err := t.recvControlDirect(tunnelSetupTimeout)
	if err != nil {
		return fmt.Errorf("recv SCCRP: %w", err)
	}
	msgType, err := GetMessageType(avps)
	if err != nil {
		return err
	}
	if msgType == MsgTypeStopCCN {
		return fmt.Errorf("LNS rejected tunnel with StopCCN")
	}
	if msgType != MsgTypeSCCRP {
		return fmt.Errorf("expected SCCRP, got msg type %d", msgType)
	}

	// Extract Assigned Tunnel ID from SCCRP
	tidAVP := FindAVP(avps, 0, AVPAssignedTunnelID)
	if tidAVP == nil {
		return fmt.Errorf("%w: Assigned Tunnel ID in SCCRP", ErrMissingAVP)
	}
	remoteTID, err := AVPUint16(tidAVP)
	if err != nil {
		return err
	}
	t.remoteTunnelID = remoteTID

	t.logger.Debug("received SCCRP",
		zap.Uint16("remoteTunnelID", remoteTID))

	// Handle tunnel authentication
	var challengeResponse []byte
	if len(t.secret) > 0 {
		// Check for Challenge in SCCRP (LNS may challenge us)
		lnsChallenge := FindAVP(avps, 0, AVPChallenge)
		if lnsChallenge != nil {
			// Respond with MD5(SCCCN_type + secret + LNS_challenge)
			challengeResponse = ComputeChallengeResponse(byte(MsgTypeSCCCN), t.secret, lnsChallenge.Value)
		}

		// Verify LNS's Challenge Response if we sent a challenge
		lnsCR := FindAVP(avps, 0, AVPChallengeResponse)
		if lnsCR == nil {
			return fmt.Errorf("LNS did not respond to our challenge")
		}
		expected := ComputeChallengeResponse(byte(MsgTypeSCCRP), t.secret, challenge)
		if len(lnsCR.Value) != len(expected) {
			return fmt.Errorf("invalid challenge response from LNS")
		}
		for i := range expected {
			if lnsCR.Value[i] != expected[i] {
				return fmt.Errorf("invalid challenge response from LNS")
			}
		}
	}

	// Send SCCCN
	t.logger.Debug("sending SCCCN",
		zap.Uint16("remoteTunnelID", t.remoteTunnelID))
	scccnPayload := BuildSCCCN(challengeResponse)
	if err := t.sendControl(t.remoteTunnelID, 0, scccnPayload); err != nil {
		return fmt.Errorf("send SCCCN: %w", err)
	}

	t.logger.Debug("tunnel handshake complete, starting background loops")
	go t.recvLoop()
	if t.helloInterval > 0 {
		go t.helloLoop()
	}

	return nil
}

// CreateSession creates a new L2TP session on this tunnel.
func (t *Tunnel) CreateSession(info *ProxyInfo, callingNumber string) (*Session, error) {
	t.mu.Lock()
	sid := t.nextSID
	t.nextSID++
	s := newSession(t, sid, info, callingNumber)
	t.sessions[sid] = s
	t.mu.Unlock()

	if err := s.establish(); err != nil {
		t.mu.Lock()
		delete(t.sessions, sid)
		t.mu.Unlock()
		return nil, err
	}
	return s, nil
}

// removeSession removes a session from the registry.
// Returns the number of remaining sessions.
func (t *Tunnel) removeSession(sid uint16) int {
	t.mu.Lock()
	delete(t.sessions, sid)
	remaining := len(t.sessions)
	t.mu.Unlock()
	return remaining
}

// SessionCount returns the number of active sessions.
func (t *Tunnel) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// Close sends StopCCN and tears down the tunnel.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		close(t.closed)
		// Best-effort StopCCN
		payload := BuildStopCCN(t.localTunnelID, 1, 0, "LAC shutting down")
		_ = t.sendControl(t.remoteTunnelID, 0, payload)
		t.conn.Close()
		t.closeAllSessions()
	})
}

// Alive returns true if the tunnel has not been closed.
func (t *Tunnel) Alive() bool {
	select {
	case <-t.closed:
		return false
	default:
		return true
	}
}

func (t *Tunnel) closeAllSessions() {
	t.mu.Lock()
	sessions := make([]*Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		sessions = append(sessions, s)
	}
	t.mu.Unlock()
	for _, s := range sessions {
		s.closeDueToTunnel()
	}
}

func (t *Tunnel) sendControl(tunnelID, sessionID uint16, payload []byte) error {
	ns := uint16(t.ns.Add(1) - 1)
	nr := uint16(t.nr.Load())
	hdr := EncodeControlHeader(tunnelID, sessionID, ns, nr, len(payload))
	pkt := append(hdr, payload...)
	return t.writePacket(pkt)
}

// sendZLB sends a Zero-Length Body acknowledgment.
func (t *Tunnel) sendZLB() {
	nr := uint16(t.nr.Load())
	ns := uint16(t.ns.Load())
	hdr := EncodeControlHeader(t.remoteTunnelID, 0, ns, nr, 0)
	_ = t.writePacket(hdr)
}

func (t *Tunnel) writePacket(pkt []byte) error {
	select {
	case <-t.closed:
		return errTunnelClosed
	default:
	}
	t.writeMu.Lock()
	_, err := t.conn.Write(pkt)
	t.writeMu.Unlock()
	return err
}

// SendData sends a data packet for a session.
func (t *Tunnel) SendData(sessionID uint16, proto uint16, payload []byte) error {
	hdr := EncodeDataHeader(t.remoteTunnelID, sessionID)
	protoBuf := []byte{byte(proto >> 8), byte(proto & 0xFF)}
	pkt := make([]byte, 0, len(hdr)+2+len(payload))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, protoBuf...)
	pkt = append(pkt, payload...)
	return t.writePacket(pkt)
}

// recvControlDirect reads one control message with a deadline.
// Used ONLY during tunnel handshake before recvLoop starts.
func (t *Tunnel) recvControlDirect(timeout time.Duration) ([]AVP, error) {
	buf := make([]byte, maxPacketSize)
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	defer t.conn.SetReadDeadline(time.Time{})

	for {
		n, err := t.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		hdr, off, err := DecodeHeader(buf[:n])
		if err != nil {
			continue
		}
		if !hdr.IsControl {
			continue
		}
		t.nr.Store(uint32(hdr.Ns + 1))
		t.sendZLB()

		if off >= n {
			continue
		}
		avps, err := DecodeAVPs(buf[off:n])
		if err != nil {
			return nil, fmt.Errorf("decode AVPs: %w", err)
		}
		return avps, nil
	}
}

// recvControlViaLoop waits for a control message routed through recvLoop.
// Used during session establishment after recvLoop is running.
func (t *Tunnel) recvControlViaLoop(timeout time.Duration) ([]AVP, uint16, error) {
	ch := make(chan controlMsg, 1)
	t.pendingCtrlMu.Lock()
	t.pendingCtrl = ch
	t.pendingCtrlMu.Unlock()

	defer func() {
		t.pendingCtrlMu.Lock()
		t.pendingCtrl = nil
		t.pendingCtrlMu.Unlock()
	}()

	select {
	case msg := <-ch:
		return msg.avps, msg.msgType, nil
	case <-time.After(timeout):
		return nil, 0, fmt.Errorf("timeout waiting for control response")
	case <-t.closed:
		return nil, 0, errTunnelClosed
	}
}

// recvLoop is the main receive loop for the tunnel.
// It demuxes packets to sessions and handles control messages.
func (t *Tunnel) recvLoop() {
	buf := make([]byte, maxPacketSize)
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		if t.helloInterval > 0 {
			t.conn.SetReadDeadline(time.Now().Add(t.helloInterval * 3))
		}
		n, err := t.conn.Read(buf)
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			t.logger.Warn("tunnel read error, closing",
				zap.Uint16("tunnelID", t.localTunnelID),
				zap.Error(err))
			t.die()
			return
		}
		hdr, off, err := DecodeHeader(buf[:n])
		if err != nil {
			continue
		}

		if hdr.IsControl {
			t.handleControl(hdr, buf[off:n])
		} else {
			t.handleData(hdr, buf[off:n])
		}
	}
}

func (t *Tunnel) handleControl(hdr Header, payload []byte) {
	if len(payload) == 0 {
		return // ZLB ack from peer; don't update Nr (ZLB Ns is not incremented)
	}

	// Acknowledge non-ZLB control messages
	t.nr.Store(uint32(hdr.Ns + 1))
	t.sendZLB()

	avps, err := DecodeAVPs(payload)
	if err != nil {
		t.logger.Debug("failed to decode control AVPs", zap.Error(err))
		return
	}
	msgType, err := GetMessageType(avps)
	if err != nil {
		t.logger.Debug("failed to get message type", zap.Error(err))
		return
	}

	// If session establishment is waiting for a response, route it there.
	if msgType == MsgTypeICRP || msgType == MsgTypeCDN {
		t.pendingCtrlMu.Lock()
		ch := t.pendingCtrl
		t.pendingCtrlMu.Unlock()
		if ch != nil {
			select {
			case ch <- controlMsg{avps: avps, msgType: msgType}:
				if msgType == MsgTypeICRP {
					return
				}
			default:
			}
		}
	}

	switch msgType {
	case MsgTypeStopCCN:
		logFields := []zap.Field{zap.Uint16("tunnelID", t.localTunnelID)}
		if rcAVP := FindAVP(avps, 0, AVPResultCode); rcAVP != nil && len(rcAVP.Value) >= 2 {
			resultCode := binary.BigEndian.Uint16(rcAVP.Value[0:2])
			logFields = append(logFields, zap.Uint16("resultCode", resultCode))
			if len(rcAVP.Value) >= 4 {
				errorCode := binary.BigEndian.Uint16(rcAVP.Value[2:4])
				logFields = append(logFields, zap.Uint16("errorCode", errorCode))
			}
			if len(rcAVP.Value) > 4 {
				logFields = append(logFields, zap.String("errorMsg", string(rcAVP.Value[4:])))
			}
		}
		t.logger.Warn("received StopCCN from LNS", logFields...)
		t.die()
	case MsgTypeHello:
		// Hello is just acknowledged (ZLB already sent above)
	case MsgTypeCDN:
		t.handleCDN(avps)
	default:
		t.logger.Debug("unhandled control message",
			zap.Uint16("type", msgType),
			zap.Uint16("tunnelID", t.localTunnelID))
	}
}

func (t *Tunnel) handleCDN(avps []AVP) {
	sidAVP := FindAVP(avps, 0, AVPAssignedSessionID)
	if sidAVP == nil {
		return
	}
	sid, err := AVPUint16(sidAVP)
	if err != nil {
		return
	}
	t.mu.RLock()
	s, ok := t.sessions[sid]
	t.mu.RUnlock()
	if ok {
		s.closeDueToLNS()
	}
}

func (t *Tunnel) handleData(hdr Header, payload []byte) {
	if len(payload) < 2 {
		return
	}
	t.mu.RLock()
	s, ok := t.sessions[hdr.Session]
	t.mu.RUnlock()
	if !ok {
		return
	}
	// Some LNS implementations include FF 03 address/control in data packets
	off := 0
	if len(payload) >= 4 && payload[0] == 0xFF && payload[1] == 0x03 {
		off = 2
	}
	if off+2 > len(payload) {
		return
	}
	proto := uint16(payload[off])<<8 | uint16(payload[off+1])
	s.deliverPPP(proto, payload[off+2:])
}

func (t *Tunnel) helloLoop() {
	ticker := time.NewTicker(t.helloInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.closed:
			return
		case <-ticker.C:
			payload := BuildHello()
			if err := t.sendControl(t.remoteTunnelID, 0, payload); err != nil {
				return
			}
		}
	}
}

func (t *Tunnel) die() {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.conn.Close()
		count := t.SessionCount()
		t.logger.Warn("tunnel died",
			zap.Uint16("tunnelID", t.localTunnelID),
			zap.Int("sessionCount", count))
		t.closeAllSessions()
		if t.onClose != nil {
			t.onClose()
		}
	})
}
