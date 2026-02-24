package l2tp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

var errSessionClosed = errors.New("l2tp: session closed")

// Session represents an L2TP session within a tunnel.
type Session struct {
	tunnel *Tunnel
	logger *zap.Logger

	localSessionID  uint16
	remoteSessionID uint16
	callSerial      uint32
	callingNumber   string
	info            *ProxyInfo

	// Channel for receiving PPP frames from the tunnel's demux loop
	recvCh chan pppFrame

	closed    chan struct{}
	closeOnce sync.Once
}

type pppFrame struct {
	Proto   uint16
	Payload []byte
}

var callSerialCounter atomic.Uint32

func newSession(t *Tunnel, localSID uint16, info *ProxyInfo, callingNumber string) *Session {
	return &Session{
		tunnel:         t,
		logger:         t.logger,
		localSessionID: localSID,
		callSerial:     callSerialCounter.Add(1),
		callingNumber:  callingNumber,
		info:           info,
		recvCh:         make(chan pppFrame, 256),
		closed:         make(chan struct{}),
	}
}

// establish performs the ICRQ -> ICRP -> ICCN handshake.
// Uses recvControlViaLoop so the ICRP is delivered by recvLoop,
// avoiding a race between two concurrent readers on the same conn.
func (s *Session) establish() error {
	s.logger.Debug("sending ICRQ",
		zap.Uint16("localSessionID", s.localSessionID),
		zap.Uint32("callSerial", s.callSerial),
		zap.String("callingNumber", s.callingNumber))

	icrqPayload := BuildICRQ(s.localSessionID, s.callSerial, s.callingNumber)
	if err := s.tunnel.sendControl(s.tunnel.remoteTunnelID, 0, icrqPayload); err != nil {
		return fmt.Errorf("send ICRQ: %w", err)
	}

	s.logger.Debug("waiting for ICRP")
	avps, msgType, err := s.tunnel.recvControlViaLoop(tunnelSetupTimeout)
	if err != nil {
		return fmt.Errorf("recv ICRP: %w", err)
	}
	if msgType == MsgTypeCDN {
		return fmt.Errorf("LNS rejected session with CDN")
	}
	if msgType != MsgTypeICRP {
		return fmt.Errorf("expected ICRP, got msg type %d", msgType)
	}

	sidAVP := FindAVP(avps, 0, AVPAssignedSessionID)
	if sidAVP == nil {
		return fmt.Errorf("%w: Assigned Session ID in ICRP", ErrMissingAVP)
	}
	remoteSID, err := AVPUint16(sidAVP)
	if err != nil {
		return err
	}
	s.remoteSessionID = remoteSID

	s.logger.Debug("received ICRP",
		zap.Uint16("remoteSessionID", remoteSID))

	iccnPayload := BuildICCN(s.info)
	s.logger.Debug("sending ICCN with proxy info",
		zap.Uint16("remoteSessionID", s.remoteSessionID),
		zap.String("username", s.info.AuthName),
		zap.String("lastSentCONFREQ", hex.EncodeToString(s.info.LastSentCONFREQ)),
		zap.String("lastRecvCONFREQ", hex.EncodeToString(s.info.LastReceivedCONFREQ)),
		zap.Int("iccnLen", len(iccnPayload)),
		zap.String("iccnHex", hex.EncodeToString(iccnPayload)))
	if err := s.tunnel.sendControl(s.tunnel.remoteTunnelID, s.remoteSessionID, iccnPayload); err != nil {
		return fmt.Errorf("send ICCN: %w", err)
	}

	s.logger.Debug("session handshake complete",
		zap.Uint16("localSessionID", s.localSessionID),
		zap.Uint16("remoteSessionID", s.remoteSessionID))
	return nil
}

// SendPPP sends a PPP frame to the LNS via the tunnel.
// proto is the PPP protocol number, payload is the PPP information field.
func (s *Session) SendPPP(proto uint16, payload []byte) error {
	select {
	case <-s.closed:
		return errSessionClosed
	default:
	}
	return s.tunnel.SendData(s.remoteSessionID, proto, payload)
}

// RecvPPP receives a PPP frame from the LNS.
// Returns the PPP protocol number and information payload.
func (s *Session) RecvPPP() (uint16, []byte, error) {
	select {
	case <-s.closed:
		return 0, nil, errSessionClosed
	case frame, ok := <-s.recvCh:
		if !ok {
			return 0, nil, errSessionClosed
		}
		return frame.Proto, frame.Payload, nil
	}
}

// deliverPPP is called by the tunnel's demux loop to deliver a PPP frame.
func (s *Session) deliverPPP(proto uint16, payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)
	frame := pppFrame{Proto: proto, Payload: data}
	select {
	case s.recvCh <- frame:
	case <-s.closed:
	default:
		s.logger.Warn("L2TP session recvCh full, backpressure active",
			zap.Uint16("sessionID", s.localSessionID))
		select {
		case s.recvCh <- frame:
		case <-s.closed:
		}
	}
}

// Close sends CDN and cleans up the session.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		// Best-effort CDN
		cdnPayload := BuildCDN(s.localSessionID, 2, 0, "LAC disconnect")
		_ = s.tunnel.sendControl(s.tunnel.remoteTunnelID, s.remoteSessionID, cdnPayload)
		remaining := s.tunnel.removeSession(s.localSessionID)
		s.logger.Info("session closed",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("username", s.info.AuthName))
		// If this was the last session, tear down the tunnel
		if remaining == 0 {
			s.logger.Info("last session ended, closing tunnel",
				zap.Uint16("tunnelID", s.tunnel.localTunnelID))
			s.tunnel.Close()
		}
	})
}

// closeDueToTunnel is called when the tunnel dies.
func (s *Session) closeDueToTunnel() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.logger.Warn("session died due to tunnel death",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("username", s.info.AuthName))
	})
}

// closeDueToLNS is called when the LNS sends CDN.
func (s *Session) closeDueToLNS() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.tunnel.removeSession(s.localSessionID)
		s.logger.Warn("session CDN received from LNS",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("username", s.info.AuthName))
	})
}
