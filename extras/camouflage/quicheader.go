package camouflage

import "errors"

var (
	ErrPacketTooShort = errors.New("packet too short")
)

// ParseDCID extracts the Destination Connection ID from a QUIC packet.
// Returns the DCID bytes, whether the packet is an Initial packet, and any error.
// For short-header packets, isInitial=false and dcid is nil.
func ParseDCID(packet []byte) (dcid []byte, isInitial bool, err error) {
	if len(packet) < 1 {
		return nil, false, ErrPacketTooShort
	}
	if packet[0]&0x80 == 0 {
		return nil, false, nil
	}
	// Long header: 1B header + 4B version + 1B DCID len + DCID...
	if len(packet) < 6 {
		return nil, false, ErrPacketTooShort
	}
	// Packet type from bits 4-5 of first byte (QUIC v1):
	// 0b00 = Initial, 0b01 = 0-RTT, 0b10 = Handshake, 0b11 = Retry
	isInitial = (packet[0] & 0x30) == 0x00

	dcidLen := int(packet[5])
	if len(packet) < 6+dcidLen {
		return nil, false, ErrPacketTooShort
	}
	dcid = make([]byte, dcidLen)
	copy(dcid, packet[6:6+dcidLen])
	return dcid, isInitial, nil
}
