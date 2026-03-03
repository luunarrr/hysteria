package camouflage

import "golang.org/x/sys/unix"

// msgTypeIPTOS is the cmsg type an arriving IPv4 packet's TOS byte is reported
// under, which is not the same as the one used to set it and is not the same
// across kernels. Linux reports IP_TOS; see the BSD file for the other spelling.
//
// Getting it wrong fails silently in the worst direction: no message ever
// matches, every relayed packet loses its ECN marking, and the relay looks like
// it is propagating ECN while doing nothing. Kept split per platform for the
// same reason quic-go splits it -- the two must agree about the same socket.
const msgTypeIPTOS = unix.IP_TOS
