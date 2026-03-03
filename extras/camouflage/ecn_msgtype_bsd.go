//go:build darwin || freebsd

package camouflage

import "golang.org/x/sys/unix"

// msgTypeIPTOS is IP_RECVTOS on the BSDs, where the socket option that enables
// reporting is also the type the report arrives under. Linux instead answers
// IP_RECVTOS with an IP_TOS message; see the linux file.
const msgTypeIPTOS = unix.IP_RECVTOS
