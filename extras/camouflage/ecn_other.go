//go:build !(linux || darwin || freebsd)

package camouflage

import "net"

// Platforms without the IP_TOS/IPV6_TCLASS control messages relay without
// propagating ECN, which is what every platform did before this existed. The
// stubs keep udprelay.go free of build tags: it asks for the codepoint, is told
// there isn't one, and forwards the packet unmarked.

var ecnOOBSpace = 0

func parseECNBits([]byte) (byte, bool) { return 0, false }

func appendECNOOB(b []byte, _ bool, _ byte) []byte { return b }

func enableECNRead(*net.UDPConn) {}
