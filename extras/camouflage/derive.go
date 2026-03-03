package camouflage

import (
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for turning an authentication credential into a PSK.
// They must never change: every deployment sharing a credential has to arrive
// at the same key, so these are part of the wire contract, not a tunable.
//
// A memory-hard KDF rather than a plain hash because the 4-byte tag in every
// DCID is a verifiable function of the PSK and DCIDs travel in cleartext.
// Keying the HMAC with the credential itself would let anyone who captures a
// single Initial packet guess passwords offline at one HMAC per candidate.
//
// 16 MiB with p=1 rather than the larger RFC 9106 profiles: clients here run
// on OpenWrt routers, where a 64 MiB allocation is a real risk and extra
// parallelism buys nothing on one core. Cost lands on whoever derives, and
// that includes the guessing attacker.
const (
	deriveTime    = 4
	deriveMemory  = 16 * 1024 // KiB
	deriveThreads = 1
	deriveKeyLen  = 32
)

// deriveSalt is a fixed context string, deliberately not anything
// server-specific. Servers holding the same credential must produce the same
// PSK, which is what lets one credential cover a fleet of interchangeable
// servers; a per-server salt would break exactly that.
var deriveSalt = []byte("hysteria-camouflage-v1")

var deriveCache sync.Map // normalized credential -> []byte

// NormalizeCredential puts a credential into the form both ends hash.
//
// A client holds one opaque auth string and cannot tell whether the server
// runs "password" or "userpass" auth, so it cannot know whether that string is
// a bare password or "username:password". Both ends run this same function
// over whatever they hold, and the results agree without the client needing to
// know which it is.
//
// Lowercasing up to the first colon matches UserPassAuthenticator, which
// lowercases usernames before comparing. Without it a client configured as
// "Bear:pw" would authenticate happily as "bear" and then derive a PSK the
// server never computes -- the packet filter would relay it away, which looks
// like a dead server rather than a credential problem.
func NormalizeCredential(cred string) string {
	i := strings.Index(cred, ":")
	if i < 0 {
		return cred
	}
	return strings.ToLower(cred[:i]) + cred[i:]
}

// DerivePSK derives a camouflage PSK from an authentication credential, so a
// deployment can distribute one secret instead of two.
//
// Results are cached because the client rebuilds its entire config on every
// reconnect: an uncached derivation would add its full cost to each link
// recovery, which for a multilink bundle is the worst possible moment.
func DerivePSK(cred string) []byte {
	key := NormalizeCredential(cred)
	if psk, ok := deriveCache.Load(key); ok {
		return psk.([]byte)
	}
	psk := argon2.IDKey([]byte(key), deriveSalt, deriveTime, deriveMemory, deriveThreads, deriveKeyLen)
	actual, _ := deriveCache.LoadOrStore(key, psk)
	return actual.([]byte)
}
