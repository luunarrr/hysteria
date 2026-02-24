package cmd

import (
	"errors"
	"os"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
)

// pppStatusEnv names a file where a terminal PPP failure reason is recorded.
//
// In nospawn mode hysteria runs as pppd's pty child, so the only thing netifd
// ever sees is pppd's exit code -- and a hangup looks identical whether the
// password was wrong or the network blinked. netifd would therefore restart the
// interface forever against a credential that can never work, showing a generic
// pppd error. The OpenWrt protocol handler sets this variable and reads the file
// back in its teardown, which is where it can call proto_notify_error with
// something useful and proto_block_restart to stop the loop.
const pppStatusEnv = "HYSTERIA_PPP_STATUS"

// PPP status reasons. These are the strings the netifd handler matches on and
// that luci-proto-hysteria registers for display, so they are a contract.
const (
	pppStatusAuthFailed = "AUTH_FAILED"
)

// writePPPStatus records why PPP mode stopped, when the reason is one the
// protocol handler should act on. A nil error, an unset variable, or a failure
// that is worth retrying all write nothing.
func writePPPStatus(err error) {
	path := os.Getenv(pppStatusEnv)
	if path == "" || err == nil {
		return
	}
	reason := ""
	var authErr coreErrs.AuthError
	var linkDown *pppbridge.LinkDownError
	switch {
	case errors.As(err, &authErr):
		// The Hysteria2 handshake itself was refused.
		reason = pppStatusAuthFailed
	case errors.As(err, &linkDown) && linkDown.Reason.Code.Permanent():
		// The far side explained why, and retrying cannot fix it -- a refused
		// subscriber credential, or a realm that does not exist.
		reason = linkDown.Reason.Code.String()
	}
	if reason == "" {
		return
	}
	// Best effort: if this cannot be written the handler simply falls back to
	// pppd's exit code, which is the behaviour without it.
	_ = os.WriteFile(path, []byte(reason+"\n"), 0o600)
}

// pppRestartFloor is how long this process must have been alive before it is
// allowed to exit on a failure while it is pppd's pty child.
//
// Nothing between here and netifd rate-limits a redial in that mode. pppd is run
// without persist -- it has to exit so the protocol handler's teardown can read
// the status file and decide whether the failure is worth retrying at all -- so
// pppd's own holdoff never comes into play, and netifd restarts the interface as
// soon as the command returns. The redial rate is therefore exactly this
// process's exit rate. When the underlay is gone the QUIC dial fails with
// ENETUNREACH before it reaches the wire, which turns a dropped upstream into
// dozens of pppd spawns a second.
//
// A flat floor rather than backoff that grows: each restart is a fresh process,
// so growing it would mean persisting an attempt count somewhere and reasoning
// about when to clear it -- and a count left behind by an outage that has since
// ended delays the reconnect that would have worked. One attempt every five
// seconds is not a storm, and is about the rate an ordinary PPPoE redial runs at.
const pppRestartFloor = 5 * time.Second

var pppProcStart = time.Now()

// holdPPPRestart delays a failing exit until this process has been alive for
// pppRestartFloor.
//
// It keys off pppStatusEnv because that variable is set by the protocol handler
// and by nothing else, which makes it the available signal for "this process is
// pppd's pty child and its exit is a redial". A session that ran longer than the
// floor sleeps for nothing, which is every session that actually carried traffic.
//
// Sleeping holds the pty open with nothing answering on it. pppd retries LCP
// ConfReq every three seconds and gives up only after ten of them, so a pause
// this short passes unnoticed; pppd still sees the hangup when this process
// exits, exactly as it would have.
func holdPPPRestart() {
	if d := pppRestartDelay(os.Getenv(pppStatusEnv), time.Since(pppProcStart)); d > 0 {
		time.Sleep(d)
	}
}

// pppRestartDelay is the decision holdPPPRestart acts on, split out so it can be
// tested without spending the wall-clock time it describes.
func pppRestartDelay(statusPath string, alive time.Duration) time.Duration {
	if statusPath == "" {
		return 0
	}
	// Clamped at both ends. time.Since reads the monotonic clock so a negative
	// lifetime does not arise today, but the subtraction below would turn one
	// into a delay longer than the floor -- the opposite of what a floor is.
	if alive < 0 {
		alive = 0
	}
	if d := pppRestartFloor - alive; d > 0 {
		return d
	}
	return 0
}
