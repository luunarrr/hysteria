package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The netifd handler reads this file in its teardown to decide between naming the
// failure and blocking restart, or letting pppd's exit code speak. Writing the
// wrong thing either loops forever on a bad password or wedges an interface that
// would have recovered on its own, so the mapping is a contract.
func TestWritePPPStatusOnlyRecordsTerminalFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string // "" means the file must not be created
	}{
		{"auth failure is terminal", coreErrs.AuthError{StatusCode: 401}, pppStatusAuthFailed},
		{"wrapped auth failure is terminal", fmt.Errorf("ppp: %w", coreErrs.AuthError{StatusCode: 403}), pppStatusAuthFailed},

		{"no error writes nothing", nil, ""},
		{"connect failure writes nothing", coreErrs.ConnectError{Err: errors.New("refused")}, ""},
		{"link loss writes nothing", errors.New("ppp: hysteria2 link lost"), ""},
		{"closed writes nothing", coreErrs.ClosedError{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "status")
			t.Setenv(pppStatusEnv, path)

			writePPPStatus(tt.err)

			data, err := os.ReadFile(path)
			if tt.want == "" {
				require.ErrorIs(t, err, os.ErrNotExist,
					"a retryable failure must leave restart to netifd")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want+"\n", string(data))
		})
	}
}

// Without the variable there is nothing to write to, and the client must not
// invent a path.
func TestWritePPPStatusIsInertWithoutTheEnvVar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(pppStatusEnv, "")

	require.NotPanics(t, func() {
		writePPPStatus(coreErrs.AuthError{StatusCode: 401})
	})

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// In nospawn mode this process's exit rate is the redial rate: pppd runs without
// persist so that its exit lets the handler read the status file, which means
// pppd's own holdoff never applies and netifd restarts as soon as the command
// returns. A failure that costs microseconds -- a QUIC dial with no route -- then
// spawns pppd as fast as the two can be forked.
func TestPPPRestartDelayThrottlesOnlyFastFailuresUnderNetifd(t *testing.T) {
	const path = "/var/run/hysteria-wan.status"

	tests := []struct {
		name       string
		statusPath string
		alive      time.Duration
		want       time.Duration
	}{
		{
			// The hot loop: ENETUNREACH comes back before anything reaches the wire.
			name:       "instant failure waits out the whole floor",
			statusPath: path, alive: 0, want: pppRestartFloor,
		},
		{
			name:       "a partly-elapsed floor waits only the remainder",
			statusPath: path, alive: pppRestartFloor - time.Second, want: time.Second,
		},
		{
			// Every session that carried traffic lands here, so the common case
			// pays nothing.
			name:       "a session past the floor is not delayed",
			statusPath: path, alive: pppRestartFloor, want: 0,
		},
		{
			name:       "a long session is not delayed",
			statusPath: path, alive: time.Hour, want: 0,
		},
		{
			// Nothing else sets the variable, so its absence means no netifd is
			// waiting to respawn us and the delay would be pure harm -- it would
			// stall an interactive run and every unit test in this package.
			name:       "outside the netifd handler there is no delay",
			statusPath: "", alive: 0, want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pppRestartDelay(tt.statusPath, tt.alive))
		})
	}
}

// A negative elapsed time is not reachable from time.Since on a monotonic clock,
// but the floor must still be an upper bound rather than something that grows.
func TestPPPRestartDelayNeverExceedsTheFloor(t *testing.T) {
	assert.Equal(t, pppRestartFloor, pppRestartDelay("/var/run/s", -time.Hour),
		"the delay is a floor on process lifetime, not an accumulating penalty")
}

// The guard has to be inert in the case it is called in most often -- a process
// that is not pppd's child -- because every call site is immediately before a
// Fatal that would otherwise exit at once.
func TestHoldPPPRestartReturnsImmediatelyWithoutTheEnvVar(t *testing.T) {
	t.Setenv(pppStatusEnv, "")

	start := time.Now()
	holdPPPRestart()

	assert.Less(t, time.Since(start), time.Second,
		"holdPPPRestart must not delay a process netifd is not respawning")
}

// The branch that actually costs wall-clock time. Driven by moving the process
// start forward rather than by waiting out the real floor, so the sleep it
// performs is milliseconds while still being the same code path.
func TestHoldPPPRestartSleepsOutTheRemainderOfTheFloor(t *testing.T) {
	const remainder = 60 * time.Millisecond

	t.Setenv(pppStatusEnv, "/var/run/hysteria-wan.status")
	saved := pppProcStart
	t.Cleanup(func() { pppProcStart = saved })
	pppProcStart = time.Now().Add(remainder - pppRestartFloor)

	start := time.Now()
	holdPPPRestart()
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, remainder,
		"the exit must be held back until the floor is reached")
	assert.Less(t, elapsed, pppRestartFloor,
		"only the remainder is owed, not the whole floor again")
}

// The file is written where the password lives, so it must not be world-readable
// even though it only carries a reason string.
func TestWritePPPStatusFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	t.Setenv(pppStatusEnv, path)

	writePPPStatus(coreErrs.AuthError{StatusCode: 401})

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}
