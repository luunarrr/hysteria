package camouflage

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeCredential(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{"bare password untouched", "SomePassword", "SomePassword"},
		{"username lowercased", "Bear:SomePassword", "bear:SomePassword"},
		{"password case preserved", "bear:SoMePaSs", "bear:SoMePaSs"},
		{"only the first colon splits", "Bear:pa:ss", "bear:pa:ss"},
		{"empty username", ":pass", ":pass"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.out, NormalizeCredential(tt.in))
		})
	}
}

func TestDerivePSK_Deterministic(t *testing.T) {
	psk := DerivePSK("bear:hunter2")
	assert.Len(t, psk, deriveKeyLen)
	assert.Equal(t, psk, DerivePSK("bear:hunter2"))
}

func TestDerivePSK_DistinguishesCredentials(t *testing.T) {
	assert.NotEqual(t, DerivePSK("bear:hunter2"), DerivePSK("bear:hunter3"))
	assert.NotEqual(t, DerivePSK("bear:hunter2"), DerivePSK("zyp:hunter2"))
	// A bare password must not collide with a userpass credential that happens
	// to contain the same bytes around a colon.
	assert.NotEqual(t, DerivePSK("bearhunter2"), DerivePSK("bear:hunter2"))
}

func TestDerivePSK_UsernameCaseInsensitive(t *testing.T) {
	// UserPassAuthenticator lowercases usernames, so these authenticate as the
	// same account and must land on the same PSK.
	assert.Equal(t, DerivePSK("bear:hunter2"), DerivePSK("Bear:hunter2"))
	// The password half is not case-insensitive and must not be folded.
	assert.NotEqual(t, DerivePSK("bear:hunter2"), DerivePSK("bear:HUNTER2"))
}

// TestDerivePSK_ClientServerAgree is the property the whole scheme rests on:
// a client derives from its one opaque auth string, a server derives from the
// userpass entry it holds, and the two must arrive at the same key without the
// client knowing which auth type the server runs.
func TestDerivePSK_ClientServerAgree(t *testing.T) {
	const user, pass = "Bear", "hunter2"
	serverIP := net.ParseIP("203.0.113.7")

	// Client side: the auth string exactly as it appears in client config.
	clientPSK := DerivePSK(user + ":" + pass)
	dcid, err := GenerateDCID(clientPSK, serverIP, 0)
	require.NoError(t, err)

	// Server side: viper lowercases the userpass map keys before we see them.
	secrets := map[string][]byte{
		"bear": DerivePSK("bear" + ":" + pass),
		"zyp":  DerivePSK("zyp:somethingelse"),
	}
	result := VerifyDCID(secrets, serverIP, dcid, 0)
	assert.True(t, result.Matched())
	assert.True(t, result.ServerIDMatch)
	assert.Equal(t, "bear", result.Label, "alert label should name the account")
}

// TestDerivePSK_PasswordAuthAgrees covers the other derivable auth type, where
// the credential is a bare password and no splitting happens on either end.
func TestDerivePSK_PasswordAuthAgrees(t *testing.T) {
	const password = "353f87cf3903512a04a98b8c33b6a53f"
	serverIP := net.ParseIP("203.0.113.7")

	dcid, err := GenerateDCID(DerivePSK(password), serverIP, 0)
	require.NoError(t, err)

	result := VerifyDCID(map[string][]byte{"password": DerivePSK(password)}, serverIP, dcid, 0)
	assert.True(t, result.Matched())
	assert.Equal(t, "password", result.Label)
}

func TestDerivePSK_WrongCredentialRejected(t *testing.T) {
	serverIP := net.ParseIP("203.0.113.7")
	dcid, err := GenerateDCID(DerivePSK("bear:hunter2"), serverIP, 0)
	require.NoError(t, err)

	secrets := map[string][]byte{"bear": DerivePSK("bear:wrongpass")}
	assert.False(t, VerifyDCID(secrets, serverIP, dcid, 0).Matched())
}
