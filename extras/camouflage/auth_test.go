package camouflage

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndVerifyDCID(t *testing.T) {
	psk := []byte("test-secret-key-1234567890123456")
	serverIP := net.ParseIP("1.2.3.4")
	bucket := 120 * time.Second

	dcid, err := GenerateDCID(psk, serverIP, bucket)
	require.NoError(t, err)
	assert.Len(t, dcid, DCIDLen)

	secrets := map[string][]byte{"group-a": psk}
	result := VerifyDCID(secrets, serverIP, dcid, bucket)
	assert.Equal(t, "group-a", result.Label)
	assert.True(t, result.ServerIDMatch)
	assert.True(t, result.Matched())
}

func TestVerifyDCID_WrongSecret(t *testing.T) {
	psk := []byte("correct-secret")
	wrongPSK := []byte("wrong-secret")
	serverIP := net.ParseIP("1.2.3.4")

	dcid, err := GenerateDCID(psk, serverIP, 0)
	require.NoError(t, err)

	result := VerifyDCID(map[string][]byte{"wrong": wrongPSK}, serverIP, dcid, 0)
	assert.False(t, result.Matched())
}

func TestVerifyDCID_MultipleSecrets(t *testing.T) {
	psk1 := []byte("secret-one-aaaa")
	psk2 := []byte("secret-two-bbbb")
	serverIP := net.ParseIP("10.0.0.1")

	dcid, err := GenerateDCID(psk2, serverIP, 0)
	require.NoError(t, err)

	secrets := map[string][]byte{"group-a": psk1, "group-b": psk2}
	result := VerifyDCID(secrets, serverIP, dcid, 0)
	assert.Equal(t, "group-b", result.Label)
	assert.True(t, result.ServerIDMatch)
}

func TestVerifyDCID_ServerIDMismatch(t *testing.T) {
	psk := []byte("shared-secret")
	clientSees := net.ParseIP("1.2.3.4")
	serverActual := net.ParseIP("5.6.7.8")

	dcid, err := GenerateDCID(psk, clientSees, 0)
	require.NoError(t, err)

	result := VerifyDCID(map[string][]byte{"fleet": psk}, serverActual, dcid, 0)
	assert.True(t, result.Matched())
	assert.False(t, result.ServerIDMatch)
}

func TestVerifyDCID_NilMyIP(t *testing.T) {
	psk := []byte("some-secret")
	serverIP := net.ParseIP("1.2.3.4")

	dcid, err := GenerateDCID(psk, serverIP, 0)
	require.NoError(t, err)

	result := VerifyDCID(map[string][]byte{"test": psk}, nil, dcid, 0)
	assert.True(t, result.Matched())
	assert.True(t, result.ServerIDMatch)
}

func TestVerifyDCID_WrongLength(t *testing.T) {
	result := VerifyDCID(map[string][]byte{"x": []byte("s")}, net.ParseIP("1.2.3.4"), []byte{1, 2, 3}, 0)
	assert.False(t, result.Matched())
}

func TestParseDCID_Initial(t *testing.T) {
	packet := []byte{
		0xC0,                         // long header, Initial (bits 4-5 = 00)
		0x00, 0x00, 0x00, 0x01,       // version
		0x08,                         // DCID length = 8
		1, 2, 3, 4, 5, 6, 7, 8,      // DCID
		0x00,                         // SCID length = 0
	}
	dcid, isInitial, err := ParseDCID(packet)
	require.NoError(t, err)
	assert.True(t, isInitial)
	assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, dcid)
}

func TestParseDCID_ShortHeader(t *testing.T) {
	dcid, isInitial, err := ParseDCID([]byte{0x40, 0x01, 0x02, 0x03})
	require.NoError(t, err)
	assert.False(t, isInitial)
	assert.Nil(t, dcid)
}

func TestParseDCID_Handshake(t *testing.T) {
	packet := []byte{
		0xE0,                     // long header, Handshake (bits 4-5 = 10)
		0x00, 0x00, 0x00, 0x01,
		0x04,
		0xAA, 0xBB, 0xCC, 0xDD,
	}
	dcid, isInitial, err := ParseDCID(packet)
	require.NoError(t, err)
	assert.False(t, isInitial)
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, dcid)
}

func TestParseDCID_TooShort(t *testing.T) {
	_, _, err := ParseDCID(nil)
	assert.Equal(t, ErrPacketTooShort, err)

	_, _, err = ParseDCID([]byte{0xC0, 0x00})
	assert.Equal(t, ErrPacketTooShort, err)
}
