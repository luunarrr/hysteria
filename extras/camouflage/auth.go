package camouflage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"
)

const (
	DCIDLen           = 8
	nonceLen          = 3
	serverIDLen       = 1
	hmacTagLen        = 4
	DefaultTimeBucket = 120 * time.Second
)

// GenerateDCID generates an 8-byte Destination Connection ID for the client.
// Layout: nonce (3B) || server_id (1B) || HMAC-SHA256 tag (4B truncated).
func GenerateDCID(psk []byte, serverIP net.IP, timeBucketSize time.Duration) ([]byte, error) {
	if timeBucketSize == 0 {
		timeBucketSize = DefaultTimeBucket
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	serverID := ComputeServerID(psk, serverIP)
	bucket := currentTimeBucket(timeBucketSize)

	tag := computeHMACTag(psk, nonce, bucket, serverID)

	dcid := make([]byte, DCIDLen)
	copy(dcid[0:nonceLen], nonce)
	dcid[nonceLen] = serverID
	copy(dcid[nonceLen+serverIDLen:], tag[:hmacTagLen])
	return dcid, nil
}

// VerifyResult holds the result of a DCID verification attempt.
type VerifyResult struct {
	// Label is the matched secret's label, empty if no secret matched.
	Label string
	// ServerIDMatch is true when the server_id embedded in the DCID matches
	// the expected value for this server. Always true when myIP is nil.
	ServerIDMatch bool
}

// Matched returns true when at least one secret produced a valid HMAC.
func (r VerifyResult) Matched() bool { return r.Label != "" }

// VerifyDCID checks a DCID against all labeled secrets.
// Returns immediately with empty result if len(dcid) != DCIDLen.
// Iterates all secrets x 2 time buckets (current and previous).
// When myIP is nil, server_id comparison is skipped (ServerIDMatch = true).
func VerifyDCID(secrets map[string][]byte, myIP net.IP, dcid []byte, timeBucketSize time.Duration) VerifyResult {
	if len(dcid) != DCIDLen {
		return VerifyResult{}
	}
	if timeBucketSize == 0 {
		timeBucketSize = DefaultTimeBucket
	}

	nonce := dcid[0:nonceLen]
	serverID := dcid[nonceLen]
	tag := dcid[nonceLen+serverIDLen : DCIDLen]

	cur := currentTimeBucket(timeBucketSize)
	buckets := [2]uint64{cur, cur - 1}

	for label, psk := range secrets {
		for _, bucket := range buckets {
			expected := computeHMACTag(psk, nonce, bucket, serverID)
			if hmac.Equal(tag, expected[:hmacTagLen]) {
				sidMatch := true
				if myIP != nil {
					sidMatch = serverID == ComputeServerID(psk, myIP)
				}
				return VerifyResult{Label: label, ServerIDMatch: sidMatch}
			}
		}
	}
	return VerifyResult{}
}

// ComputeServerID derives a 1-byte server identifier from PSK and IP.
func ComputeServerID(psk []byte, ip net.IP) byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("server_id"))
	mac.Write(ip.To16())
	return mac.Sum(nil)[0]
}

func computeHMACTag(psk, nonce []byte, timeBucket uint64, serverID byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], timeBucket)
	mac.Write(tb[:])
	mac.Write([]byte{serverID})
	return mac.Sum(nil)[:hmacTagLen]
}

func currentTimeBucket(size time.Duration) uint64 {
	return uint64(time.Now().Unix()) / uint64(size.Seconds())
}
