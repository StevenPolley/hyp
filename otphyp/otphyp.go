// Package otphyp is a loose implementation of hotp standard RFC4226
// it is not a full hotp implementation and only contains specific features required for hyp
package otphyp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// A loose implementation of hotp meant for our specific purposes of generating four random port numbers
// Accepts a base32 encoded shared secret and a time
func GeneratePorts(sharedSecret string, t time.Time) (ports [4]uint16, err error) {
	// 30 second key rotation
	movingFactor := uint64(math.Floor(float64(t.Unix()) / float64(30)))

	sharedSecretBytes, err := base32.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		return [4]uint16{0, 0, 0, 0}, fmt.Errorf("failed to base32 decode shared secret string to bytes: %v", err)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, movingFactor)

	mac := hmac.New(sha1.New, sharedSecretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf

	// deviation from RFC4226's dynamic truncate and modulo reduction algorithm
	// we don't need base10 human friendliness and instead just care about 64 bits / 4
	ports = [4]uint16{
		uint16((int(sum[offset]) & 0xff) << 8),
		uint16((int(sum[offset+1] & 0xff)) << 8),
		uint16((int(sum[offset+2] & 0xff)) << 8),
		uint16((int(sum[offset+3] & 0xff)) << 8),
	}

	return ports, err
}

func GenerateSecret() (sharedSecret string, err error) {
	sharedSecretBytes := make([]byte, 20)
	r := rand.Reader
	_, err = r.Read([]byte(sharedSecretBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read from RNG to sharedSecret byte slice: %v", err)
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(sharedSecretBytes)), nil
}
