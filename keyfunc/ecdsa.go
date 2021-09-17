package keyfunc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

const (

	// es256 represents a public cryptography key generated by an SHA-256 hash and an ECDSA algorithm.
	es256 = "ES256"

	// es384 represents a public cryptography key generated by an SHA-384 hash and an ECDSA algorithm.
	es384 = "ES384"

	// es512 represents a public cryptography key generated by an SHA-512 hash and an ECDSA algorithm.
	es512 = "ES512"

	// p256 represents a 256-bit cryptographic elliptical curve type.
	p256 = "P-256"

	// p384 represents a 384-bit cryptographic elliptical curve type.
	p384 = "P-384"

	// p521 represents a 521-bit cryptographic elliptical curve type.
	p521 = "P-521"
)

// ECDSA parses a jsonKey and turns it into an ECDSA public key.
func (j *jsonKey) ECDSA() (publicKey *ecdsa.PublicKey, err error) {

	// Check if the key has already been computed.
	j.precomputedMux.RLock()
	if j.precomputed != nil {
		var ok bool
		if publicKey, ok = j.precomputed.(*ecdsa.PublicKey); ok {
			j.precomputedMux.RUnlock()
			return publicKey, nil
		}
	}
	j.precomputedMux.RUnlock()

	// Confirm everything needed is present.
	if j.X == "" || j.Y == "" || j.Curve == "" {
		return nil, fmt.Errorf("%w: ecdsa", ErrMissingAssets)
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	var xCoordinate []byte
	if xCoordinate, err = base64.RawURLEncoding.DecodeString(j.X); err != nil {
		return nil, err
	}

	// Decode the Y coordinate from Base64.
	var yCoordinate []byte
	if yCoordinate, err = base64.RawURLEncoding.DecodeString(j.Y); err != nil {
		return nil, err
	}

	// Create the ECDSA public key.
	publicKey = &ecdsa.PublicKey{}

	// Set the curve type.
	switch j.Curve {
	case p256:
		publicKey.Curve = elliptic.P256()
	case p384:
		publicKey.Curve = elliptic.P384()
	case p521:
		publicKey.Curve = elliptic.P521()
	}

	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	publicKey.X = big.NewInt(0).SetBytes(xCoordinate)

	// Turn the Y coordinate into a *big.Int.
	publicKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	// Keep the public key so it won't have to be computed every time.
	j.precomputedMux.Lock()
	j.precomputed = publicKey
	j.precomputedMux.Unlock()

	return publicKey, nil
}
