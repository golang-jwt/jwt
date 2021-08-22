// +build go1.4

package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// SigningMethodRSAPSS implements the RSAPSS family of signing methods signing methods
type SigningMethodRSAPSS struct {
	*SigningMethodRSA
	Options *rsa.PSSOptions
	// VerifyOptions is optional. If set overrides Options for rsa.VerifyPPS.
	// Used to accept tokens signed with rsa.PSSSaltLengthAuto, what doesn't follow
	// https://tools.ietf.org/html/rfc7518#section-3.5 but was used previously.
	// See https://github.com/dgrijalva/jwt-go/issues/285#issuecomment-437451244 for details.
	VerifyOptions *rsa.PSSOptions
}

// Specific instances for RS/PS and company.
var (

	// PS256
	SigningMethodPS256 = NewSigningMethodRSAPSS(
		&SigningMethodRSA{
			Name: "PS256",
			Hash: crypto.SHA256,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	)

	// PS384
	SigningMethodPS384 = NewSigningMethodRSAPSS(
		&SigningMethodRSA{
			Name: "PS384",
			Hash: crypto.SHA384,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	)

	// PS512
	SigningMethodPS512 = NewSigningMethodRSAPSS(
		&SigningMethodRSA{
			Name: "PS512",
			Hash: crypto.SHA512,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	)
)

// NewSigningMethodRSAPSS creates a new SigningMethodRSAPSS struct and
// registers it as a signing method.
func NewSigningMethodRSAPSS(smRSA *SigningMethodRSA, options *rsa.PSSOptions, verifyOptions ...*rsa.PSSOptions) *SigningMethodRSAPSS {
	m := &SigningMethodRSAPSS{
		SigningMethodRSA: smRSA,
		Options:          options,
		VerifyOptions:    &rsa.PSSOptions{},
	}
	// If an additional *rsa.PSSOptions struct is given, use that for the VerifyOptions field.
	// VerifyOptions is optional.
	if len(verifyOptions) == 1 {
		m.VerifyOptions = verifyOptions[0]
	}
	Register(m)
	return m
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an rsa.PublicKey struct
func (m *SigningMethodRSAPSS) Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	switch k := key.(type) {
	case *rsa.PublicKey:
		rsaKey = k
	default:
		return ErrInvalidKey
	}

	// Create hasher
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	opts := m.Options
	if m.VerifyOptions != nil {
		opts = m.VerifyOptions
	}

	return rsa.VerifyPSS(rsaKey, m.Hash, hasher.Sum(nil), sig, opts)
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an rsa.PrivateKey struct
func (m *SigningMethodRSAPSS) Sign(signingString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return "", ErrInvalidKeyType
	}

	// Create the hasher
	if !m.Hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPSS(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil), m.Options); err == nil {
		return EncodeSegment(sigBytes), nil
	} else {
		return "", err
	}
}
