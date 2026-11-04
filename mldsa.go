//go:build go1.27

package jwt

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"errors"
)

var (
	ErrMLDSAVerification = errors.New("mldsa: verification error")
)

// SigningMethodMLDSA implements the ML-DSA family of signing methods.
// It expects *mldsa.PrivateKey or a compatible crypto.Signer for signing,
// and *mldsa.PublicKey for verification.
//
// Requires Go 1.27 or later.
type SigningMethodMLDSA struct {
	Name   string
	Params mldsa.Parameters
}

// Specific instances for ML-DSA parameter sets.
var (
	SigningMethodMLDSA44 *SigningMethodMLDSA
	SigningMethodMLDSA65 *SigningMethodMLDSA
	SigningMethodMLDSA87 *SigningMethodMLDSA
)

func init() {
	// ML-DSA-44
	SigningMethodMLDSA44 = &SigningMethodMLDSA{"ML-DSA-44", mldsa.MLDSA44()}
	RegisterSigningMethod(SigningMethodMLDSA44.Alg(), func() SigningMethod {
		return SigningMethodMLDSA44
	})

	// ML-DSA-65
	SigningMethodMLDSA65 = &SigningMethodMLDSA{"ML-DSA-65", mldsa.MLDSA65()}
	RegisterSigningMethod(SigningMethodMLDSA65.Alg(), func() SigningMethod {
		return SigningMethodMLDSA65
	})

	// ML-DSA-87
	SigningMethodMLDSA87 = &SigningMethodMLDSA{"ML-DSA-87", mldsa.MLDSA87()}
	RegisterSigningMethod(SigningMethodMLDSA87.Alg(), func() SigningMethod {
		return SigningMethodMLDSA87
	})
}

func (m *SigningMethodMLDSA) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod.
// The key must be an *mldsa.PublicKey.
func (m *SigningMethodMLDSA) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(*mldsa.PublicKey)
	if !ok {
		return newError("ML-DSA verify expects *mldsa.PublicKey", ErrInvalidKeyType)
	}
	if pub == nil || *pub == (mldsa.PublicKey{}) || pub.Parameters() != m.Params {
		return ErrInvalidKey
	}
	if err := mldsa.Verify(pub, []byte(signingString), sig, &mldsa.Options{}); err != nil {
		return ErrMLDSAVerification
	}
	return nil
}

// Sign implements token signing for the SigningMethod.
// The key must be a crypto.Signer with an *mldsa.PublicKey.
func (m *SigningMethodMLDSA) Sign(signingString string, key any) ([]byte, error) {
	if privateKey, ok := key.(*mldsa.PrivateKey); ok && privateKey == nil {
		return nil, ErrInvalidKey
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, newError("ML-DSA sign expects crypto.Signer", ErrInvalidKeyType)
	}
	pub, ok := signer.Public().(*mldsa.PublicKey)
	if !ok || pub == nil || *pub == (mldsa.PublicKey{}) || pub.Parameters() != m.Params {
		return nil, ErrInvalidKey
	}
	// JOSE uses the full signing input and an empty ML-DSA context.
	return signer.Sign(rand.Reader, []byte(signingString), &mldsa.Options{})
}
