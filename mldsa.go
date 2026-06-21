//go:build go1.25

package jwt

import (
	"crypto"
	"errors"

	"filippo.io/mldsa"
)

var (
	ErrMLDSAVerification = errors.New("mldsa: verification error")
)

// SigningMethodMLDSA implements the ML-DSA family of signing methods
// as defined in FIPS 204.
// Expects *mldsa.PrivateKey for signing and *mldsa.PublicKey for verification.
type SigningMethodMLDSA struct {
	Name   string
	Params *mldsa.Parameters
}

// Specific instances for ML-DSA parameter sets
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
// For this verify method, key must be a *mldsa.PublicKey.
func (m *SigningMethodMLDSA) Verify(signingString string, sig []byte, key any) error {
	var mldsaKey *mldsa.PublicKey
	var ok bool

	if mldsaKey, ok = key.(*mldsa.PublicKey); !ok {
		return newError("ML-DSA verify expects *mldsa.PublicKey", ErrInvalidKeyType)
	}

	if mldsaKey.Parameters() != m.Params {
		return newError("ML-DSA verify: key parameter set mismatch", ErrInvalidKey)
	}

	if err := mldsa.Verify(mldsaKey, []byte(signingString), sig, &mldsa.Options{}); err != nil {
		return ErrMLDSAVerification
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be a *mldsa.PrivateKey.
func (m *SigningMethodMLDSA) Sign(signingString string, key any) ([]byte, error) {
	var mldsaKey *mldsa.PrivateKey

	switch k := key.(type) {
	case *mldsa.PrivateKey:
		mldsaKey = k
	case crypto.Signer:
		// Support crypto.Signer interface for hardware-backed keys
		pub, ok := k.Public().(*mldsa.PublicKey)
		if !ok {
			return nil, newError("ML-DSA sign expects *mldsa.PrivateKey or crypto.Signer with ML-DSA key", ErrInvalidKeyType)
		}
		if pub.Parameters() != m.Params {
			return nil, newError("ML-DSA sign: key parameter set mismatch", ErrInvalidKey)
		}
		sig, err := k.Sign(nil, []byte(signingString), &mldsa.Options{})
		if err != nil {
			return nil, err
		}
		return sig, nil
	default:
		return nil, newError("ML-DSA sign expects *mldsa.PrivateKey", ErrInvalidKeyType)
	}

	// Verify parameter set matches
	pub := mldsaKey.PublicKey()
	if pub.Parameters() != m.Params {
		return nil, newError("ML-DSA sign: key parameter set mismatch", ErrInvalidKey)
	}

	sig, err := mldsaKey.Sign(nil, []byte(signingString), &mldsa.Options{})
	if err != nil {
		return nil, err
	}

	return sig, nil
}
