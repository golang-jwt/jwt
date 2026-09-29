package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
)

var (
	// Sadly this is missing from crypto/ecdsa compared to crypto/rsa
	ErrECDSAVerification = errors.New("crypto/ecdsa: verification error")
)

// SigningMethodECDSA implements the ECDSA family of signing methods.
// Expects *ecdsa.PrivateKey for signing and *ecdsa.PublicKey for verification
type SigningMethodECDSA struct {
	Name      string
	Hash      crypto.Hash
	KeySize   int
	CurveBits int
}

// Specific instances for EC256 and company
var (
	SigningMethodES256 *SigningMethodECDSA
	SigningMethodES384 *SigningMethodECDSA
	SigningMethodES512 *SigningMethodECDSA
)

func init() {
	// ES256
	SigningMethodES256 = &SigningMethodECDSA{"ES256", crypto.SHA256, 32, 256}
	RegisterSigningMethod(SigningMethodES256.Alg(), func() SigningMethod {
		return SigningMethodES256
	})

	// ES384
	SigningMethodES384 = &SigningMethodECDSA{"ES384", crypto.SHA384, 48, 384}
	RegisterSigningMethod(SigningMethodES384.Alg(), func() SigningMethod {
		return SigningMethodES384
	})

	// ES512
	SigningMethodES512 = &SigningMethodECDSA{"ES512", crypto.SHA512, 66, 521}
	RegisterSigningMethod(SigningMethodES512.Alg(), func() SigningMethod {
		return SigningMethodES512
	})
}

func (m *SigningMethodECDSA) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an ecdsa.PublicKey struct
func (m *SigningMethodECDSA) Verify(signingString string, sig []byte, key any) error {
	// Get the key
	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return newError("ECDSA verify expects *ecdsa.PublicKey", ErrInvalidKeyType)
	}

	if len(sig) != 2*m.KeySize {
		return ErrECDSAVerification
	}

	r := big.NewInt(0).SetBytes(sig[:m.KeySize])
	s := big.NewInt(0).SetBytes(sig[m.KeySize:])

	// Create hasher
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Verify the signature
	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus {
		return nil
	}

	return ErrECDSAVerification
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an ecdsa.PrivateKey struct
func (m *SigningMethodECDSA) Sign(signingString string, key any) ([]byte, error) {
	// Create the hasher
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// create a structure to hold the parsed signature components (r and s)
	var parsedSignature struct {
		R, S *big.Int
	}
	var curveBits int

	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
		curveBits = ecdsaKey.Curve.Params().BitSize

		// Sign the string and return r, s
		r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil))
		if err != nil {
			return nil, err
		}

		parsedSignature.R = r
		parsedSignature.S = s
	} else if ecdsaSigner, ok := key.(crypto.Signer); ok {
		publicKey, ok := ecdsaSigner.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, newError("ECDSA sign expects crypto.Signer.Public() with *ecdsa.PublicKey", ErrInvalidKeyType)
		}
		params := publicKey.Curve.Params()
		curveBits = params.BitSize

		// Sign the hashed message to produce an ASN.1 encoded signature
		signature, err := ecdsaSigner.Sign(rand.Reader, hasher.Sum(nil), m.Hash)
		if err != nil {
			return nil, err
		}

		// Parse the ASN.1-encoded signature into r and s
		rest, err := asn1.Unmarshal(signature, &parsedSignature)
		if err != nil {
			return nil, newError("ECDSA sign expects signature in ASN.1 format", err)
		}

		if len(rest) != 0 ||
			parsedSignature.R == nil || parsedSignature.S == nil ||
			parsedSignature.R.Sign() <= 0 || parsedSignature.S.Sign() <= 0 ||
			// Ensure r and s are less than the order of the curve (N).
			parsedSignature.R.Cmp(params.N) >= 0 || parsedSignature.S.Cmp(params.N) >= 0 ||
			// Ensure r and s do not exceed the bit length of the curve.
			parsedSignature.R.BitLen() > curveBits || parsedSignature.S.BitLen() > curveBits {
			return nil, errors.New("invalid ASN.1 ECDSA signature")
		}
	} else {
		return nil, newError("ECDSA sign expects *ecdsa.PrivateKey", ErrInvalidKeyType)
	}

	if m.CurveBits != curveBits {
		return nil, ErrInvalidKey
	}

	keyBytes := (curveBits + 7) / 8
	// We serialize the outputs (r and s) into big-endian byte arrays
	// padded with zeros on the left to make sure the sizes work out.
	// Output must be 2*keyBytes long.
	out := make([]byte, 2*keyBytes)
	parsedSignature.R.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
	parsedSignature.S.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

	return out, nil
}
