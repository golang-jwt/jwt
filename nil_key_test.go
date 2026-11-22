package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestNilSigningKeysRejected ensures that a typed nil key passed to a signing
// method, e.g., one returned by a keyfunc after a failed key lookup, results
// in an error instead of a panic.
func TestNilSigningKeysRejected(t *testing.T) {
	var (
		nilRSAPublicKey    *rsa.PublicKey
		nilRSAPrivateKey   *rsa.PrivateKey
		nilECDSAPublicKey  *ecdsa.PublicKey
		nilECDSAPrivateKey *ecdsa.PrivateKey
		nilEdPublicKey     ed25519.PublicKey
		nilEdPrivateKey    ed25519.PrivateKey
	)

	testCases := []struct {
		name   string
		method jwt.SigningMethod
		sign   bool
		key    any
	}{
		{"RSA verify", jwt.SigningMethodRS256, false, nilRSAPublicKey},
		{"RSA sign", jwt.SigningMethodRS256, true, nilRSAPrivateKey},
		{"RSA-PSS verify", jwt.SigningMethodPS256, false, nilRSAPublicKey},
		{"RSA-PSS sign", jwt.SigningMethodPS256, true, nilRSAPrivateKey},
		{"ECDSA verify", jwt.SigningMethodES256, false, nilECDSAPublicKey},
		{"ECDSA sign", jwt.SigningMethodES256, true, nilECDSAPrivateKey},
		{"EdDSA verify", jwt.SigningMethodEdDSA, false, nilEdPublicKey},
		{"EdDSA sign", jwt.SigningMethodEdDSA, true, nilEdPrivateKey},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.sign {
				_, err = tc.method.Sign("", tc.key)
			} else {
				err = tc.method.Verify("", make([]byte, 512), tc.key)
			}

			if err == nil {
				t.Fatal("expected an error for a nil key, got nil")
			}
			if !errors.Is(err, jwt.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got %v", err)
			}
		})
	}
}

// TestParseWithNilKeyFromKeyfunc ensures that parsing a token whose keyfunc
// returns a typed nil key with a nil error returns an error instead of
// panicking.
func TestParseWithNilKeyFromKeyfunc(t *testing.T) {
	var nilRSAPublicKey *rsa.PublicKey
	tokenString := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.e30.AQ"

	_, err := jwt.NewParser().Parse(tokenString, func(*jwt.Token) (any, error) {
		return nilRSAPublicKey, nil
	})

	if err == nil {
		t.Fatal("expected an error when the keyfunc returns a nil key, got nil")
	}
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("expected ErrTokenSignatureInvalid, got %v", err)
	}
	if !errors.Is(err, jwt.ErrInvalidKey) {
		t.Fatalf("expected wrapped ErrInvalidKey, got %v", err)
	}
}
