//go:build go1.27

package jwt_test

import (
	"crypto"
	"crypto/mldsa"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

var mldsaTestMethods = []*jwt.SigningMethodMLDSA{
	jwt.SigningMethodMLDSA44,
	jwt.SigningMethodMLDSA65,
	jwt.SigningMethodMLDSA87,
}

// TestMLDSARFC9964 verifies the ML-DSA-44 JWS from RFC 9964, Appendix A.1.
// The key is derived from the all-zeros seed given in that example.
func TestMLDSARFC9964(t *testing.T) {
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), make([]byte, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	tokenString, err := os.ReadFile("test/ml-dsa-44-rfc9964.jws")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSpace(string(tokenString)), ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 token parts, got %d", len(parts))
	}
	message := strings.Join(parts[:2], ".")
	signature := decodeSegment(t, parts[2])
	if err := jwt.SigningMethodMLDSA44.Verify(message, signature, key.PublicKey()); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if err := jwt.SigningMethodMLDSA44.Verify(
		message,
		append(signature, 0),
		key.PublicKey(),
	); !errors.Is(err, jwt.ErrMLDSAVerification) {
		t.Fatalf("Verify() with trailing byte = %v, want %v", err, jwt.ErrMLDSAVerification)
	}
}

func TestMLDSASign(t *testing.T) {
	for _, method := range mldsaTestMethods {
		t.Run(method.Alg(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(method.Params)
			if err != nil {
				t.Fatal(err)
			}
			if jwt.GetSigningMethod(method.Alg()) != method {
				t.Fatal("signing method is not registered")
			}
			tokenString, err := jwt.NewWithClaims(method, jwt.MapClaims{"foo": "bar"}).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			token, err := jwt.Parse(tokenString, func(*jwt.Token) (any, error) {
				return key.PublicKey(), nil
			}, jwt.WithValidMethods([]string{method.Alg()}))
			if err != nil || !token.Valid {
				t.Fatalf("Parse() failed: %v", err)
			}

			parts := strings.Split(tokenString, ".")
			message := strings.Join(parts[:2], ".")
			signature := decodeSegment(t, parts[2])
			if err := mldsa.Verify(key.PublicKey(), []byte(message), signature, &mldsa.Options{}); err != nil {
				t.Fatalf("standard library verification failed: %v", err)
			}
			for _, other := range mldsaTestMethods {
				if other == method {
					continue
				}
				if _, err := other.Sign(message, key); !errors.Is(err, jwt.ErrInvalidKey) {
					t.Fatalf("Sign() accepted %s key for %s: %v", method.Alg(), other.Alg(), err)
				}
			}

			for _, data := range []struct {
				key  any
				want error
			}{
				{"key", jwt.ErrInvalidKeyType},
				{nil, jwt.ErrInvalidKeyType},
				{(*mldsa.PrivateKey)(nil), jwt.ErrInvalidKey},
				{&mldsa.PrivateKey{}, jwt.ErrInvalidKey},
				{mldsaTestSigner{publicKey: "key"}, jwt.ErrInvalidKey},
				{mldsaTestSigner{publicKey: (*mldsa.PublicKey)(nil)}, jwt.ErrInvalidKey},
				{mldsaTestSigner{publicKey: &mldsa.PublicKey{}}, jwt.ErrInvalidKey},
			} {
				if _, err := method.Sign(message, data.key); !errors.Is(err, data.want) {
					t.Fatalf("Sign(%T) = %v, want %v", data.key, err, data.want)
				}
			}

			signerError := errors.New("signer failed")
			signer := mldsaTestSigner{
				publicKey: key.PublicKey(),
				sign: func(random io.Reader, input []byte, opts crypto.SignerOpts) ([]byte, error) {
					options, ok := opts.(*mldsa.Options)
					if !ok || options.Context != "" || opts.HashFunc() != 0 || string(input) != message || random == nil {
						t.Fatal("unexpected signing parameters")
					}
					return nil, signerError
				},
			}
			if _, err := method.Sign(message, signer); !errors.Is(err, signerError) {
				t.Fatalf("Sign() = %v, want %v", err, signerError)
			}
		})
	}
}

func TestMLDSAVerify(t *testing.T) {
	for _, method := range mldsaTestMethods {
		t.Run(method.Alg(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(method.Params)
			if err != nil {
				t.Fatal(err)
			}
			otherKey, err := mldsa.GenerateKey(method.Params)
			if err != nil {
				t.Fatal(err)
			}
			message := "test"
			signature, err := key.Sign(nil, []byte(message), &mldsa.Options{})
			if err != nil {
				t.Fatal(err)
			}
			contextSignature, err := key.Sign(nil, []byte(message), &mldsa.Options{Context: "other"})
			if err != nil {
				t.Fatal(err)
			}
			for _, data := range []struct {
				name      string
				message   string
				signature []byte
				key       any
				want      error
			}{
				{"valid", message, signature, key.PublicKey(), nil},
				{"changed message", message + "x", signature, key.PublicKey(), jwt.ErrMLDSAVerification},
				{"short signature", message, signature[:len(signature)-1], key.PublicKey(), jwt.ErrMLDSAVerification},
				{"wrong key", message, signature, otherKey.PublicKey(), jwt.ErrMLDSAVerification},
				{"wrong context", message, contextSignature, key.PublicKey(), jwt.ErrMLDSAVerification},
				{"wrong type", message, signature, "key", jwt.ErrInvalidKeyType},
				{"nil key", message, signature, (*mldsa.PublicKey)(nil), jwt.ErrInvalidKey},
				{"zero key", message, signature, &mldsa.PublicKey{}, jwt.ErrInvalidKey},
			} {
				t.Run(data.name, func(t *testing.T) {
					if err := method.Verify(data.message, data.signature, data.key); !errors.Is(err, data.want) {
						t.Fatalf("Verify() = %v, want %v", err, data.want)
					}
				})
			}
			for _, other := range mldsaTestMethods {
				if other == method {
					continue
				}
				if err := other.Verify(message, signature, key.PublicKey()); !errors.Is(err, jwt.ErrInvalidKey) {
					t.Fatalf("Verify() accepted %s key for %s: %v", method.Alg(), other.Alg(), err)
				}
			}
		})
	}
}

type mldsaTestSigner struct {
	publicKey crypto.PublicKey
	sign      func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

func (s mldsaTestSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s mldsaTestSigner) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.sign(random, message, opts)
}
