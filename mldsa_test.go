//go:build go1.25

package jwt_test

import (
	"strings"
	"testing"

	"filippo.io/mldsa"
	"github.com/golang-jwt/jwt/v5"
)

var mldsaTestData = []struct {
	name   string
	alg    string
	params *mldsa.Parameters
	method *jwt.SigningMethodMLDSA
}{
	{
		"ML-DSA-44",
		"ML-DSA-44",
		mldsa.MLDSA44(),
		jwt.SigningMethodMLDSA44,
	},
	{
		"ML-DSA-65",
		"ML-DSA-65",
		mldsa.MLDSA65(),
		jwt.SigningMethodMLDSA65,
	},
	{
		"ML-DSA-87",
		"ML-DSA-87",
		mldsa.MLDSA87(),
		jwt.SigningMethodMLDSA87,
	},
}

func TestMLDSAAlg(t *testing.T) {
	for _, data := range mldsaTestData {
		if data.method.Alg() != data.alg {
			t.Errorf("[%v] Alg() = %v, want %v", data.name, data.method.Alg(), data.alg)
		}
	}
}

func TestMLDSAGetSigningMethod(t *testing.T) {
	for _, data := range mldsaTestData {
		method := jwt.GetSigningMethod(data.alg)
		if method == nil {
			t.Errorf("[%v] GetSigningMethod(%v) returned nil", data.name, data.alg)
		}
		if method.Alg() != data.alg {
			t.Errorf("[%v] GetSigningMethod(%v).Alg() = %v, want %v", data.name, data.alg, method.Alg(), data.alg)
		}
	}
}

func TestMLDSASignAndVerify(t *testing.T) {
	for _, data := range mldsaTestData {
		t.Run(data.name, func(t *testing.T) {
			// Generate key pair
			sk, err := mldsa.GenerateKey(data.params)
			if err != nil {
				t.Fatalf("Failed to generate ML-DSA key: %v", err)
			}
			pk := sk.PublicKey()

			method := jwt.GetSigningMethod(data.alg)

			// Create a token and sign it
			token := jwt.NewWithClaims(method, jwt.MapClaims{
				"foo": "bar",
			})
			tokenString, err := token.SignedString(sk)
			if err != nil {
				t.Fatalf("Error signing token: %v", err)
			}

			// Parse and verify the token
			parts := strings.Split(tokenString, ".")
			if len(parts) != 3 {
				t.Fatalf("Token should have 3 parts, got %d", len(parts))
			}

			sig := decodeSegment(t, parts[2])
			err = method.Verify(strings.Join(parts[0:2], "."), sig, pk)
			if err != nil {
				t.Errorf("Error verifying token: %v", err)
			}
		})
	}
}

func TestMLDSAVerifyTamperedToken(t *testing.T) {
	for _, data := range mldsaTestData {
		t.Run(data.name, func(t *testing.T) {
			sk, err := mldsa.GenerateKey(data.params)
			if err != nil {
				t.Fatalf("Failed to generate ML-DSA key: %v", err)
			}
			pk := sk.PublicKey()

			method := jwt.GetSigningMethod(data.alg)

			// Sign a token
			token := jwt.NewWithClaims(method, jwt.MapClaims{
				"foo": "bar",
			})
			tokenString, err := token.SignedString(sk)
			if err != nil {
				t.Fatalf("Error signing token: %v", err)
			}

			parts := strings.Split(tokenString, ".")
			sig := decodeSegment(t, parts[2])

			// Tamper with the signing string
			tampered := strings.Join(parts[0:2], ".") + "tampered"
			err = method.Verify(tampered, sig, pk)
			if err == nil {
				t.Error("Expected verification to fail with tampered token")
			}
		})
	}
}

func TestMLDSAVerifyWrongKey(t *testing.T) {
	for _, data := range mldsaTestData {
		t.Run(data.name, func(t *testing.T) {
			sk, err := mldsa.GenerateKey(data.params)
			if err != nil {
				t.Fatalf("Failed to generate ML-DSA key: %v", err)
			}

			// Generate a different key pair
			sk2, err := mldsa.GenerateKey(data.params)
			if err != nil {
				t.Fatalf("Failed to generate second ML-DSA key: %v", err)
			}
			pk2 := sk2.PublicKey()

			method := jwt.GetSigningMethod(data.alg)

			// Sign with first key
			token := jwt.NewWithClaims(method, jwt.MapClaims{
				"foo": "bar",
			})
			tokenString, err := token.SignedString(sk)
			if err != nil {
				t.Fatalf("Error signing token: %v", err)
			}

			parts := strings.Split(tokenString, ".")
			sig := decodeSegment(t, parts[2])

			// Verify with wrong key
			err = method.Verify(strings.Join(parts[0:2], "."), sig, pk2)
			if err == nil {
				t.Error("Expected verification to fail with wrong key")
			}
		})
	}
}

func TestMLDSASignInvalidKey(t *testing.T) {
	for _, data := range mldsaTestData {
		t.Run(data.name, func(t *testing.T) {
			method := jwt.GetSigningMethod(data.alg)

			// Try signing with invalid key type
			_, err := method.Sign("test", "not a key")
			if err == nil {
				t.Error("Expected error when signing with invalid key type")
			}
		})
	}
}

func TestMLDSAVerifyInvalidKey(t *testing.T) {
	for _, data := range mldsaTestData {
		t.Run(data.name, func(t *testing.T) {
			method := jwt.GetSigningMethod(data.alg)

			// Try verifying with invalid key type
			err := method.Verify("test", []byte("sig"), "not a key")
			if err == nil {
				t.Error("Expected error when verifying with invalid key type")
			}
		})
	}
}

func TestMLDSANilKey(t *testing.T) {
	t.Run("Verify with nil public key", func(t *testing.T) {
		method := jwt.GetSigningMethod("ML-DSA-44")
		err := method.Verify("test", []byte("sig"), (*mldsa.PublicKey)(nil))
		if err == nil {
			t.Error("Expected error when verifying with nil public key")
		}
	})

	t.Run("Sign with nil private key", func(t *testing.T) {
		method := jwt.GetSigningMethod("ML-DSA-44")
		_, err := method.Sign("test", (*mldsa.PrivateKey)(nil))
		if err == nil {
			t.Error("Expected error when signing with nil private key")
		}
	})
}

func TestMLDSAParameterMismatch(t *testing.T) {
	// Sign with ML-DSA-44 key, try to verify with ML-DSA-65 method
	sk44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-44 key: %v", err)
	}

	method44 := jwt.GetSigningMethod("ML-DSA-44")
	method65 := jwt.GetSigningMethod("ML-DSA-65")

	// Sign with correct method
	token := jwt.NewWithClaims(method44, jwt.MapClaims{"foo": "bar"})
	tokenString, err := token.SignedString(sk44)
	if err != nil {
		t.Fatalf("Error signing token: %v", err)
	}

	parts := strings.Split(tokenString, ".")
	sig := decodeSegment(t, parts[2])

	// Try to verify with wrong parameter set method
	pk44 := sk44.PublicKey()
	err = method65.Verify(strings.Join(parts[0:2], "."), sig, pk44)
	if err == nil {
		t.Error("Expected error when verifying ML-DSA-44 signature with ML-DSA-65 method")
	}
}

func TestMLDSAFullTokenRoundTrip(t *testing.T) {
	for _, data := range mldsaTestData {
		t.Run(data.name, func(t *testing.T) {
			sk, err := mldsa.GenerateKey(data.params)
			if err != nil {
				t.Fatalf("Failed to generate ML-DSA key: %v", err)
			}
			pk := sk.PublicKey()

			claims := jwt.MapClaims{
				"sub":  "1234567890",
				"name": "Quantum Safe",
				"iat":  1516239022,
			}

			// Create and sign token
			token := jwt.NewWithClaims(data.method, claims)
			tokenString, err := token.SignedString(sk)
			if err != nil {
				t.Fatalf("Error signing token: %v", err)
			}

			// Parse and verify token
			parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodMLDSA); !ok {
					t.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return pk, nil
			})
			if err != nil {
				t.Fatalf("Error parsing token: %v", err)
			}
			if !parsed.Valid {
				t.Error("Token should be valid")
			}

			mc, ok := parsed.Claims.(jwt.MapClaims)
			if !ok {
				t.Fatal("Claims should be MapClaims")
			}
			if mc["sub"] != "1234567890" {
				t.Errorf("sub claim = %v, want 1234567890", mc["sub"])
			}
			if mc["name"] != "Quantum Safe" {
				t.Errorf("name claim = %v, want Quantum Safe", mc["name"])
			}
		})
	}
}

func BenchmarkMLDSASigning(b *testing.B) {
	for _, data := range mldsaTestData {
		sk, err := mldsa.GenerateKey(data.params)
		if err != nil {
			b.Fatalf("Failed to generate ML-DSA key: %v", err)
		}

		b.Run(data.name, func(b *testing.B) {
			benchmarkSigning(b, data.method, sk)
		})
	}
}

func BenchmarkMLDSAVerification(b *testing.B) {
	for _, data := range mldsaTestData {
		sk, err := mldsa.GenerateKey(data.params)
		if err != nil {
			b.Fatalf("Failed to generate ML-DSA key: %v", err)
		}
		pk := sk.PublicKey()

		token := jwt.NewWithClaims(data.method, jwt.MapClaims{"foo": "bar"})
		tokenString, err := token.SignedString(sk)
		if err != nil {
			b.Fatalf("Error signing token: %v", err)
		}

		parts := strings.Split(tokenString, ".")
		signingString := strings.Join(parts[0:2], ".")
		sig := decodeSegment(b, parts[2])

		b.Run(data.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := data.method.Verify(signingString, sig, pk)
				if err != nil {
					b.Fatalf("Error verifying token: %v", err)
				}
			}
		})
	}
}
