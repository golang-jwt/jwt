package jwt

import (
	"testing"
	"time"
)

func TestPhiVerify_AllCases(t *testing.T) {
	key, _ := GeneratePhiKey(PhiFalcon)
	method := NewPhiQuantumMethod(PhiFalcon)

	t.Run("ValidToken", func(t *testing.T) {
		token := NewWithClaims(method, MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		tokenString, _ := token.SignedString(key)

		parsed, err := Parse(tokenString, func(t *Token) (interface{}, error) {
			return key, nil
		})
		if err != nil {
			t.Fatalf("Valid token rejected: %v", err)
		}
		if !parsed.Valid {
			t.Fatal("Valid token marked invalid")
		}
		t.Log("✓ Valid token accepted")
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		token := NewWithClaims(method, MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(-time.Hour).Unix(), // EXPIRED
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		})
		tokenString, _ := token.SignedString(key)

		parsed, err := Parse(tokenString, func(t *Token) (interface{}, error) {
			return key, nil
		})
		if err == nil {
			t.Error("Expired token should return error")
		}
		if parsed != nil && parsed.Valid {
			t.Error("Expired token should be invalid")
		}
		t.Log("✓ Expired token rejected:", err)
	})

	t.Run("WrongKey", func(t *testing.T) {
		token := NewWithClaims(method, MapClaims{
			"sub": "user123",
		})
		tokenString, _ := token.SignedString(key)

		badKey, _ := GeneratePhiKey(PhiFalcon)
		parsed, err := Parse(tokenString, func(t *Token) (interface{}, error) {
			return badKey, nil
		})
		if err == nil {
			t.Error("Token with wrong key should fail")
		}
		if parsed != nil && parsed.Valid {
			t.Error("Token with wrong key should be invalid")
		}
		t.Log("✓ Wrong key rejected:", err)
	})

	t.Run("WrongAlgorithm", func(t *testing.T) {
		// Create token with Falcon
		token := NewWithClaims(method, MapClaims{
			"sub": "user123",
		})
		tokenString, _ := token.SignedString(key)

		// Try to parse with Dilithium method
		dilithiumKey, _ := GeneratePhiKey(PhiDilithium)
		parsed, err := Parse(tokenString, func(t *Token) (interface{}, error) {
			return dilithiumKey, nil
		})
		if err == nil {
			t.Error("Token with wrong algorithm should fail")
		}
		if parsed != nil && parsed.Valid {
			t.Error("Token with wrong algorithm should be invalid")
		}
		t.Log("✓ Wrong algorithm rejected:", err)
	})

	t.Run("TamperedToken", func(t *testing.T) {
		token := NewWithClaims(method, MapClaims{
			"sub": "user123",
			"admin": false,
		})
		tokenString, _ := token.SignedString(key)

		// Tamper: change the token string
		tampered := tokenString[:len(tokenString)-5] + "xxxxx"

		parsed, err := Parse(tampered, func(t *Token) (interface{}, error) {
			return key, nil
		})
		if err == nil {
			t.Error("Tampered token should fail")
		}
		if parsed != nil && parsed.Valid {
			t.Error("Tampered token should be invalid")
		}
		t.Log("✓ Tampered token rejected:", err)
	})

	t.Run("EmptyToken", func(t *testing.T) {
		_, err := Parse("", func(t *Token) (interface{}, error) {
			return key, nil
		})
		if err == nil {
			t.Error("Empty token should fail")
		}
		t.Log("✓ Empty token rejected:", err)
	})

	t.Run("MissingSignature", func(t *testing.T) {
		token := NewWithClaims(method, MapClaims{"sub": "user123"})
		tokenString, _ := token.SignedString(key)
		// Remove signature part
		parts, _ := splitToken(tokenString)
		noSig := parts[0] + "." + parts[1] + ".xxx" // missing signature

		_, err := Parse(noSig, func(t *Token) (interface{}, error) {
			return key, nil
		})
		if err == nil {
			t.Error("Token without signature should fail")
		}
		t.Log("✓ Missing signature rejected:", err)
	})

	t.Run("NoneAlgorithm", func(t *testing.T) {
		// Someone might try to use "none" algorithm to bypass
		token := NewWithClaims(method, MapClaims{"sub": "hacker"})
		token.Header["alg"] = "none"
		tokenString, _ := token.SignedString(key)

		parsed, err := Parse(tokenString, func(t *Token) (interface{}, error) {
			return key, nil
		})
		// Should fail because signature doesn't match "none"
		if parsed != nil && parsed.Valid {
			t.Error("Token with 'none' algorithm should be invalid")
		}
		t.Log("✓ None algorithm attack rejected:", err)
	})
}


func TestPhiVerify_BruteForce(t *testing.T) {
	key, _ := GeneratePhiKey(PhiFalcon)
	method := NewPhiQuantumMethod(PhiFalcon)

	token := NewWithClaims(method, MapClaims{
		"sub": "target",
		"role": "admin",
	})
	tokenString, _ := token.SignedString(key)

	// Try 100 random keys — NONE should work
	for i := 0; i < 100; i++ {
		badKey, _ := GeneratePhiKey(PhiFalcon)
		parsed, err := Parse(tokenString, func(t *Token) (interface{}, error) {
			return badKey, nil
		})
		if err == nil && parsed.Valid {
			t.Fatalf("BRUTE FORCE SUCCEEDED at attempt %d! Key collision!", i)
		}
	}

	t.Log("✓ Brute force test passed: 100 random keys all rejected")
}
