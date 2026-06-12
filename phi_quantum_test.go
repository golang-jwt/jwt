package jwt

import (
	"testing"
)

func TestPhiQuantumSigning(t *testing.T) {
	// Generate φ-quantum key
	key, err := GeneratePhiKey(PhiFalcon)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	// Create signing method
	method := NewPhiQuantumMethod(PhiFalcon)
	
	// Test signing
	signingString := "test.claims.payload"
	sig, err := method.Sign(signingString, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	
	if len(sig) == 0 {
		t.Fatal("Signature is empty")
	}
	
	t.Logf("Signature length: %d bytes", len(sig))
	t.Logf("Algorithm: %s", key.Algorithm)
	t.Logf("Divine noise: %.2f", key.DivineNoise)
	
	// Test verification
	err = method.Verify(signingString, sig, key)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	
	t.Log("✓ Signature verified!")
	
	// Test with wrong key
	badKey, _ := GeneratePhiKey(PhiFalcon)
	err = method.Verify(signingString, sig, badKey)
	if err == nil {
		t.Fatal("Should have failed with wrong key")
	}
	
	t.Log("✓ Wrong key rejected!")
}

func TestPhiJWTTokenCreation(t *testing.T) {
	// Generate key
	key, _ := GeneratePhiKey(PhiDilithium)
	
	// Create token
	token := NewWithClaims(NewPhiQuantumMethod(PhiDilithium), MapClaims{
		"sub":  "1234567890",
		"name": "Phi Quantum User",
		"iat":  1700000000,
	})
	
	// Sign token
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	
	t.Logf("Φ-JWT Token: %s...", tokenString[:50])
	t.Logf("Token length: %d", len(tokenString))
	
	// Parse token
	parsedToken, err := Parse(tokenString, func(token *Token) (interface{}, error) {
		return key, nil
	})
	
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	if !parsedToken.Valid {
		t.Fatal("Token should be valid")
	}
	
	t.Log("✓ Φ-JWT Token created and verified!")
	t.Log("✓ Post-quantum hybrid JWT working!")
}
