package jwt

import (
	"testing"
)

func TestParseUnverified_PopulatesSignature(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.test_signature"

	token, _, err := NewParser().ParseUnverified(tokenString, MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified failed unexpectedly: %v", err)
	}

	if len(token.Signature) == 0 {
		t.Errorf("expected token.Signature to be populated, but it was empty")
	}
}
