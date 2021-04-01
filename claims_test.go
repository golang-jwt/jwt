package jwt

import (
	"testing"
	"time"
)

func Test_StandardClaims_VerifyExpiresAt_empty(t *testing.T) {
	c := StandardClaims{}
	if !c.VerifyExpiresAt(time.Now(), false) {
		t.Fatalf("Failed to verify exp claim, wanted: %v got %v", true, false)
	}
}

func Test_StandardClaims_VerifyExpiresAt_expired(t *testing.T) {
	c := StandardClaims{
		ExpiresAt: float64(time.Now().Add(-1*time.Hour).Unix()) + 0.123,
	}
	if c.VerifyExpiresAt(time.Now(), true) {
		t.Fatalf("Failed to verify exp claim, wanted: %v got %v", false, true)
	}
}

func Test_StandardClaims_VerifyExpiresAt_not_expired(t *testing.T) {
	c := StandardClaims{
		ExpiresAt: float64(time.Now().Add(1*time.Hour).Unix()) + 0.123,
	}
	if !c.VerifyExpiresAt(time.Now(), true) {
		t.Fatalf("Failed to verify exp claim, wanted: %v got %v", true, false)
	}
}

func Test_StandardClaims_VerifyIssuedAt_empty(t *testing.T) {
	c := StandardClaims{}
	if !c.VerifyIssuedAt(time.Now(), false) {
		t.Fatalf("Failed to verify iat claim, wanted: %v got %v", true, false)
	}
}

func Test_StandardClaims_VerifyIssuedAt_expired(t *testing.T) {
	c := StandardClaims{
		IssuedAt: float64(time.Now().Add(1*time.Hour).Unix()) + 0.123,
	}
	if c.VerifyIssuedAt(time.Now(), true) {
		t.Fatalf("Failed to verify iat claim, wanted: %v got %v", false, true)
	}
}

func Test_StandardClaims_VerifyIssuedAt_past(t *testing.T) {
	c := StandardClaims{
		IssuedAt: float64(time.Now().Add(-1*time.Hour).Unix()) + 0.123,
	}
	if !c.VerifyIssuedAt(time.Now(), true) {
		t.Fatalf("Failed to verify iat claim, wanted: %v got %v", true, false)
	}
}

func Test_StandardClaims_VerifyNotBefore_empty(t *testing.T) {
	c := StandardClaims{}
	if !c.VerifyNotBefore(time.Now(), false) {
		t.Fatalf("Failed to verify nbf claim, wanted: %v got %v", true, false)
	}
}

func Test_StandardClaims_VerifyNotBefore_expired(t *testing.T) {
	c := StandardClaims{
		NotBefore: float64(time.Now().Add(1*time.Hour).Unix()) + 0.123,
	}
	if c.VerifyNotBefore(time.Now(), true) {
		t.Fatalf("Failed to verify nbf claim, wanted: %v got %v", false, true)
	}
}

func Test_StandardClaims_VerifyNotBefore_passed(t *testing.T) {
	c := StandardClaims{
		NotBefore: float64(time.Now().Add(-1*time.Hour).Unix()) + 0.123,
	}
	if !c.VerifyNotBefore(time.Now(), true) {
		t.Fatalf("Failed to verify nbf claim, wanted: %v got %v", true, false)
	}
}
