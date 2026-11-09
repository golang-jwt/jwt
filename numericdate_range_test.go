package jwt_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// An out-of-range numeric date (e.g. exp/nbf far beyond int64 seconds) used to
// wrap around inside time.Unix and produce a time.Time that formats as a
// far-future date but compares as if it were in the past. That inverted the
// exp/nbf checks: a far-future nbf was accepted as currently valid (fail open)
// and a far-future exp was rejected as expired. Such values must now be
// rejected when decoding.
func TestNumericDate_OutOfRange_RejectedOnDecode(t *testing.T) {
	for _, claim := range []string{"exp", "nbf", "iat"} {
		raw := []byte(`{"` + claim + `": 1e19}`)

		var rc jwt.RegisteredClaims
		if err := json.Unmarshal(raw, &rc); err == nil {
			t.Errorf("RegisteredClaims: expected error decoding out-of-range %q, got nil", claim)
		} else if !errors.Is(err, jwt.ErrInvalidType) {
			t.Errorf("RegisteredClaims: %q error = %v, want wrapping ErrInvalidType", claim, err)
		}
	}
}

// A far-future nbf must make the token "not valid yet" instead of being
// silently accepted (the pre-fix fail-open behavior).
func TestNumericDate_OutOfRange_MapClaimsAccessorErrors(t *testing.T) {
	var m jwt.MapClaims
	if err := json.Unmarshal([]byte(`{"nbf": 1e19}`), &m); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if _, err := m.GetNotBefore(); err == nil {
		t.Fatal("MapClaims.GetNotBefore: expected error for out-of-range nbf, got nil")
	} else if !errors.Is(err, jwt.ErrInvalidType) {
		t.Fatalf("MapClaims.GetNotBefore error = %v, want wrapping ErrInvalidType", err)
	}
}

// Real-world dates (including the maximum RFC 3339 year 9999) must keep
// decoding without error.
func TestNumericDate_InRange_StillDecodes(t *testing.T) {
	// 253402300799 = 9999-12-31T23:59:59Z, the largest calendar date.
	for _, raw := range []string{`{"exp": 253402300799}`, `{"nbf": 1516239022}`, `{"iat": 0}`, `{"nbf": -1}`} {
		var rc jwt.RegisteredClaims
		if err := json.Unmarshal([]byte(raw), &rc); err != nil {
			t.Errorf("in-range decode %s failed: %v", raw, err)
		}

		var m jwt.MapClaims
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("map decode %s failed: %v", raw, err)
		}
		if _, err := m.GetExpirationTime(); err != nil {
			t.Errorf("in-range MapClaims.GetExpirationTime %s failed: %v", raw, err)
		}
		if _, err := m.GetNotBefore(); err != nil {
			t.Errorf("in-range MapClaims.GetNotBefore %s failed: %v", raw, err)
		}
	}
}
