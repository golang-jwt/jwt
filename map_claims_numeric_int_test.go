package jwt

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Manually constructed MapClaims commonly use time.Time.Unix() (int64) for
// exp/nbf/iat. parseNumericDate historically only accepted float64 and
// json.Number — the types encoding/json produces — so Validate rejected
// otherwise-valid integer claims with ErrInvalidType.
func TestMapClaims_IntegerNumericDates(t *testing.T) {
	now := time.Unix(1_700_000_060, 0)
	exp := now.Add(time.Hour).Unix()
	nbf := now.Add(-time.Minute).Unix()
	iat := now.Unix()

	cases := []struct {
		name   string
		claims MapClaims
	}{
		{
			name:   "int64",
			claims: MapClaims{"exp": exp, "nbf": nbf, "iat": iat},
		},
		{
			name:   "int",
			claims: MapClaims{"exp": int(exp), "nbf": int(nbf), "iat": int(iat)},
		},
		{
			name: "json.Number still works",
			claims: MapClaims{
				"exp": json.Number("1700003660"),
				"nbf": json.Number("1700000000"),
				"iat": json.Number("1700000060"),
			},
		},
		{
			name:   "float64 still works",
			claims: MapClaims{"exp": float64(exp), "nbf": float64(nbf), "iat": float64(iat)},
		},
	}

	v := NewValidator(WithIssuedAt(), WithTimeFunc(func() time.Time { return now }))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.Validate(tc.claims); err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			got, err := tc.claims.GetExpirationTime()
			if err != nil {
				t.Fatalf("GetExpirationTime: %v", err)
			}
			if got == nil || got.Unix() != exp {
				t.Fatalf("GetExpirationTime = %v, want unix %d", got, exp)
			}
		})
	}
}

func TestMapClaims_IntegerNumericDates_Expired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := MapClaims{"exp": int64(1_699_999_999)}
	err := NewValidator(WithTimeFunc(func() time.Time { return now })).Validate(claims)
	if err == nil {
		t.Fatal("expected expiration error for past int64 exp")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Validate = %v, want ErrTokenExpired", err)
	}
}
