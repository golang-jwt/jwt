package jwt

import (
	"errors"
	"testing"
)

// Test_containsConstantTime pins the exact membership semantics of the
// constant-time set membership helper used by verifyAudience. The behavioral
// contract is identical to slices.Contains; the difference is that every element
// of the set is compared in full before the function returns.
func Test_containsConstantTime(t *testing.T) {
	tests := []struct {
		name string
		set  []string
		s    string
		want bool
	}{
		{name: "nil set contains nothing", set: nil, s: "example.com", want: false},
		{name: "nil set does not contain the empty string", set: nil, s: "", want: false},
		{name: "empty set contains nothing", set: []string{}, s: "example.com", want: false},
		{name: "single member", set: []string{"example.com"}, s: "example.com", want: true},
		{name: "single non member", set: []string{"example.com"}, s: "example.org", want: false},
		{name: "match at first position", set: []string{"a.example", "b.example", "c.example"}, s: "a.example", want: true},
		{name: "match at last position", set: []string{"a.example", "b.example", "c.example"}, s: "c.example", want: true},
		{name: "duplicated members still match", set: []string{"example.com", "example.com"}, s: "example.com", want: true},
		{name: "no partial or prefix matches", set: []string{"example"}, s: "example.com", want: false},
		{name: "empty string is a matchable member", set: []string{"", "example.com"}, s: "", want: true},
		{name: "values of different length never match", set: []string{"a", "aa", "aaa"}, s: "aaaa", want: false},
		{name: "multibyte values match byte for byte", set: []string{"unicode-raw.example"}, s: "unicode-raw.example", want: true},
		{name: "matching is case sensitive", set: []string{"Example.com"}, s: "example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsConstantTime(tt.set, tt.s); got != tt.want {
				t.Errorf("containsConstantTime(%q, %q) = %v, want %v", tt.set, tt.s, got, tt.want)
			}
		})
	}
}

// Test_Validator_verifyAudience_match_positions covers both audience modes
// with the matching value at every position of the claim, and with expected
// values at every position of the comparison set. Both must be position
// independent: the result must not depend on which element matched, only on
// whether one did.
func Test_Validator_verifyAudience_match_positions(t *testing.T) {
	audFive := ClaimStrings{"a.example", "b.example", "c.example", "d.example", "e.example"}

	for _, pos := range []int{0, 2, 4} {
		matched := audFive[pos]
		t.Run("any-mode match at position "+string(rune('0'+pos)), func(t *testing.T) {
			v := &Validator{expectedAud: []string{matched}}
			if err := v.verifyAudience(RegisteredClaims{Audience: audFive}, []string{matched}, false); err != nil {
				t.Errorf("verifyAudience() error = %v, wantErr nil", err)
			}
		})
		t.Run("all-mode expects value at position "+string(rune('0'+pos)), func(t *testing.T) {
			v := &Validator{expectedAud: []string{matched}, expectAllAud: true}
			if err := v.verifyAudience(RegisteredClaims{Audience: audFive}, []string{matched}, true); err != nil {
				t.Errorf("verifyAudience() error = %v, wantErr nil", err)
			}
		})
	}

	t.Run("any-mode walks the whole claim list", func(t *testing.T) {
		// The only audience that matches sits at the end of the claim; a
		// match anywhere in the claim must be accepted.
		v := &Validator{expectedAud: []string{"e.example"}}
		claims := RegisteredClaims{Audience: ClaimStrings{"x.example", "y.example", "e.example"}}
		if err := v.verifyAudience(claims, []string{"e.example"}, false); err != nil {
			t.Errorf("verifyAudience() error = %v, wantErr nil", err)
		}
	})

	t.Run("any-mode walks the whole expected list", func(t *testing.T) {
		// The matching expected value sits at the end of the comparison set.
		v := &Validator{expectedAud: []string{"x.example", "y.example", "e.example"}}
		claims := RegisteredClaims{Audience: ClaimStrings{"e.example"}}
		if err := v.verifyAudience(claims, []string{"x.example", "y.example", "e.example"}, false); err != nil {
			t.Errorf("verifyAudience() error = %v, wantErr nil", err)
		}
	})

	t.Run("all-mode superset of expected values passes", func(t *testing.T) {
		v := &Validator{expectedAud: []string{"a.example", "c.example"}, expectAllAud: true}
		if err := v.verifyAudience(RegisteredClaims{Audience: audFive}, []string{"a.example", "c.example"}, true); err != nil {
			t.Errorf("verifyAudience() error = %v, wantErr nil", err)
		}
	})

	t.Run("all-mode with duplicates in the claim passes", func(t *testing.T) {
		v := &Validator{expectedAud: []string{"a.example"}, expectAllAud: true}
		claims := RegisteredClaims{Audience: ClaimStrings{"a.example", "a.example", "b.example"}}
		if err := v.verifyAudience(claims, []string{"a.example"}, true); err != nil {
			t.Errorf("verifyAudience() error = %v, wantErr nil", err)
		}
	})

	t.Run("all-mode missing first expected value fails", func(t *testing.T) {
		v := &Validator{expectedAud: []string{"a.example", "b.example"}, expectAllAud: true}
		claims := RegisteredClaims{Audience: ClaimStrings{"b.example", "c.example"}}
		if err := v.verifyAudience(claims, []string{"a.example", "b.example"}, true); !errors.Is(err, ErrTokenInvalidAudience) {
			t.Errorf("verifyAudience() error = %v, wantErr %v", err, ErrTokenInvalidAudience)
		}
	})

	t.Run("all-mode missing last expected value fails", func(t *testing.T) {
		v := &Validator{expectedAud: []string{"a.example", "b.example"}, expectAllAud: true}
		claims := RegisteredClaims{Audience: ClaimStrings{"a.example", "c.example"}}
		if err := v.verifyAudience(claims, []string{"a.example", "b.example"}, true); !errors.Is(err, ErrTokenInvalidAudience) {
			t.Errorf("verifyAudience() error = %v, wantErr %v", err, ErrTokenInvalidAudience)
		}
	})

	t.Run("any-mode claim with leading empty string still matches later values", func(t *testing.T) {
		// A two-element claim whose first element is empty is not the
		// canonical empty claim (that is a single empty string), so a
		// later matching value must be honored.
		v := &Validator{expectedAud: []string{"e.example"}}
		claims := RegisteredClaims{Audience: ClaimStrings{"", "e.example"}}
		if err := v.verifyAudience(claims, []string{"e.example"}, false); err != nil {
			t.Errorf("verifyAudience() error = %v, wantErr nil", err)
		}
	})

	t.Run("all-mode claim with leading empty string still matches later values", func(t *testing.T) {
		v := &Validator{expectedAud: []string{"e.example"}, expectAllAud: true}
		claims := RegisteredClaims{Audience: ClaimStrings{"", "e.example"}}
		if err := v.verifyAudience(claims, []string{"e.example"}, true); err != nil {
			t.Errorf("verifyAudience() error = %v, wantErr nil", err)
		}
	})

	t.Run("any-mode with no expected values fails on a non-empty claim", func(t *testing.T) {
		// expectAllAud=false with an empty comparison set can never
		// produce a match, but the claim must still be read in full.
		v := &Validator{}
		if err := v.verifyAudience(RegisteredClaims{Audience: audFive}, nil, false); !errors.Is(err, ErrTokenInvalidAudience) {
			t.Errorf("verifyAudience() error = %v, wantErr %v", err, ErrTokenInvalidAudience)
		}
	})

	t.Run("all-mode with no expected values passes", func(t *testing.T) {
		// expectAllAud=true with an empty comparison set is vacuously
		// satisfied, matching the behavior of the early-exit loop.
		v := &Validator{expectAllAud: true}
		if err := v.verifyAudience(RegisteredClaims{Audience: audFive}, nil, true); err != nil {
			t.Errorf("verifyAudience() error = %v, wantErr nil", err)
		}
	})
}

// Test_Validator_audience_end_to_end runs the public Validator entry points
// over a multi-valued aud claim whose matching value sits at the end, so the
// full end-to-end path (including WithAudience and WithAllAudiences) is
// covered for the constant-time comparison.
func Test_Validator_audience_end_to_end(t *testing.T) {
	claims := RegisteredClaims{
		Audience: ClaimStrings{"x.example", "y.example", "z.example"},
	}

	t.Run("WithAudience accepts a match at the end of the claim", func(t *testing.T) {
		v := NewValidator(WithAudience("z.example"))
		if err := v.Validate(claims); err != nil {
			t.Errorf("Validate() error = %v, wantErr nil", err)
		}
	})

	t.Run("WithAudience rejects a non-member", func(t *testing.T) {
		v := NewValidator(WithAudience("w.example"))
		if err := v.Validate(claims); !errors.Is(err, ErrTokenInvalidAudience) {
			t.Errorf("Validate() error = %v, wantErr %v", err, ErrTokenInvalidAudience)
		}
	})

	t.Run("WithAllAudiences accepts a subset claim", func(t *testing.T) {
		v := NewValidator(WithAllAudiences("x.example", "z.example"))
		if err := v.Validate(claims); err != nil {
			t.Errorf("Validate() error = %v, wantErr nil", err)
		}
	})

	t.Run("WithAllAudiences rejects a missing expected value", func(t *testing.T) {
		v := NewValidator(WithAllAudiences("x.example", "w.example"))
		if err := v.Validate(claims); !errors.Is(err, ErrTokenInvalidAudience) {
			t.Errorf("Validate() error = %v, wantErr %v", err, ErrTokenInvalidAudience)
		}
	})
}
