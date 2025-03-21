package jwt

import (
	"testing"
)

func TestSplitToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
		isValid  bool
	}{
		{
			name:     "valid token with three parts",
			input:    "header.claims.signature",
			expected: []string{"header", "claims", "signature"},
			isValid:  true,
		},
		{
			name:     "invalid token with two parts only",
			input:    "header.claims",
			expected: nil,
			isValid:  false,
		},
		{
			name:     "invalid token with one part only",
			input:    "header",
			expected: nil,
			isValid:  false,
		},
		{
			name:     "invalid token with extra delimiter",
			input:    "header.claims.signature.extra",
			expected: nil,
			isValid:  false,
		},
		{
			name:     "invalid empty token",
			input:    "",
			expected: nil,
			isValid:  false,
		},
		{
			name:     "valid token with empty parts",
			input:    "..signature",
			expected: []string{"", "", "signature"},
			isValid:  true,
		},
		{
			// We are just splitting the token into parts, so we don't care about the actual values.
			// It is up to the caller to validate the parts.
			name:     "valid token with all parts empty",
			input:    "..",
			expected: []string{"", "", ""},
			isValid:  true,
		},
		{
			name:     "invalid token with just delimiters and extra part",
			input:    "...",
			expected: nil,
			isValid:  false,
		},
		{
			name:     "invalid token with many delimiters",
			input:    "header.claims.signature..................",
			expected: nil,
			isValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, ok := splitToken(tt.input)
			if ok != tt.isValid {
				t.Errorf("expected %t, got %t", tt.isValid, ok)
			}
			if ok {
				for i, part := range tt.expected {
					if parts[i] != part {
						t.Errorf("expected %s, got %s", part, parts[i])
					}
				}
			}
		})
	}
}
