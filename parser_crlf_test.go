package jwt_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseRejectsCRLFinCompactSerializationSegments(t *testing.T) {
	key := []byte("secret")
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "test"}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	originalParts := strings.Split(token, ".")
	tests := []struct {
		name      string
		segment   int
		lineBreak string
	}{
		{name: "header CR", segment: 0, lineBreak: "\r"},
		{name: "header LF", segment: 0, lineBreak: "\n"},
		{name: "payload CR", segment: 1, lineBreak: "\r"},
		{name: "payload LF", segment: 1, lineBreak: "\n"},
		{name: "signature CR", segment: 2, lineBreak: "\r"},
		{name: "signature LF", segment: 2, lineBreak: "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := append([]string(nil), originalParts...)
			segment := parts[tt.segment]
			cut := len(segment) / 2
			parts[tt.segment] = segment[:cut] + tt.lineBreak + segment[cut:]

			// Keep the mutated header or payload token validly signed so the
			// test isolates acceptance of line breaks in compact serialization.
			if tt.segment != 2 {
				signature, err := jwt.SigningMethodHS256.Sign(parts[0]+"."+parts[1], key)
				if err != nil {
					t.Fatal(err)
				}
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
			}

			mutatedToken := strings.Join(parts, ".")
			parsed, err := jwt.Parse(mutatedToken, func(*jwt.Token) (any, error) {
				return key, nil
			})
			if !errors.Is(err, jwt.ErrTokenMalformed) {
				t.Fatalf("expected malformed-token error, got token=%#v err=%v", parsed, err)
			}
			if parsed != nil && parsed.Valid {
				t.Fatal("token with a line break was marked valid")
			}
		})
	}
}
