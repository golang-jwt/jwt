package jwt_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestDecodeSegment_RejectCRLF(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		opts          []jwt.ParserOption
		expectedIndex int64
	}{
		{
			name:          "CR in middle",
			input:         "eyJhb\rGciOiJIUzI1NiJ9",
			expectedIndex: 5,
		},
		{
			name:          "LF in middle",
			input:         "eyJhb\nGciOiJIUzI1NiJ9",
			expectedIndex: 5,
		},
		{
			name:          "CRLF in middle",
			input:         "eyJhb\r\nGciOiJIUzI1NiJ9",
			expectedIndex: 5,
		},
		{
			name:          "CR at beginning",
			input:         "\reyJhbGciOiJIUzI1NiJ9",
			expectedIndex: 0,
		},
		{
			name:          "LF at beginning",
			input:         "\neyJhbGciOiJIUzI1NiJ9",
			expectedIndex: 0,
		},
		{
			name:          "CR at end",
			input:         "eyJhbGciOiJIUzI1NiJ9\r",
			expectedIndex: 20,
		},
		{
			name:          "LF at end",
			input:         "eyJhbGciOiJIUzI1NiJ9\n",
			expectedIndex: 20,
		},
		{
			name:          "CR with padding allowed",
			input:         "eyJhb\rGciOiJIUzI1NiJ9==",
			opts:          []jwt.ParserOption{jwt.WithPaddingAllowed()},
			expectedIndex: 5,
		},
		{
			name:          "LF with padding allowed",
			input:         "eyJhb\nGciOiJIUzI1NiJ9==",
			opts:          []jwt.ParserOption{jwt.WithPaddingAllowed()},
			expectedIndex: 5,
		},
		{
			name:          "CR with strict decoding",
			input:         "eyJhb\rGciOiJIUzI1NiJ9",
			opts:          []jwt.ParserOption{jwt.WithStrictDecoding()},
			expectedIndex: 5,
		},
		{
			name:          "LF with strict decoding",
			input:         "eyJhb\nGciOiJIUzI1NiJ9",
			opts:          []jwt.ParserOption{jwt.WithStrictDecoding()},
			expectedIndex: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := jwt.NewParser(tt.opts...)
			data, err := parser.DecodeSegment(tt.input)
			if err == nil {
				t.Fatalf("expected error for input %q, got data %v", tt.input, data)
			}

			var corruptErr base64.CorruptInputError
			if !errors.As(err, &corruptErr) {
				t.Fatalf("expected base64.CorruptInputError, got %T: %v", err, err)
			}
			if int64(corruptErr) != tt.expectedIndex {
				t.Fatalf("expected corrupt input index %d, got %d", tt.expectedIndex, corruptErr)
			}
		})
	}
}

func TestParse_RejectCRLFInSegments(t *testing.T) {
	key := []byte("secret")
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "test"}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	originalParts := strings.Split(token, ".")
	if len(originalParts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(originalParts))
	}

	tests := []struct {
		name      string
		segment   int
		lineBreak string
		pos       string
	}{
		{name: "header CR start", segment: 0, lineBreak: "\r", pos: "start"},
		{name: "header LF start", segment: 0, lineBreak: "\n", pos: "start"},
		{name: "header CRLF middle", segment: 0, lineBreak: "\r\n", pos: "middle"},
		{name: "header CR middle", segment: 0, lineBreak: "\r", pos: "middle"},
		{name: "header LF middle", segment: 0, lineBreak: "\n", pos: "middle"},
		{name: "header CR end", segment: 0, lineBreak: "\r", pos: "end"},
		{name: "header LF end", segment: 0, lineBreak: "\n", pos: "end"},

		{name: "payload CR start", segment: 1, lineBreak: "\r", pos: "start"},
		{name: "payload LF start", segment: 1, lineBreak: "\n", pos: "start"},
		{name: "payload CRLF middle", segment: 1, lineBreak: "\r\n", pos: "middle"},
		{name: "payload CR middle", segment: 1, lineBreak: "\r", pos: "middle"},
		{name: "payload LF middle", segment: 1, lineBreak: "\n", pos: "middle"},
		{name: "payload CR end", segment: 1, lineBreak: "\r", pos: "end"},
		{name: "payload LF end", segment: 1, lineBreak: "\n", pos: "end"},

		{name: "signature CR start", segment: 2, lineBreak: "\r", pos: "start"},
		{name: "signature LF start", segment: 2, lineBreak: "\n", pos: "start"},
		{name: "signature CRLF middle", segment: 2, lineBreak: "\r\n", pos: "middle"},
		{name: "signature CR middle", segment: 2, lineBreak: "\r", pos: "middle"},
		{name: "signature LF middle", segment: 2, lineBreak: "\n", pos: "middle"},
		{name: "signature CR end", segment: 2, lineBreak: "\r", pos: "end"},
		{name: "signature LF end", segment: 2, lineBreak: "\n", pos: "end"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := append([]string(nil), originalParts...)
			segment := parts[tt.segment]

			switch tt.pos {
			case "start":
				parts[tt.segment] = tt.lineBreak + segment
			case "middle":
				cut := len(segment) / 2
				parts[tt.segment] = segment[:cut] + tt.lineBreak + segment[cut:]
			case "end":
				parts[tt.segment] = segment + tt.lineBreak
			}

			// Keep mutated header or payload token validly signed so the test isolates
			// rejection of line breaks during segment decoding.
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
				t.Fatalf("jwt.Parse: expected ErrTokenMalformed, got err=%v", err)
			}
			if parsed != nil && parsed.Valid {
				t.Fatal("jwt.Parse: token with line break marked valid")
			}

			parser := jwt.NewParser()
			_, _, err = parser.ParseUnverified(mutatedToken, jwt.MapClaims{})
			if !errors.Is(err, jwt.ErrTokenMalformed) {
				t.Fatalf("ParseUnverified: expected ErrTokenMalformed, got err=%v", err)
			}
		})
	}
}
