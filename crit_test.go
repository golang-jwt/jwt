package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const critTestSecret = "0123456789abcdef0123456789abcdef"

func signTokenWithHeader(t *testing.T, header map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	for k, v := range header {
		token.Header[k] = v
	}
	signed, err := token.SignedString([]byte(critTestSecret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func parseCrit(token string, opts ...jwt.ParserOption) (*jwt.Token, error) {
	keyFunc := func(*jwt.Token) (any, error) { return []byte(critTestSecret), nil }
	opts = append([]jwt.ParserOption{jwt.WithValidMethods([]string{"HS256"})}, opts...)
	return jwt.Parse(token, keyFunc, opts...)
}

func TestCritWithUnsupportedExtensionIsRejected(t *testing.T) {
	signed := signTokenWithHeader(t, map[string]any{
		"crit":                           []string{"http://example.com/unsupported"},
		"http://example.com/unsupported": true,
	})
	parsed, err := parseCrit(signed)
	if err == nil && parsed != nil && parsed.Valid {
		t.Fatal("token with unsupported crit was accepted as valid")
	}
	if !errors.Is(err, jwt.ErrTokenInvalidCritical) {
		t.Fatalf("got %v, want ErrTokenInvalidCritical", err)
	}
}

func TestCritWithSupportedExtensionIsAccepted(t *testing.T) {
	signed := signTokenWithHeader(t, map[string]any{
		"crit":                   []string{"http://example.com/ext"},
		"http://example.com/ext": true,
	})
	parsed, err := parseCrit(signed, jwt.WithCriticalHeaders("http://example.com/ext"))
	if err != nil {
		t.Fatalf("supported crit was rejected: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("expected a valid token")
	}
}

func TestCritEmptyListIsRejected(t *testing.T) {
	signed := signTokenWithHeader(t, map[string]any{"crit": []string{}})
	_, err := parseCrit(signed)
	if !errors.Is(err, jwt.ErrTokenInvalidCritical) {
		t.Fatalf("got %v, want ErrTokenInvalidCritical", err)
	}
}

func TestCritRegisteredHeaderNameIsRejected(t *testing.T) {
	signed := signTokenWithHeader(t, map[string]any{"crit": []string{"alg"}})
	_, err := parseCrit(signed)
	if !errors.Is(err, jwt.ErrTokenInvalidCritical) {
		t.Fatalf("got %v, want ErrTokenInvalidCritical", err)
	}
}

func TestCritMissingHeaderIsRejected(t *testing.T) {
	signed := signTokenWithHeader(t, map[string]any{
		"crit": []string{"http://example.com/ext"},
	})
	_, err := parseCrit(signed, jwt.WithCriticalHeaders("http://example.com/ext"))
	if !errors.Is(err, jwt.ErrTokenInvalidCritical) {
		t.Fatalf("got %v, want ErrTokenInvalidCritical", err)
	}
}

func TestCritNonArrayIsRejected(t *testing.T) {
	signed := signTokenWithHeader(t, map[string]any{"crit": "http://example.com/ext"})
	_, err := parseCrit(signed)
	if !errors.Is(err, jwt.ErrTokenInvalidCritical) {
		t.Fatalf("got %v, want ErrTokenInvalidCritical", err)
	}
}

func TestParseWithoutCritStillSucceeds(t *testing.T) {
	signed := signTokenWithHeader(t, nil)
	parsed, err := parseCrit(signed)
	if err != nil {
		t.Fatalf("token without crit was rejected: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("expected a valid token")
	}
}
