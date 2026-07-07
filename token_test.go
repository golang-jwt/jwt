package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestToken_SigningString(t1 *testing.T) {
	type fields struct {
		Raw       string
		Method    jwt.SigningMethod
		Header    map[string]any
		Claims    jwt.Claims
		Signature []byte
		Valid     bool
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "",
			fields: fields{
				Raw:    "",
				Method: jwt.SigningMethodHS256,
				Header: map[string]any{
					"typ": "JWT",
					"alg": jwt.SigningMethodHS256.Alg(),
				},
				Claims: jwt.RegisteredClaims{},
				Valid:  false,
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &jwt.Token{
				Raw:       tt.fields.Raw,
				Method:    tt.fields.Method,
				Header:    tt.fields.Header,
				Claims:    tt.fields.Claims,
				Signature: tt.fields.Signature,
				Valid:     tt.fields.Valid,
			}
			got, err := t.SigningString()
			if (err != nil) != tt.wantErr {
				t1.Errorf("SigningString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t1.Errorf("SigningString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkToken_SigningString(b *testing.B) {
	t := &jwt.Token{
		Method: jwt.SigningMethodHS256,
		Header: map[string]any{
			"typ": "JWT",
			"alg": jwt.SigningMethodHS256.Alg(),
		},
		Claims: jwt.RegisteredClaims{},
	}
	b.Run("BenchmarkToken_SigningString", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = t.SigningString()
		}
	})
}

func TestToken_SetType(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
	token.SetType("at+jwt")
	if token.Header["typ"] != "at+jwt" {
		t.Errorf("Header[typ] = %v, want at+jwt", token.Header["typ"])
	}

	// Empty string removes typ
	token.SetType("")
	if _, ok := token.Header["typ"]; ok {
		t.Error("SetType(\"\") should remove typ from header")
	}
}

func TestToken_SetType_NilHeader(t *testing.T) {
	token := &jwt.Token{Method: jwt.SigningMethodHS256, Claims: jwt.MapClaims{}}
	token.SetType("JWT")
	if token.Header == nil || token.Header["typ"] != "JWT" {
		t.Errorf("SetType on nil Header: Header = %v", token.Header)
	}
}

func TestToken_SetContentType(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
	token.SetContentType("JWT")
	if token.Header["cty"] != "JWT" {
		t.Errorf("Header[cty] = %v, want JWT", token.Header["cty"])
	}

	// Empty string removes cty
	token.SetContentType("")
	if _, ok := token.Header["cty"]; ok {
		t.Error("SetContentType(\"\") should remove cty from header")
	}
}

func TestToken_SetContentType_NilHeader(t *testing.T) {
	token := &jwt.Token{Method: jwt.SigningMethodHS256, Claims: jwt.MapClaims{}}
	token.SetContentType("JWT")
	if token.Header == nil || token.Header["cty"] != "JWT" {
		t.Errorf("SetContentType on nil Header: Header = %v", token.Header)
	}
}

func TestToken_SetType_SetContentType_InSigningString(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
	token.SetType("at+jwt")
	token.SetContentType("JWT")
	sstr, err := token.SigningString()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sstr, ".")
	if len(parts) != 2 {
		t.Fatalf("SigningString has %d parts, want 2", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["typ"] != "at+jwt" {
		t.Errorf("encoded header typ = %v, want at+jwt", header["typ"])
	}
	if header["cty"] != "JWT" {
		t.Errorf("encoded header cty = %v, want JWT", header["cty"])
	}
}
