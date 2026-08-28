package jwt_test

import (
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

func TestToken_SetTypeAndContentType(t *testing.T) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.SetType("at+jwt")
	token.SetContentType("JWT")

	if token.Header["typ"] != "at+jwt" {
		t.Errorf("expected typ to be at+jwt, got %v", token.Header["typ"])
	}
	if token.Header["cty"] != "JWT" {
		t.Errorf("expected cty to be JWT, got %v", token.Header["cty"])
	}
}
