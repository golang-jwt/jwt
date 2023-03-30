package jwt_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestToken_SigningString(t1 *testing.T) {
	type fields struct {
		Raw       string
		Method    jwt.SigningMethod
		Header    map[string]interface{}
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
				Header: map[string]interface{}{
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

func TestToken_B64Header(t *testing.T) {
	type customClaims struct {
		jwt.RegisteredClaims
		Value string `json:"value"`
	}

	type fields struct {
		Raw       string
		Method    jwt.SigningMethod
		Header    map[string]interface{}
		Claims    customClaims
		Signature []byte
	}

	tests := []struct {
		name         string
		fields       fields
		expectString string
	}{
		{
			name:         "no b64 header",
			expectString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YWx1ZSI6ImhlbGxvIHdvcmxkIn0",
			fields: fields{
				Raw:    "",
				Method: jwt.SigningMethodHS256,
				Header: map[string]interface{}{
					"typ": "JWT",
					"alg": jwt.SigningMethodHS256.Alg(),
				},
				Claims: customClaims{
					Value: "hello world",
				},
			},
		}, {
			name:         "b64 header is false",
			expectString: `eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsInR5cCI6IkpXVCJ9.{"value":"hello world"}`,
			fields: fields{
				Raw:    "",
				Method: jwt.SigningMethodHS256,
				Header: map[string]interface{}{
					"typ": "JWT",
					"b64": false,
					"alg": jwt.SigningMethodHS256.Alg(),
				},
				Claims: customClaims{
					Value: "hello world",
				},
			},
		}, {
			name:         "b64 header is true",
			expectString: `eyJhbGciOiJIUzI1NiIsImI2NCI6dHJ1ZSwidHlwIjoiSldUIn0.eyJ2YWx1ZSI6ImhlbGxvIHdvcmxkIn0`,
			fields: fields{
				Raw:    "",
				Method: jwt.SigningMethodHS256,
				Header: map[string]interface{}{
					"typ": "JWT",
					"b64": true,
					"alg": jwt.SigningMethodHS256.Alg(),
				},
				Claims: customClaims{
					Value: "hello world",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t1 *testing.T) {
			t := &jwt.Token{
				Raw:       tt.fields.Raw,
				Method:    tt.fields.Method,
				Header:    tt.fields.Header,
				Claims:    tt.fields.Claims,
				Signature: tt.fields.Signature,
			}
			got, err := t.SigningString()
			if err != nil {
				t1.Errorf("SigningString() error = %v, Should not output error", err)
			}
			jwtSplitted := strings.Split(got, ".")

			var claims customClaims
			err = json.Unmarshal([]byte(jwtSplitted[1]), &claims)
			// if we get error does this mean that we got a encoded claims that json can't unmarshal
			if _, ok := tt.fields.Header["b64"].(bool); !ok && err == nil {
				t1.Error("Unmarshal() expected to get error but got nil")
			}

			// if b64 exist in headers and is enabled
			if enabled, ok := tt.fields.Header["b64"].(bool); ok && enabled && err == nil {
				t1.Error("Unmarshal() expected to get error but got nil even if claims is not json")
				return
			}

			// if b64 exist in headers and is not enabled
			if enabled, ok := tt.fields.Header["b64"].(bool); ok && !enabled && err != nil {
				t1.Error("Unmarshal() expected to get nil but got error even if claims is valid json")
				return
			}

			//verify that we are able to parse the returned json
			if err == nil && claims.Value != "hello world" {
				t1.Errorf("Value by unmarshal is valid, expected to get 'hello world' but got %s", claims.Value)
				return
			}

			if got != tt.expectString {
				t1.Errorf("expected string: expected to get %s, got %s", tt.expectString, got)
			}
		})
	}
}

func BenchmarkToken_SigningString(b *testing.B) {
	t := &jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{
			"typ": "JWS",
			"alg": jwt.SigningMethodRS256.Alg(),
		},
		Claims: jwt.RegisteredClaims{},
	}
	b.Run("BenchmarkToken_SigningString", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			t.SigningString()
		}
	})
}
