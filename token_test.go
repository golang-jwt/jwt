package jwt

import (
	"errors"
	"reflect"
	"testing"
)

func TestToken_SigningString(t1 *testing.T) {
	type fields struct {
		Raw       string
		Method    SigningMethod
		Header    map[string]interface{}
		Claims    Claims
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
				Method: SigningMethodHS256,
				Header: map[string]interface{}{
					"typ": "JWT",
					"alg": SigningMethodHS256.Alg(),
				},
				Claims: RegisteredClaims{},
				Valid:  false,
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &Token{
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
	t := &Token{
		Method: SigningMethodHS256,
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": SigningMethodHS256.Alg(),
		},
		Claims: RegisteredClaims{},
	}
	b.Run("BenchmarkToken_SigningString", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			t.SigningString()
		}
	})
}

func Test_secureKeyFunc(t *testing.T) {
	type fields struct {
		token *Token
	}
	type args struct {
		key          any
		validMethods []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantKey any
		wantErr error
	}{
		{
			name:    "invalid method",
			fields:  fields{&Token{Header: map[string]interface{}{"alg": "RS512"}, Method: SigningMethodRS512}},
			args:    args{key: []byte("mysecret"), validMethods: []string{"HS256"}},
			wantKey: nil,
			wantErr: ErrTokenSignatureInvalid,
		},
		{
			name:    "correct method",
			fields:  fields{&Token{Header: map[string]interface{}{"alg": "HS256"}, Method: SigningMethodHS256}},
			args:    args{key: []byte("mysecret"), validMethods: []string{"HS256"}},
			wantKey: []byte("mysecret"),
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyfunc := secureKeyFunc(tt.args.key, tt.args.validMethods)
			gotKey, gotErr := keyfunc(tt.fields.token)

			if !reflect.DeepEqual(gotKey, tt.wantKey) {
				t.Errorf("secureKeyFunc() key = %v, want %v", gotKey, tt.wantKey)
			}
			if (gotErr != nil) && !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("secureKeyFunc() err = %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}
