package jwt

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestVerifyAud(t *testing.T) {
	var nilInterface any
	var nilListInterface []any
	var intListInterface any = []int{1, 2, 3}
	type test struct {
		Name        string
		MapClaims   MapClaims
		Expected    bool
		Comparison  []string
		MatchAllAud bool
		Required    bool
	}
	tests := []test{
		// Matching Claim in aud
		// Required = true
		{Name: "String Aud matching required", MapClaims: MapClaims{"aud": "example.com"}, Expected: true, Required: true, Comparison: []string{"example.com"}},
		{Name: "[]String Aud with match required", MapClaims: MapClaims{"aud": []string{"example.com", "example.example.com"}}, Expected: true, Required: true, Comparison: []string{"example.com"}},
		{Name: "[]String Aud with []match any required", MapClaims: MapClaims{"aud": []string{"example.com", "example.example.com"}}, Expected: true, Required: true, Comparison: []string{"example.com", "auth.example.com"}},
		{Name: "[]String Aud with []match all required", MapClaims: MapClaims{"aud": []string{"example.com", "example.example.com"}}, Expected: true, Required: true, Comparison: []string{"example.com", "example.example.com"}, MatchAllAud: true},

		// Required = false
		{Name: "String Aud with match not required", MapClaims: MapClaims{"aud": "example.com"}, Expected: true, Required: false, Comparison: []string{"example.com"}},
		{Name: "Empty String Aud with match not required", MapClaims: MapClaims{}, Expected: true, Required: false, Comparison: []string{"example.com"}},
		{Name: "Empty String Aud with match not required", MapClaims: MapClaims{"aud": ""}, Expected: true, Required: false, Comparison: []string{"example.com"}},
		{Name: "Nil String Aud with match not required", MapClaims: MapClaims{"aud": nil}, Expected: true, Required: false, Comparison: []string{"example.com"}},

		{Name: "[]String Aud with match not required", MapClaims: MapClaims{"aud": []string{"example.com", "example.example.com"}}, Expected: true, Required: false, Comparison: []string{"example.com"}},
		{Name: "Empty []String Aud with match not required", MapClaims: MapClaims{"aud": []string{}}, Expected: true, Required: false, Comparison: []string{"example.com"}},

		// Non-Matching Claim in aud
		// Required = true
		{Name: "String Aud without match required", MapClaims: MapClaims{"aud": "not.example.com"}, Expected: false, Required: true, Comparison: []string{"example.com"}},
		{Name: "Empty String Aud without match required", MapClaims: MapClaims{"aud": ""}, Expected: false, Required: true, Comparison: []string{"example.com"}},
		{Name: "[]String Aud without match required", MapClaims: MapClaims{"aud": []string{"not.example.com", "example.example.com"}}, Expected: false, Required: true, Comparison: []string{"example.com"}},
		{Name: "Empty []String Aud without match required", MapClaims: MapClaims{"aud": []string{""}}, Expected: false, Required: true, Comparison: []string{"example.com"}},
		{Name: "String Aud without match not required", MapClaims: MapClaims{"aud": "not.example.com"}, Expected: false, Required: true, Comparison: []string{"example.com"}},
		{Name: "Empty String Aud without match not required", MapClaims: MapClaims{"aud": ""}, Expected: false, Required: true, Comparison: []string{"example.com"}},
		{Name: "[]String Aud without match not required", MapClaims: MapClaims{"aud": []string{"not.example.com", "example.example.com"}}, Expected: false, Required: true, Comparison: []string{"example.com"}},

		// Required = false
		{Name: "Empty []String Aud without match required", MapClaims: MapClaims{"aud": []string{""}}, Expected: true, Required: false, Comparison: []string{"example.com"}},

		// []any
		{Name: "Empty []interface{} Aud without match required", MapClaims: MapClaims{"aud": nilListInterface}, Expected: true, Required: false, Comparison: []string{"example.com"}},
		{Name: "[]interface{} Aud with match required", MapClaims: MapClaims{"aud": []any{"a", "foo", "example.com"}}, Expected: true, Required: true, Comparison: []string{"example.com"}},
		{Name: "[]interface{} Aud with match but invalid types", MapClaims: MapClaims{"aud": []any{"a", 5, "example.com"}}, Expected: false, Required: true, Comparison: []string{"example.com"}},
		{Name: "[]interface{} Aud int with match required", MapClaims: MapClaims{"aud": intListInterface}, Expected: false, Required: true, Comparison: []string{"example.com"}},

		// any
		{Name: "Empty interface{} Aud without match not required", MapClaims: MapClaims{"aud": nilInterface}, Expected: true, Required: false, Comparison: []string{"example.com"}},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var opts []ParserOption

			if test.Required && test.MatchAllAud {
				opts = append(opts, WithAllAudiences(test.Comparison...))
			} else if test.Required {
				opts = append(opts, WithAudience(test.Comparison...))
			}

			validator := NewValidator(opts...)
			got := validator.Validate(test.MapClaims)

			if (got == nil) != test.Expected {
				t.Errorf("Expected %v, got %v", test.Expected, (got == nil))
			}
		})
	}
}

func TestMapclaimsVerifyIssuedAtInvalidTypeString(t *testing.T) {
	mapClaims := MapClaims{
		"iat": "foo",
	}
	want := false
	got := NewValidator(WithIssuedAt()).Validate(mapClaims)
	if want != (got == nil) {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, (got == nil))
	}
}

func TestMapclaimsVerifyNotBeforeInvalidTypeString(t *testing.T) {
	mapClaims := MapClaims{
		"nbf": "foo",
	}
	want := false
	got := NewValidator().Validate(mapClaims)
	if want != (got == nil) {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, (got == nil))
	}
}

func TestMapclaimsVerifyExpiresAtInvalidTypeString(t *testing.T) {
	mapClaims := MapClaims{
		"exp": "foo",
	}
	want := false
	got := NewValidator().Validate(mapClaims)

	if want != (got == nil) {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, (got == nil))
	}
}

func TestMapClaimsVerifyExpiresAtExpire(t *testing.T) {
	exp := time.Now()
	mapClaims := MapClaims{
		"exp": float64(exp.Unix()),
	}
	want := false
	got := NewValidator(WithTimeFunc(func() time.Time {
		return exp
	})).Validate(mapClaims)
	if want != (got == nil) {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, (got == nil))
	}

	got = NewValidator(WithTimeFunc(func() time.Time {
		return exp.Add(1 * time.Second)
	})).Validate(mapClaims)
	if want != (got == nil) {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, (got == nil))
	}

	want = true
	got = NewValidator(WithTimeFunc(func() time.Time {
		return exp.Add(-1 * time.Second)
	})).Validate(mapClaims)
	if want != (got == nil) {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, (got == nil))
	}
}

func TestMapClaims_parseString(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name    string
		m       MapClaims
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "missing key",
			m:    MapClaims{},
			args: args{
				key: "mykey",
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "wrong key type",
			m:    MapClaims{"mykey": 4},
			args: args{
				key: "mykey",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "correct key type",
			m:    MapClaims{"mykey": "mystring"},
			args: args{
				key: "mykey",
			},
			want:    "mystring",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.parseString(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapClaims.parseString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("MapClaims.parseString() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Regression for #496: a token whose exp claim is the literal 0 (i.e.
// 1970-01-01) used to be treated as valid because parseNumericDate
// special-cased a zero float64 as "claim not present". The json.Number
// branch had no such carve-out, so the same token parsed via
// WithJSONNumber() correctly came back expired.
func TestMapClaims_GetExpirationTime_ZeroIsExpired(t *testing.T) {
	for name, claims := range map[string]MapClaims{
		"float64":     {"exp": float64(0)},
		"json.Number": {"exp": json.Number("0")},
	} {
		t.Run(name, func(t *testing.T) {
			err := NewValidator().Validate(claims)
			if err == nil {
				t.Fatalf("expected an error for exp=0, got nil")
			}
			if !errors.Is(err, ErrTokenExpired) {
				t.Fatalf("expected ErrTokenExpired, got %v", err)
			}
		})
	}
}

// A string exp must come back as ErrInvalidType, not as a stealth
// "claim not present" via the old float64==0 shortcut. Empty string is
// the case worth pinning down explicitly.
func TestMapClaims_GetExpirationTime_StringIsInvalidType(t *testing.T) {
	for name, claims := range map[string]MapClaims{
		"empty string": {"exp": ""},
		"non-empty":    {"exp": "foo"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := claims.GetExpirationTime()
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !errors.Is(err, ErrInvalidType) {
				t.Fatalf("expected ErrInvalidType, got %v", err)
			}
		})
	}
}

func TestMapClaims_GetAudience(t *testing.T) {
	tests := []struct {
		name    string
		m       MapClaims
		want    ClaimStrings
		wantErr bool
	}{
		// aud is optional: absent or null means "no audience", not an error.
		{name: "missing aud", m: MapClaims{}, want: nil, wantErr: false},
		{name: "null aud", m: MapClaims{"aud": nil}, want: nil, wantErr: false},
		// Valid shapes per RFC 7519: a single string or an array of strings.
		{name: "string aud", m: MapClaims{"aud": "example.com"}, want: ClaimStrings{"example.com"}, wantErr: false},
		{name: "[]string aud", m: MapClaims{"aud": []string{"a", "b"}}, want: ClaimStrings{"a", "b"}, wantErr: false},
		{name: "[]any of strings aud", m: MapClaims{"aud": []any{"a", "b"}}, want: ClaimStrings{"a", "b"}, wantErr: false},
		// Invalid types must return ErrInvalidType, consistent with the other
		// MapClaims accessors (iss/sub/exp/nbf/iat) and with the per-element
		// check already performed on []any audiences.
		{name: "[]any with non-string element", m: MapClaims{"aud": []any{"a", 5}}, want: nil, wantErr: true},
		{name: "wrong type: number", m: MapClaims{"aud": 123}, want: nil, wantErr: true},
		{name: "wrong type: bool", m: MapClaims{"aud": true}, want: nil, wantErr: true},
		{name: "wrong type: object", m: MapClaims{"aud": map[string]any{"x": 1}}, want: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.GetAudience()
			if (err != nil) != tt.wantErr {
				t.Errorf("MapClaims.GetAudience() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidType) {
					t.Errorf("MapClaims.GetAudience() error = %v, want errors.Is(err, ErrInvalidType)", err)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapClaims.GetAudience() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
