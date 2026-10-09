package jwt

import (
	"encoding/json"
	"errors"
	"math"
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
		"int64":       {"exp": int64(0)},
		"int":         {"exp": int(0)},
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
		wantErr error // nil means no error; otherwise errors.Is(err, wantErr)
	}{
		// aud is optional: absent or null means "no audience", not an error.
		{name: "missing aud", m: MapClaims{}, want: nil, wantErr: nil},
		{name: "null aud", m: MapClaims{"aud": nil}, want: nil, wantErr: nil},
		// Valid shapes per RFC 7519: a single string or an array of strings.
		{name: "string aud", m: MapClaims{"aud": "example.com"}, want: ClaimStrings{"example.com"}, wantErr: nil},
		{name: "[]string aud", m: MapClaims{"aud": []string{"a", "b"}}, want: ClaimStrings{"a", "b"}, wantErr: nil},
		{name: "[]any of strings aud", m: MapClaims{"aud": []any{"a", "b"}}, want: ClaimStrings{"a", "b"}, wantErr: nil},
		// Invalid types must return ErrInvalidType, consistent with the other
		// MapClaims accessors (iss/sub/exp/nbf/iat) and with the per-element
		// check already performed on []any audiences.
		{name: "[]any with non-string element", m: MapClaims{"aud": []any{"a", 5}}, want: nil, wantErr: ErrInvalidType},
		{name: "wrong type: number", m: MapClaims{"aud": 123}, want: nil, wantErr: ErrInvalidType},
		{name: "wrong type: bool", m: MapClaims{"aud": true}, want: nil, wantErr: ErrInvalidType},
		{name: "wrong type: object", m: MapClaims{"aud": map[string]any{"x": 1}}, want: nil, wantErr: ErrInvalidType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.GetAudience()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("MapClaims.GetAudience() error = %v, want %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapClaims.GetAudience() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestMapClaims_NumericDate_Types(t *testing.T) {
	ts := int64(1700000000)
	want := time.Unix(ts, 0).Truncate(TimePrecision)

	tests := []struct {
		name  string
		value any
		want  time.Time
	}{
		{name: "float64", value: float64(ts), want: want},
		{name: "float32", value: float32(ts), want: time.Unix(int64(float32(ts)), 0).Truncate(TimePrecision)},
		{name: "int64", value: int64(ts), want: want},
		{name: "int", value: int(ts), want: want},
		{name: "int32", value: int32(100000), want: time.Unix(100000, 0).Truncate(TimePrecision)},
		{name: "int16", value: int16(1000), want: time.Unix(1000, 0).Truncate(TimePrecision)},
		{name: "int8", value: int8(10), want: time.Unix(10, 0).Truncate(TimePrecision)},
		{name: "uint64", value: uint64(ts), want: want},
		{name: "uint", value: uint(ts), want: want},
		{name: "uint32", value: uint32(100000), want: time.Unix(100000, 0).Truncate(TimePrecision)},
		{name: "uint16", value: uint16(1000), want: time.Unix(1000, 0).Truncate(TimePrecision)},
		{name: "uint8", value: uint8(10), want: time.Unix(10, 0).Truncate(TimePrecision)},
		{name: "json.Number", value: json.Number("1700000000"), want: want},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MapClaims{
				"exp": tt.value,
				"nbf": tt.value,
				"iat": tt.value,
			}

			exp, err := m.GetExpirationTime()
			if err != nil {
				t.Fatalf("GetExpirationTime() unexpected error: %v", err)
			}
			if exp == nil || !exp.Time.Equal(tt.want) {
				t.Errorf("GetExpirationTime() = %v, want %v", exp, tt.want)
			}

			nbf, err := m.GetNotBefore()
			if err != nil {
				t.Fatalf("GetNotBefore() unexpected error: %v", err)
			}
			if nbf == nil || !nbf.Time.Equal(tt.want) {
				t.Errorf("GetNotBefore() = %v, want %v", nbf, tt.want)
			}

			iat, err := m.GetIssuedAt()
			if err != nil {
				t.Fatalf("GetIssuedAt() unexpected error: %v", err)
			}
			if iat == nil || !iat.Time.Equal(tt.want) {
				t.Errorf("GetIssuedAt() = %v, want %v", iat, tt.want)
			}
		})
	}
}

func TestMapClaims_NumericDate_Negative(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int64
	}{
		{name: "int64", value: int64(-500), want: -500},
		{name: "int", value: int(-500), want: -500},
		{name: "int32", value: int32(-500), want: -500},
		{name: "int16", value: int16(-500), want: -500},
		{name: "int8", value: int8(-50), want: -50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MapClaims{"exp": tt.value}
			exp, err := m.GetExpirationTime()
			if err != nil {
				t.Fatalf("GetExpirationTime() unexpected error: %v", err)
			}
			wantTime := time.Unix(tt.want, 0).Truncate(TimePrecision)
			if exp == nil || !exp.Time.Equal(wantTime) {
				t.Errorf("GetExpirationTime() = %v, want %v", exp, wantTime)
			}
		})
	}
}

func TestMapClaims_NumericDate_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "string", value: "1700000000"},
		{name: "bool", value: true},
		{name: "slice", value: []int{1, 2, 3}},
		{name: "map", value: map[string]int{"exp": 1}},
		{name: "struct", value: struct{}{}},
		{name: "invalid json.Number", value: json.Number("not-a-number")},
		{name: "uint64 overflow", value: uint64(math.MaxInt64) + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MapClaims{"exp": tt.value, "nbf": tt.value, "iat": tt.value}

			_, err := m.GetExpirationTime()
			if !errors.Is(err, ErrInvalidType) {
				t.Errorf("GetExpirationTime() error = %v, want ErrInvalidType", err)
			}

			_, err = m.GetNotBefore()
			if !errors.Is(err, ErrInvalidType) {
				t.Errorf("GetNotBefore() error = %v, want ErrInvalidType", err)
			}

			_, err = m.GetIssuedAt()
			if !errors.Is(err, ErrInvalidType) {
				t.Errorf("GetIssuedAt() error = %v, want ErrInvalidType", err)
			}
		})
	}
}

func TestMapClaims_NumericDate_Missing(t *testing.T) {
	m := MapClaims{}

	exp, err := m.GetExpirationTime()
	if err != nil || exp != nil {
		t.Errorf("GetExpirationTime() = (%v, %v), want (nil, nil)", exp, err)
	}

	nbf, err := m.GetNotBefore()
	if err != nil || nbf != nil {
		t.Errorf("GetNotBefore() = (%v, %v), want (nil, nil)", nbf, err)
	}

	iat, err := m.GetIssuedAt()
	if err != nil || iat != nil {
		t.Errorf("GetIssuedAt() = (%v, %v), want (nil, nil)", iat, err)
	}
}

func TestMapClaims_Validator_IntegerTimestamps(t *testing.T) {
	now := time.Now()

	t.Run("valid integer claims", func(t *testing.T) {
		claims := MapClaims{
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Add(-time.Hour).Unix(),
		}
		validator := NewValidator(
			WithIssuedAt(),
			WithTimeFunc(func() time.Time { return now }),
		)
		if err := validator.Validate(claims); err != nil {
			t.Fatalf("expected valid claims, got: %v", err)
		}
	})

	t.Run("expired integer claim", func(t *testing.T) {
		claims := MapClaims{
			"exp": now.Add(-time.Hour).Unix(),
		}
		validator := NewValidator(
			WithTimeFunc(func() time.Time { return now }),
		)
		err := validator.Validate(claims)
		if !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("expected ErrTokenExpired, got: %v", err)
		}
	})

	t.Run("future nbf integer claim", func(t *testing.T) {
		claims := MapClaims{
			"nbf": now.Add(time.Hour).Unix(),
		}
		validator := NewValidator(
			WithTimeFunc(func() time.Time { return now }),
		)
		err := validator.Validate(claims)
		if !errors.Is(err, ErrTokenNotValidYet) {
			t.Fatalf("expected ErrTokenNotValidYet, got: %v", err)
		}
	})

	t.Run("future iat integer claim", func(t *testing.T) {
		claims := MapClaims{
			"iat": now.Add(time.Hour).Unix(),
		}
		validator := NewValidator(
			WithIssuedAt(),
			WithTimeFunc(func() time.Time { return now }),
		)
		err := validator.Validate(claims)
		if !errors.Is(err, ErrTokenUsedBeforeIssued) {
			t.Fatalf("expected ErrTokenUsedBeforeIssued, got: %v", err)
		}
	})
}
