package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var ErrFooBar = errors.New("must be foobar")

type MyCustomClaims struct {
	Foo string `json:"foo"`
	RegisteredClaims
}

func (m MyCustomClaims) Validate() error {
	if m.Foo != "bar" {
		return ErrFooBar
	}
	return nil
}

func Test_Validator_Validate(t *testing.T) {
	type fields struct {
		leeway       time.Duration
		timeFunc     func() time.Time
		verifyIat    bool
		expectedAud  []string
		expectAllAud bool
		expectedIss  string
		expectedSub  string
	}
	type args struct {
		claims Claims
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name:    "expected iss mismatch",
			fields:  fields{expectedIss: "me"},
			args:    args{RegisteredClaims{Issuer: "not_me"}},
			wantErr: ErrTokenInvalidIssuer,
		},
		{
			name:    "expected iss is missing",
			fields:  fields{expectedIss: "me"},
			args:    args{RegisteredClaims{}},
			wantErr: ErrTokenRequiredClaimMissing,
		},
		{
			name:    "expected sub mismatch",
			fields:  fields{expectedSub: "me"},
			args:    args{RegisteredClaims{Subject: "not-me"}},
			wantErr: ErrTokenInvalidSubject,
		},
		{
			name:    "expected sub is missing",
			fields:  fields{expectedSub: "me"},
			args:    args{RegisteredClaims{}},
			wantErr: ErrTokenRequiredClaimMissing,
		},
		{
			name:    "custom validator",
			fields:  fields{},
			args:    args{MyCustomClaims{Foo: "not-bar"}},
			wantErr: ErrFooBar,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				leeway:       tt.fields.leeway,
				timeFunc:     tt.fields.timeFunc,
				verifyIat:    tt.fields.verifyIat,
				expectedAud:  tt.fields.expectedAud,
				expectAllAud: tt.fields.expectAllAud,
				expectedIss:  tt.fields.expectedIss,
				expectedSub:  tt.fields.expectedSub,
			}
			if err := v.Validate(tt.args.claims); (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Validator_verifyExpiresAt(t *testing.T) {
	type fields struct {
		leeway   time.Duration
		timeFunc func() time.Time
	}
	type args struct {
		claims   Claims
		cmp      time.Time
		required bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
		wantBy  string
	}{
		{
			name:    "good claim",
			fields:  fields{timeFunc: time.Now},
			args:    args{claims: RegisteredClaims{ExpiresAt: NewNumericDate(time.Now().Add(10 * time.Minute))}},
			wantErr: nil,
		},
		{
			name:    "claims with invalid type",
			fields:  fields{},
			args:    args{claims: MapClaims{"exp": "string"}},
			wantErr: ErrInvalidType,
		},
		{
			name:    "when leeway is in future",
			fields:  fields{leeway: 10 * time.Minute},
			args:    args{claims: RegisteredClaims{ExpiresAt: NewNumericDate(time.Now().Add(9 * time.Minute))}},
			wantErr: nil,
		},
		{
			name:    "when leeway is in the past",
			fields:  fields{leeway: 10 * time.Minute},
			args:    args{claims: RegisteredClaims{ExpiresAt: NewNumericDate(time.Now().Add(-15 * time.Minute))}, cmp: time.Now()},
			wantErr: ErrTokenExpired,
			wantBy:  "by 15m0s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				leeway:   tt.fields.leeway,
				timeFunc: tt.fields.timeFunc,
			}

			err := v.verifyExpiresAt(tt.args.claims, tt.args.cmp, tt.args.required)
			if err != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("validator.verifyExpiresAt() error = %v, wantErr %v", err, tt.wantErr)
				}

				if errors.Is(err, ErrTokenExpired) && !strings.Contains(err.Error(), tt.wantBy) {
					t.Errorf("Error string %q did not contain %q", err, tt.wantBy)
				}
			}
		})
	}
}

func Test_Validator_verifyIssuer(t *testing.T) {
	type fields struct {
		expectedIss string
	}
	type args struct {
		claims   Claims
		cmp      string
		required bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name:    "good claim",
			fields:  fields{expectedIss: "me"},
			args:    args{claims: MapClaims{"iss": "me"}, cmp: "me"},
			wantErr: nil,
		},
		{
			name:    "claims with invalid type",
			fields:  fields{expectedIss: "me"},
			args:    args{claims: MapClaims{"iss": 1}, cmp: "me"},
			wantErr: ErrInvalidType,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				expectedIss: tt.fields.expectedIss,
			}
			err := v.verifyIssuer(tt.args.claims, tt.args.cmp, tt.args.required)
			if (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.verifyIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Validator_verifySubject(t *testing.T) {
	type fields struct {
		expectedSub string
	}
	type args struct {
		claims   Claims
		cmp      string
		required bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name:    "good claim",
			fields:  fields{expectedSub: "me"},
			args:    args{claims: MapClaims{"sub": "me"}, cmp: "me"},
			wantErr: nil,
		},
		{
			name:    "claims with invalid type",
			fields:  fields{expectedSub: "me"},
			args:    args{claims: MapClaims{"sub": 1}, cmp: "me"},
			wantErr: ErrInvalidType,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				expectedSub: tt.fields.expectedSub,
			}
			err := v.verifySubject(tt.args.claims, tt.args.cmp, tt.args.required)
			if (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.verifySubject() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Validator_verifyIssuedAt(t *testing.T) {
	type fields struct {
		leeway    time.Duration
		timeFunc  func() time.Time
		verifyIat bool
	}
	type args struct {
		claims   Claims
		cmp      time.Time
		required bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name:    "good claim without iat",
			fields:  fields{verifyIat: true},
			args:    args{claims: MapClaims{}, required: false},
			wantErr: nil,
		},
		{
			name:   "good claim with iat",
			fields: fields{verifyIat: true},
			args: args{
				claims:   RegisteredClaims{IssuedAt: NewNumericDate(time.Now())},
				cmp:      time.Now().Add(10 * time.Minute),
				required: false,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				leeway:    tt.fields.leeway,
				timeFunc:  tt.fields.timeFunc,
				verifyIat: tt.fields.verifyIat,
			}
			if err := v.verifyIssuedAt(tt.args.claims, tt.args.cmp, tt.args.required); (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.verifyIssuedAt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Validator_requireNotBefore(t *testing.T) {
	type fields struct {
		leeway     time.Duration
		timeFunc   func() time.Time
		requireNbf bool
	}
	type args struct {
		claims   Claims
		cmp      time.Time
		required bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name:    "good claim without nbf",
			fields:  fields{requireNbf: false},
			args:    args{claims: MapClaims{}, required: false},
			wantErr: nil,
		},
		{
			name:   "good claim with nbf",
			fields: fields{requireNbf: true},
			args: args{
				claims:   RegisteredClaims{NotBefore: NewNumericDate(time.Now().Add(time.Minute * -10))},
				cmp:      time.Now().Add(10 * time.Minute),
				required: true,
			},
			wantErr: nil,
		},
		{
			name:   "token nbf time is in future",
			fields: fields{requireNbf: true, timeFunc: time.Now},
			args: args{
				claims:   RegisteredClaims{NotBefore: NewNumericDate(time.Now().Add(time.Minute * +10))},
				cmp:      time.Now().Add(10 * time.Minute),
				required: true,
			},
			wantErr: ErrTokenNotValidYet,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []ParserOption{
				WithLeeway(tt.fields.leeway),
			}

			if tt.fields.requireNbf {
				opts = append(opts, WithNotBeforeRequired())
			}

			if tt.fields.timeFunc != nil {
				opts = append(opts, WithTimeFunc(tt.fields.timeFunc))
			}

			v := NewValidator(opts...)

			if err := v.verifyNotBefore(tt.args.claims, tt.args.cmp, tt.args.required); (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.requireNotBefore() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Validator_verifyAudience(t *testing.T) {
	type fields struct {
		expectedAud []string
	}
	type args struct {
		claims       Claims
		cmp          []string
		expectAllAud bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name:   "fail without audience when expecting one aud match",
			fields: fields{expectedAud: []string{"example.com"}},
			args: args{
				claims:       MapClaims{},
				cmp:          []string{"example.com"},
				expectAllAud: false,
			},
			wantErr: ErrTokenRequiredClaimMissing,
		},
		{
			name:   "fail without audience when expecting all aud matches",
			fields: fields{expectedAud: []string{"example.com"}},
			args: args{
				claims:       MapClaims{},
				cmp:          []string{"example.com"},
				expectAllAud: true,
			},
			wantErr: ErrTokenRequiredClaimMissing,
		},
		{
			name:   "good when audience matches",
			fields: fields{expectedAud: []string{"example.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"example.com"}},
				cmp:          []string{"example.com"},
				expectAllAud: false,
			},
			wantErr: nil,
		},
		{
			name:   "fail when audience matches with one value",
			fields: fields{expectedAud: []string{"example.org", "example.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"example.com"}},
				cmp:          []string{"example.org", "example.com"},
				expectAllAud: false,
			},
			wantErr: nil,
		},
		{
			name:   "fail when audience matches with all values",
			fields: fields{expectedAud: []string{"example.org", "example.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"example.org", "example.com"}},
				cmp:          []string{"example.org", "example.com"},
				expectAllAud: true,
			},
			wantErr: nil,
		},
		{
			name:   "fail when audience not matching",
			fields: fields{expectedAud: []string{"example.org", "example.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"example.net"}},
				cmp:          []string{"example.org", "example.com"},
				expectAllAud: false,
			},
			wantErr: ErrTokenInvalidAudience,
		},
		{
			name:   "fail when audience not matching all values",
			fields: fields{expectedAud: []string{"example.org", "example.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"example.org", "example.net"}},
				cmp:          []string{"example.org", "example.com"},
				expectAllAud: true,
			},
			wantErr: ErrTokenInvalidAudience,
		},
		{
			name:   "fail when audience missing",
			fields: fields{expectedAud: []string{"example.org", "example.com"}},
			args: args{
				claims:       MapClaims{},
				cmp:          []string{"example.org", "example.com"},
				expectAllAud: true,
			},
			wantErr: ErrTokenRequiredClaimMissing,
		},
		{
			name:   "good when audience matches last candidate in cmp",
			fields: fields{expectedAud: []string{"example.org", "example.net", "example.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"example.com"}},
				cmp:          []string{"example.org", "example.net", "example.com"},
				expectAllAud: false,
			},
			wantErr: nil,
		},
		{
			name:   "good when match is last element in aud slice",
			fields: fields{expectedAud: []string{"target.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"unrelated1.com", "unrelated2.com", "target.com"}},
				cmp:          []string{"target.com"},
				expectAllAud: false,
			},
			wantErr: nil,
		},
		{
			name:   "good when multiple audiences in token satisfy all expected in cmp",
			fields: fields{expectedAud: []string{"a.com", "b.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"c.com", "b.com", "a.com"}},
				cmp:          []string{"a.com", "b.com"},
				expectAllAud: true,
			},
			wantErr: nil,
		},
		{
			name:   "fail when all expected audiences required but one missing in middle",
			fields: fields{expectedAud: []string{"a.com", "b.com", "c.com"}},
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"a.com", "c.com"}},
				cmp:          []string{"a.com", "b.com", "c.com"},
				expectAllAud: true,
			},
			wantErr: ErrTokenInvalidAudience,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				expectedAud:  tt.fields.expectedAud,
				expectAllAud: tt.args.expectAllAud,
			}

			err := v.verifyAudience(tt.args.claims, tt.args.cmp, tt.args.expectAllAud)
			if tt.wantErr == nil && err != nil {
				t.Errorf("validator.verifyAudience() error = %v, wantErr %v", err, tt.wantErr)
			} else if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.verifyAudience() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_containsConstantTime(t *testing.T) {
	tests := []struct {
		name string
		set  []string
		s    string
		want int
	}{
		{
			name: "empty set",
			set:  []string{},
			s:    "foo",
			want: 0,
		},
		{
			name: "single match",
			set:  []string{"foo"},
			s:    "foo",
			want: 1,
		},
		{
			name: "single non-match",
			set:  []string{"bar"},
			s:    "foo",
			want: 0,
		},
		{
			name: "match at start",
			set:  []string{"foo", "bar", "baz"},
			s:    "foo",
			want: 1,
		},
		{
			name: "match in middle",
			set:  []string{"foo", "bar", "baz"},
			s:    "bar",
			want: 1,
		},
		{
			name: "match at end",
			set:  []string{"foo", "bar", "baz"},
			s:    "baz",
			want: 1,
		},
		{
			name: "no match in multiple",
			set:  []string{"foo", "bar", "baz"},
			s:    "qux",
			want: 0,
		},
		{
			name: "prefix does not match",
			set:  []string{"foobar"},
			s:    "foo",
			want: 0,
		},
		{
			name: "different length does not match",
			set:  []string{"foo"},
			s:    "fooo",
			want: 0,
		},
		{
			name: "empty string match",
			set:  []string{"", "foo"},
			s:    "",
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsConstantTime(tt.set, tt.s)
			if got != tt.want {
				t.Errorf("containsConstantTime() = %v, want %v", got, tt.want)
			}
		})
	}
}
