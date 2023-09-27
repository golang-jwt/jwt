package jwt

import (
	"errors"
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
		leeway      time.Duration
		timeFunc    func() time.Time
		verifyIat   bool
		expectedAud string
		expectedIss string
		expectedSub string
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
				leeway:      tt.fields.leeway,
				timeFunc:    tt.fields.timeFunc,
				verifyIat:   tt.fields.verifyIat,
				expectedAud: tt.fields.expectedAud,
				expectedIss: tt.fields.expectedIss,
				expectedSub: tt.fields.expectedSub,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				leeway:   tt.fields.leeway,
				timeFunc: tt.fields.timeFunc,
			}

			err := v.verifyExpiresAt(tt.args.claims, tt.args.cmp, tt.args.required)
			if (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.verifyExpiresAt() error = %v, wantErr %v", err, tt.wantErr)
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
