package jwt

import (
	"testing"
	"time"
)

func TestValidator_Validate(t *testing.T) {
	type fields struct {
		leeway             time.Duration
		timeFunc           func() time.Time
		verifyIat          bool
		expectedAud        string
		expectedIss        string
		expectedSubPattern PatternFunc
	}
	type args struct {
		claims Claims
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "with subject pattern",
			fields: fields{
				expectedSubPattern: HasPrefix("My"),
			},
			args: args{
				claims: RegisteredClaims{Subject: "MyUser"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				leeway:             tt.fields.leeway,
				timeFunc:           tt.fields.timeFunc,
				verifyIat:          tt.fields.verifyIat,
				expectedAud:        tt.fields.expectedAud,
				expectedIss:        tt.fields.expectedIss,
				expectedSubPattern: tt.fields.expectedSubPattern,
			}
			if err := v.Validate(tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("Validator.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
