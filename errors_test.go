package jwt

import (
	"fmt"
	"testing"
)

func TestValidationErrorIncludes(t *testing.T) {
	type checks struct {
		params  []uint32 // the params to pass to .IncludesAll and .IncludesAny
		wantAll bool     // the desired result of .IncludesAll
		wantAny bool     // the desired result of .IncludesAny
	}
	cases := []struct {
		name      string   // the name of the test case
		errors    uint32   // the errors to put into the ValidationError
		wantValid bool     // true if the error should be .valid()
		checks    []checks // the checks to perform against the ValidationError
	}{
		{
			name:      "valid",
			errors:    0,
			wantValid: true,
			checks: []checks{
				{
					params:  []uint32{},
					wantAll: true,
					wantAny: false,
				},
				{
					params:  []uint32{ValidationErrorMalformed},
					wantAll: false,
					wantAny: false,
				},
			},
		},
		{
			name:   "one error",
			errors: ValidationErrorExpired,
			checks: []checks{
				{
					params:  []uint32{},
					wantAll: true,
					wantAny: false,
				},
				{
					params:  []uint32{ValidationErrorExpired},
					wantAll: true,
					wantAny: true,
				},
				{
					params:  []uint32{ValidationErrorExpired, ValidationErrorAudience},
					wantAll: false,
					wantAny: true,
				},
				{
					params:  []uint32{ValidationErrorAudience},
					wantAll: false,
					wantAny: false,
				},
			},
		},
		{
			name:   "many errors",
			errors: ValidationErrorAudience | ValidationErrorIssuer,
			checks: []checks{
				{
					params:  []uint32{},
					wantAll: true,
					wantAny: false,
				},
				{
					params:  []uint32{ValidationErrorAudience},
					wantAll: true,
					wantAny: true,
				},
				{
					params:  []uint32{ValidationErrorAudience, ValidationErrorId},
					wantAll: false,
					wantAny: true,
				},
				{
					params:  []uint32{ValidationErrorAudience, ValidationErrorIssuer},
					wantAll: true,
					wantAny: true,
				},
				{
					params:  []uint32{ValidationErrorAudience, ValidationErrorIssuer, ValidationErrorNotValidYet},
					wantAll: false,
					wantAny: true,
				},
				{
					params:  []uint32{ValidationErrorExpired, ValidationErrorSignatureInvalid},
					wantAll: false,
					wantAny: false,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ve := NewValidationError(tc.name, tc.errors)
			if got := ve.valid(); got != tc.wantValid {
				t.Errorf("ve.valid() = %v, want %v", got, tc.wantValid)
			}
			for _, ch := range tc.checks {
				t.Run(fmt.Sprint(ch.params), func(t *testing.T) {
					if got := ve.IncludesAll(ch.params...); got != ch.wantAll {
						t.Errorf("ve.IncludesAll(%v) = %v; want %v", ch.params, got, ch.wantAll)
					}
					if got := ve.IncludesAny(ch.params...); got != ch.wantAny {
						t.Errorf("ve.IncludesAny(%v) = %v; want %v", ch.params, got, ch.wantAny)
					}
				})
			}
		})
	}
}
