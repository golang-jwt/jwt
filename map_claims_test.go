package jwt

import (
	"testing"
	"time"
)

func TestVerifyAud(t *testing.T) {
	var nilInterface interface{}
	var nilListInterface []interface{}
	var intListInterface interface{} = []int{1, 2, 3}
	type test struct {
		Name       string
		MapClaims  MapClaims
		Expected   bool
		Comparison string
		Required   bool
	}
	tests := []test{
		// Matching Claim in aud
		// Required = true
		{Name: "String Aud matching required", MapClaims: MapClaims{"aud": "example.com"}, Expected: true, Required: true, Comparison: "example.com"},
		{Name: "[]String Aud with match required", MapClaims: MapClaims{"aud": []string{"example.com", "example.example.com"}}, Expected: true, Required: true, Comparison: "example.com"},

		// Required = false
		{Name: "String Aud with match not required", MapClaims: MapClaims{"aud": "example.com"}, Expected: true, Required: false, Comparison: "example.com"},
		{Name: "Empty String Aud with match not required", MapClaims: MapClaims{}, Expected: true, Required: false, Comparison: "example.com"},
		{Name: "Empty String Aud with match not required", MapClaims: MapClaims{"aud": ""}, Expected: true, Required: false, Comparison: "example.com"},
		{Name: "Nil String Aud with match not required", MapClaims: MapClaims{"aud": nil}, Expected: true, Required: false, Comparison: "example.com"},

		{Name: "[]String Aud with match not required", MapClaims: MapClaims{"aud": []string{"example.com", "example.example.com"}}, Expected: true, Required: false, Comparison: "example.com"},
		{Name: "Empty []String Aud with match not required", MapClaims: MapClaims{"aud": []string{}}, Expected: true, Required: false, Comparison: "example.com"},

		// Non-Matching Claim in aud
		// Required = true
		{Name: "String Aud without match required", MapClaims: MapClaims{"aud": "not.example.com"}, Expected: false, Required: true, Comparison: "example.com"},
		{Name: "Empty String Aud without match required", MapClaims: MapClaims{"aud": ""}, Expected: false, Required: true, Comparison: "example.com"},
		{Name: "[]String Aud without match required", MapClaims: MapClaims{"aud": []string{"not.example.com", "example.example.com"}}, Expected: false, Required: true, Comparison: "example.com"},
		{Name: "Empty []String Aud without match required", MapClaims: MapClaims{"aud": []string{""}}, Expected: false, Required: true, Comparison: "example.com"},
		{Name: "String Aud without match not required", MapClaims: MapClaims{"aud": "not.example.com"}, Expected: false, Required: true, Comparison: "example.com"},
		{Name: "Empty String Aud without match not required", MapClaims: MapClaims{"aud": ""}, Expected: false, Required: true, Comparison: "example.com"},
		{Name: "[]String Aud without match not required", MapClaims: MapClaims{"aud": []string{"not.example.com", "example.example.com"}}, Expected: false, Required: true, Comparison: "example.com"},

		// Required = false
		{Name: "Empty []String Aud without match required", MapClaims: MapClaims{"aud": []string{""}}, Expected: true, Required: false, Comparison: "example.com"},

		// []interface{}
		{Name: "Empty []interface{} Aud without match required", MapClaims: MapClaims{"aud": nilListInterface}, Expected: true, Required: false, Comparison: "example.com"},
		{Name: "[]interface{} Aud wit match required", MapClaims: MapClaims{"aud": []interface{}{"a", "foo", "example.com"}}, Expected: true, Required: true, Comparison: "example.com"},
		{Name: "[]interface{} Aud wit match but invalid types", MapClaims: MapClaims{"aud": []interface{}{"a", 5, "example.com"}}, Expected: false, Required: true, Comparison: "example.com"},
		{Name: "[]interface{} Aud int wit match required", MapClaims: MapClaims{"aud": intListInterface}, Expected: false, Required: true, Comparison: "example.com"},

		// interface{}
		{Name: "Empty interface{} Aud without match not required", MapClaims: MapClaims{"aud": nilInterface}, Expected: true, Required: false, Comparison: "example.com"},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var opts []ValidatorOption

			if test.Required {
				opts = append(opts, WithAudience(test.Comparison))
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
