package jwt

import "time"

// validationOption is used to implement functional-style options that modify the behavior of the parser. To add
// new options, just create a function (ideally beginning with With or Without) that returns an anonymous function that
// takes a *validator type as input and manipulates its configuration accordingly.
//
// Note that this struct is (currently) un-exported, its naming is subject to change and will only be exported once
// the API is more stable.
type validationOption func(*validator)

// validator represents options that can be used for claims validation
//
// Note that this struct is (currently) un-exported, its naming is subject to change and will only be exported once
// the API is more stable.
type validator struct {
	leeway time.Duration // Leeway to provide when validating time values
	iat    bool
}

// withLeeway is an option to set the clock skew (leeway) window
//
// Note that this function is (currently) un-exported, its naming is subject to change and will only be exported once
// the API is more stable.
func withLeeway(d time.Duration) validationOption {
	return func(v *validator) {
		v.leeway = d
	}
}

// withIssuedAth is an option to enable the validation of the issued at (iat) claim
//
// Note that this function is (currently) un-exported, its naming is subject to change and will only be exported once
// the API is more stable.
func withIssuedAt() validationOption {
	return func(v *validator) {
		v.iat = true
	}
}

func getValidator(opts ...validationOption) validator {
	v := validator{}
	for _, o := range opts {
		o(&v)
	}
	return v
}
