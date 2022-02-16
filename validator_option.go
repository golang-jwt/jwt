package jwt

import "time"

// validationOption is used to implement functional-style options that modify the behavior of the parser. To add
// new options, just create a function (ideally beginning with With or Without) that returns an anonymous function that
// takes a *ValidatorOptions type as input and manipulates its configuration accordingly.
type validationOption func(*validator)

// validator represents options that can be used for claims validation
type validator struct {
	leeway time.Duration // Leeway to provide when validating time values
}


// withLeewayValidator is an option to set the clock skew (leeway) windows
func withLeewayValidator(d time.Duration) validationOption {
	return func(v *validator) {
		v.leeway = d
	}
}
