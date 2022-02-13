package jwt

import "time"

// ValidatorOption is used to implement functional-style options that modify the behavior of the parser. To add
// new options, just create a function (ideally beginning with With or Without) that returns an anonymous function that
// takes a *ValidatorOptions type as input and manipulates its configuration accordingly.
type ValidatorOption func(*ValidatorOptions)

// ValidatorOptions represents options that can be used for claims validation
type ValidatorOptions struct {
	leeway time.Duration // Leeway to provide when validating time values
}


// WithLeewayValidator is an option to set the clock skew (leeway) windows
func WithLeewayValidator(d time.Duration) ValidatorOption {
	return func(v *ValidatorOptions) {
		v.leeway = d
	}
}
