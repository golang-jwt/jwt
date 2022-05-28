package jwt

import "time"

// ValidatorOption is used to implement functional-style options that modify the
// behavior of the validator. To add new options, just create a function
// (ideally beginning with With or Without) that returns an anonymous function
// that takes a *Parser type as input and manipulates its configuration
// accordingly.
type ValidatorOption func(*Validator)

// WithLeeway returns the ParserOption for specifying the leeway window.
func WithLeeway(leeway time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.leeway = leeway
	}
}
