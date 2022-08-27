package jwt

import "time"

// ValidatorOption is used to implement functional-style options that modify the
// behavior of the validator. To add new options, just create a function
// (ideally beginning with With or Without) that returns an anonymous function
// that takes a *Parser type as input and manipulates its configuration
// accordingly.
type ValidatorOption func(*Validator)

// WithLeeway returns the ValidatorOption for specifying the leeway window.
func WithLeeway(leeway time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.leeway = leeway
	}
}

// WithTimeFunc returns the ValidatorOption for specifying the time func. The
// primary use-case for this is testing. If you are looking for a way to account
// for clock-skew, WithLeeway should be used instead.
func WithTimeFunc(f func() time.Time) ValidatorOption {
	return func(v *Validator) {
		v.timeFunc = f
	}
}

// WithIssuedAt returns the ValidatorOption to enable verification
// of issued-at.
func WithIssuedAt() ValidatorOption {
	return func(v *Validator) {
		v.verifyIat = true
	}
}

// WithAudience returns the ValidatorOption to set the expected audience.
func WithAudience(aud string) ValidatorOption {
	return func(v *Validator) {
		v.expectedAud = aud
	}
}
