package jwt

import (
	"strings"
	"time"
)

// ValidatorOption is used to implement functional-style options that modify the
// behavior of the validator. To add new options, just create a function
// (ideally beginning with With or Without) that returns an anonymous function
// that takes a *Parser type as input and manipulates its configuration
// accordingly.
type ValidatorOption func(*Validator)

type PatternFunc func(s string) bool

func HasPrefix(prefix string) PatternFunc {
	return func(s string) bool {
		return strings.HasPrefix(s, prefix)
	}
}

func Equals(cmp string) PatternFunc {
	return func(s string) bool {
		return cmp == s
	}
}

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

// WithAudience configures the validator to require the specified audience in
// the `aud` claim. Validation will fail if the audience is not listed in the
// token or the `aud` claim is missing.
//
// NOTE: While the `aud` claim is OPTIONAL is a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim.
func WithAudience(aud string) ValidatorOption {
	return func(v *Validator) {
		v.expectedAud = aud
	}
}

// WithIssuer configures the validator to require the specified issuer in the
// `iss` claim. Validation will fail if a different issuer is specified in the
// token or the `iss` claim is missing.
//
// NOTE: While the `iss` claim is OPTIONAL is a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim.
func WithIssuer(iss string) ValidatorOption {
	return func(v *Validator) {
		v.expectedIss = iss
	}
}

// WithSubject configures the validator to require the specified subject in the
// `sub` claim. Validation will fail if a different subject is specified in the
// token or the `sub` claim is missing.
//
// NOTE: While the `sub` claim is OPTIONAL is a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim.
func WithSubject(sub string) ValidatorOption {
	return func(v *Validator) {
		v.expectedSubPattern = Equals(sub)
	}
}

func WithSubjectPattern(pattern PatternFunc) ValidatorOption {
	return func(v *Validator) {
		v.expectedSubPattern = pattern
	}
}
