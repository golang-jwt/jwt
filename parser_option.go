package jwt

import "time"

// ParserOption is used to implement functional-style options that modify the behavior of the parser. To add
// new options, just create a function (ideally beginning with With or Without) that returns an anonymous function that
// takes a *Parser type as input and manipulates its configuration accordingly.
type ParserOption[T Claims] func(*Parser[T])

// WithValidMethods is an option to supply algorithm methods that the parser will check. Only those methods will be considered valid.
// It is heavily encouraged to use this option in order to prevent attacks such as https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/.
func WithValidMethods[T Claims](methods []string) ParserOption[T] {
	return func(p *Parser[T]) {
		p.validMethods = methods
	}
}

// WithJSONNumber is an option to configure the underlying JSON parser with UseNumber
func WithJSONNumber[T Claims]() ParserOption[T] {
	return func(p *Parser[T]) {
		p.useJSONNumber = true
	}
}

// WithoutClaimsValidation is an option to disable claims validation. This option should only be used if you exactly know
// what you are doing.
func WithoutClaimsValidation[T Claims]() ParserOption[T] {
	return func(p *Parser[T]) {
		p.skipClaimsValidation = true
	}
}

// WithLeeway returns the ParserOption for specifying the leeway window.
func WithLeeway[T Claims](leeway time.Duration) ParserOption[T] {
	return func(p *Parser[T]) {
		p.validator.leeway = leeway
	}
}

// WithTimeFunc returns the ParserOption for specifying the time func. The
// primary use-case for this is testing. If you are looking for a way to account
// for clock-skew, WithLeeway should be used instead.
func WithTimeFunc[T Claims](f func() time.Time) ParserOption[T] {
	return func(p *Parser[T]) {
		p.validator.timeFunc = f
	}
}

// WithIssuedAt returns the ParserOption to enable verification
// of issued-at.
func WithIssuedAt[T Claims]() ParserOption[T] {
	return func(p *Parser[T]) {
		p.validator.verifyIat = true
	}
}

// WithAudience configures the validator to require the specified audience in
// the `aud` claim. Validation will fail if the audience is not listed in the
// token or the `aud` claim is missing.
//
// NOTE: While the `aud` claim is OPTIONAL is a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim.
func WithAudience[T Claims](aud string) ParserOption[T] {
	return func(p *Parser[T]) {
		p.validator.expectedAud = aud
	}
}

// WithIssuer configures the validator to require the specified issuer in the
// `iss` claim. Validation will fail if a different issuer is specified in the
// token or the `iss` claim is missing.
//
// NOTE: While the `iss` claim is OPTIONAL is a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim.
func WithIssuer[T Claims](iss string) ParserOption[T] {
	return func(p *Parser[T]) {
		p.validator.expectedIss = iss
	}
}

// WithSubject configures the validator to require the specified subject in the
// `sub` claim. Validation will fail if a different subject is specified in the
// token or the `sub` claim is missing.
//
// NOTE: While the `sub` claim is OPTIONAL is a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim.
func WithSubject[T Claims](sub string) ParserOption[T] {
	return func(p *Parser[T]) {
		p.validator.expectedSub = sub
	}
}
