package jwt

import "time"

// ParserOption is used to implement functional-style options that modify the behavior of the parser. To add
// new options, just create a function (ideally beginning with With or Without) that returns an anonymous function that
// takes a *Parser type as input and manipulates its configuration accordingly.
type ParserOption func(*Parser)

// WithValidMethods is an option to supply algorithm methods that the parser will check. Only those methods will be considered valid.
// It is heavily encouraged to use this option in order to prevent attacks such as https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/.
func WithValidMethods(methods []string) ParserOption {
	return func(p *Parser) {
		p.ValidMethods = methods
	}
}

// WithJSONNumber is an option to configure the underlying JSON parser with UseNumber
func WithJSONNumber() ParserOption {
	return func(p *Parser) {
		p.UseJSONNumber = true
	}
}

// WithoutClaimsValidation is an option to disable claims validation. This option should only be used if you exactly know
// what you are doing.
func WithoutClaimsValidation() ParserOption {
	return func(p *Parser) {
		p.SkipClaimsValidation = true
	}
}

// WithLeeway returns the ParserOption for specifying the leeway window.
func WithLeeway(d time.Duration) ParserOption {
	return func(p *Parser) {
		p.validationOptions = append(p.validationOptions, withLeeway(d))
	}
}

// WithoutIssuedAt is an option to disable the validation of the issued at (iat) claim.
// The current `iat` time based validation is planned to be deprecated in v5

func WithoutIssuedAt() ParserOption {
	return func(p *Parser) {
		p.validationOptions = append(p.validationOptions, withoutIssuedAt())
	}
}

// WithAudience returns the ParserOption for specifying an expected aud member value
func WithAudience(aud string) ParserOption {
	return func(p *Parser) {
		p.validationOptions = append(p.validationOptions, withAudience(aud))
	}
}

// WithoutAudienceValidation returns the ParserOption that specifies audience check should be skipped
func WithoutAudienceValidation() ParserOption {
	return func(p *Parser) {
		p.validationOptions = append(p.validationOptions, withoutAudienceValidation())
	}
}
