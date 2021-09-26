package jwt

// ParserOption is used to implement functional options that modify the behaviour of the parser
type ParserOption func(*Parser)

func WithValidMethods(methods []string) ParserOption {
	return func(p *Parser) {
		p.ValidMethods = methods
	}
}

func WithJSONNumber() ParserOption {
	return func(p *Parser) {
		p.UseJSONNumber = true
	}
}

func WithoutClaimsValidation() ParserOption {
	return func(p *Parser) {
		p.SkipClaimsValidation = true
	}
}
