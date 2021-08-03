package request

import (
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

// ParseFromRequest extracts and parses a JWT token from an HTTP request.
// This behaves the same as Parse, but accepts a request and an extractor
// instead of a token string.  The Extractor interface allows you to define
// the logic for extracting a token.  Several useful implementations are provided.
//
// You can provide options to modify parsing behavior
func ParseFromRequest(req *http.Request, extractor Extractor, keyFunc jwt.Keyfunc, options ...ParseFromRequestOption) (token *jwt.Token, err error) {
	// Create basic parser struct
	p := &fromRequestParser{req, extractor, nil, nil}

	// Handle options
	for _, option := range options {
		option(p)
	}

	// Set defaults
	if p.claims == nil {
		p.claims = jwt.MapClaims{}
	}
	if p.parser == nil {
		p.parser = &jwt.Parser{}
	}

	// perform extract
	tokenString, err := p.extractor.ExtractToken(req)
	if err != nil {
		return nil, err
	}

	// perform parse
	return p.parser.ParseWithClaims(tokenString, p.claims, keyFunc)
}

// ParseFromRequestWithClaims is an alias for ParseFromRequest but with custom Claims type.
//
// Deprecated: use ParseFromRequest and the WithClaims option
func ParseFromRequestWithClaims(req *http.Request, extractor Extractor, claims jwt.Claims, keyFunc jwt.Keyfunc) (token *jwt.Token, err error) {
	return ParseFromRequest(req, extractor, keyFunc, WithClaims(claims))
}

type fromRequestParser struct {
	req       *http.Request
	extractor Extractor
	claims    jwt.Claims
	parser    *jwt.Parser
}

type ParseFromRequestOption func(*fromRequestParser)

// WithClaims parses with custom claims
func WithClaims(claims jwt.Claims) ParseFromRequestOption {
	return func(p *fromRequestParser) {
		p.claims = claims
	}
}

// WithParser parses using a custom parser
func WithParser(parser *jwt.Parser) ParseFromRequestOption {
	return func(p *fromRequestParser) {
		p.parser = parser
	}
}
