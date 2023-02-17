package request

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// ParseFromRequest extracts and parses a JWT token from an HTTP request.
// This behaves the same as Parse, but accepts a request and an extractor
// instead of a token string.  The Extractor interface allows you to define
// the logic for extracting a token.  Several useful implementations are provided.
//
// You can provide options to modify parsing behavior
func ParseFromRequest(req *http.Request, extractor Extractor, keyFunc jwt.Keyfunc[jwt.MapClaims], options ...ParseFromRequestOption[jwt.MapClaims]) (token *jwt.Token[jwt.MapClaims], err error) {
	// Create basic parser struct
	p := &fromRequestParser[jwt.MapClaims]{req, extractor, nil, nil}

	// Handle options
	for _, option := range options {
		option(p)
	}

	// Set defaults
	if p.claims == nil {
		p.claims = jwt.MapClaims{}
	}
	if p.parser == nil {
		p.parser = &jwt.Parser[jwt.MapClaims]{}
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
func ParseFromRequestWithClaims[T jwt.Claims](req *http.Request, extractor Extractor, claims T, keyFunc jwt.Keyfunc[T]) (token *jwt.Token[T], err error) {
	return ParseFromRequest(req, extractor, keyFunc, WithClaims(claims))
}

type fromRequestParser[T jwt.Claims] struct {
	req       *http.Request
	extractor Extractor
	claims    T
	parser    *jwt.Parser[T]
}

type ParseFromRequestOption[T jwt.Claims] func(*fromRequestParser[T])

// WithClaims parses with custom claims
func WithClaims[T jwt.Claims](claims T) ParseFromRequestOption[T] {
	return func(p *fromRequestParser[T]) {
		p.claims = claims
	}
}

// WithParser parses using a custom parser
func WithParser[T jwt.Claims](parser *jwt.Parser[T]) ParseFromRequestOption[T] {
	return func(p *fromRequestParser[T]) {
		p.parser = parser
	}
}
