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
func ParseFromRequest(req *http.Request, extractor Extractor, keyFunc jwt.Keyfunc, options ...Option) (token *jwt.Token, err error) {
	return ParseFromRequestWithClaims(req, extractor, keyFunc, options...)
}

func ParseFromRequestWithClaims[T jwt.Claims](req *http.Request, extractor Extractor, keyFunc jwt.KeyfuncFor[T], options ...OptionFor[T]) (token *jwt.TokenFor[T], err error) {
	// Create basic parser struct
	p := &fromRequestParser[T]{
		req:       req,
		extractor: extractor,
	}

	// Handle options
	for _, option := range options {
		option(p)
	}

	// Set defaults
	if p.parser == nil {
		p.parser = &jwt.Parser[T]{}
	}

	// perform extract
	tokenString, err := p.extractor.ExtractToken(req)
	if err != nil {
		return nil, err
	}

	// perform parse
	return p.parser.Parse(tokenString, keyFunc)
}

type fromRequestParser[T jwt.Claims] struct {
	req       *http.Request
	extractor Extractor
	parser    *jwt.Parser[T]
}

type OptionFor[T jwt.Claims] func(*fromRequestParser[T])

type Option = OptionFor[jwt.MapClaims]

// WithParser parses using a custom parser
func WithParser[T jwt.Claims](parser *jwt.Parser[T]) OptionFor[T] {
	return func(p *fromRequestParser[T]) {
		p.parser = parser
	}
}
