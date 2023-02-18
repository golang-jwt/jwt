package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

type parserOpts struct {
	// If populated, only these methods will be considered valid.
	validMethods []string

	// Use JSON Number format in JSON decoder.
	useJSONNumber bool

	// Skip claims validation during token parsing.
	skipClaimsValidation bool

	validator *validator
}

type Parser[T Claims] struct {
	opts parserOpts
}

// NewParser creates a new Parser with the specified options
func NewParser(options ...ParserOption) *Parser[MapClaims] {
	p := &Parser[MapClaims]{
		opts: parserOpts{validator: &validator{}},
	}

	// Loop through our parsing options and apply them
	for _, option := range options {
		option(&p.opts)
	}

	return p
}

func NewParserFor[T Claims](options ...ParserOption) *Parser[T] {
	p := &Parser[T]{
		opts: parserOpts{validator: &validator{}},
	}

	// Loop through our parsing options and apply them
	for _, option := range options {
		option(&p.opts)
	}

	return p
}

// Parse parses, validates, verifies the signature and returns the parsed token.
// keyFunc will receive the parsed token and should return the key for validating.
//
// Note: If you provide a custom claim implementation that embeds one of the standard claims (such as RegisteredClaims),
// make sure that a) you either embed a non-pointer version of the claims or b) if you are using a pointer, allocate the
// proper memory for it before passing in the overall claims, otherwise you might run into a panic.
func (p *Parser[T]) Parse(tokenString string, keyFunc Keyfunc[T]) (*Token[T], error) {
	token, parts, err := p.ParseUnverified(tokenString)
	if err != nil {
		return token, err
	}

	// Verify signing method is in the required set
	if p.opts.validMethods != nil {
		signingMethodValid := false
		alg := token.Method.Alg()
		for _, m := range p.opts.validMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set
			return token, newError(fmt.Sprintf("signing method %v is invalid", alg), ErrTokenSignatureInvalid)
		}
	}

	// Lookup key
	var key interface{}
	if keyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, newError("no keyfunc was provided", ErrTokenUnverifiable)
	}
	if key, err = keyFunc(token); err != nil {
		return token, newError("error while executing keyfunc", ErrTokenUnverifiable, err)
	}

	// Perform signature validation
	token.Signature = parts[2]
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		return token, newError("", ErrTokenSignatureInvalid, err)
	}

	// Validate Claims
	if !p.opts.skipClaimsValidation {
		// Make sure we have at least a default validator
		if p.opts.validator == nil {
			p.opts.validator = newValidator()
		}

		if err := p.opts.validator.Validate(token.Claims); err != nil {
			return token, newError("", ErrTokenInvalidClaims, err)
		}
	}

	// No errors so far, token is valid.
	token.Valid = true

	return token, nil
}

// ParseUnverified parses the token but doesn't validate the signature.
//
// WARNING: Don't use this method unless you know what you're doing.
//
// It's only ever useful in cases where you know the signature is valid (because it has
// been checked previously in the stack) and you want to extract values from it.
func (p *Parser[T]) ParseUnverified(tokenString string) (token *Token[T], parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, parts, newError("token contains an invalid number of segments", ErrTokenMalformed)
	}

	token = &Token[T]{Raw: tokenString}

	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return token, parts, newError("tokenstring should not contain 'bearer '", ErrTokenMalformed)
		}
		return token, parts, newError("could not base64 decode header", ErrTokenMalformed, err)
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, parts, newError("could not JSON decode header", ErrTokenMalformed, err)
	}

	// parse Claims
	var claimBytes []byte
	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, parts, newError("could not base64 decode claim", ErrTokenMalformed, err)
	}

	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	if p.opts.useJSONNumber {
		dec.UseNumber()
	}

	// Handle decode error
	if err = dec.Decode(&token.Claims); err != nil {
		return token, parts, newError("could not JSON decode claim", ErrTokenMalformed, err)
	}

	// Lookup signature method
	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, parts, newError("signing method (alg) is unavailable", ErrTokenUnverifiable)
		}
	} else {
		return token, parts, newError("signing method (alg) is unspecified", ErrTokenUnverifiable)
	}

	return token, parts, nil
}
