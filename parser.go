package jwt

import (
	"bytes"
	"encoding/json"
	"strings"
)

type Parser struct {
	ValidMethods         []string // If populated, only these methods will be considered valid
	UseJSONNumber        bool     // Use JSON Number format in JSON decoder
	SkipClaimsValidation bool     // Skip claims validation during token parsing
}

// Parse parses, validates, and returns a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func (p *Parser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, MapClaims{}, keyFunc)
}

func (p *Parser) ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	token, parts, err := p.ParseUnverified(tokenString, claims)
	if err != nil {
		return token, err
	}

	// Verify signing method is in the required set
	if p.ValidMethods != nil {
		var signingMethodValid = false
		var alg = token.Method.Alg()
		for _, m := range p.ValidMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set
			return token, &InvalidSigningMethodError{Alg: alg}
		}
	}

	// Lookup key
	var key interface{}
	if keyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, ErrMissingKeyFunc
	}

	key, err = keyFunc(token)
	if err != nil {
		return token, &KeyFuncError{Err: err}
	}

	// Validate Claims
	if !p.SkipClaimsValidation {
		if err := token.Claims.Valid(); err != nil {
			return token, err
		}
	}

	// Perform validation
	token.Signature = parts[2]
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		token.Valid = false
		return token, err
	}
	token.Valid = true
	return token, nil
}

// ParseUnverified parses the token but doesn't validate the signature.
//
// WARNING: Don't use this method unless you know what you're doing.
//
// It's only ever useful in cases where you know the signature is valid (because it has
// been checked previously in the stack) and you want to extract values from it.
func (p *Parser) ParseUnverified(tokenString string, claims Claims) (token *Token, parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, parts, MalformedTokenError("token contains an invalid number of segments")
	}

	token = &Token{Raw: tokenString}

	// parse Header
	var headerBytes []byte
	headerBytes, err = DecodeSegment(parts[0])
	if err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return token, parts, MalformedTokenError(`token may not contain "bearer "`)
		}
		return token, parts, MalformedTokenError(err.Error())
	}

	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, parts, MalformedTokenError(err.Error())
	}

	// parse Claims
	var claimBytes []byte
	token.Claims = claims

	claimBytes, err = DecodeSegment(parts[1])
	if err != nil {
		return token, parts, MalformedTokenError(err.Error())
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	if p.UseJSONNumber {
		dec.UseNumber()
	}
	// JSON Decode.  Special case for map type to avoid weird pointer behavior
	if c, ok := token.Claims.(MapClaims); ok {
		err = dec.Decode(&c)
	} else {
		err = dec.Decode(&claims)
	}
	// Handle decode error
	if err != nil {
		return token, parts, MalformedTokenError(err.Error())
	}

	// Lookup signature method

	alg, ok := token.Header["alg"].(string)
	if !ok || len(alg) == 0 {
		return token, parts, MalformedTokenError("signing method (alg) not specified")
	}
	token.Method = GetSigningMethod(alg)
	if token.Method == nil {
		return token, parts, &UnregisteredSigningMethodError{Alg: alg}
	}
	return token, parts, nil
}
