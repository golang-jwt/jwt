package keyfunc

import (
	"errors"
	"fmt"

	legacy "github.com/dgrijalva/jwt-go"
	f3t "github.com/form3tech-oss/jwt-go"
	"github.com/golang-jwt/jwt/v4"
)

var (

	// ErrKID indicates that the JWT had an invalid kid.
	ErrKID = errors.New("the JWT has an invalid kid")

	// ErrUnsupportedKeyType indicates the JWT key type is an unsupported type.
	ErrUnsupportedKeyType = errors.New("the JWT key type is unsupported")
)

// Keyfunc is a compatibility function that matches the signature of github.com/golang-jwt/jwt/v4's jwt.Keyfunc
// function.
func (j *JWKs) Keyfunc(token *jwt.Token) (interface{}, error) {

	// Get the kid from the token header.
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKID)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKID)
	}

	// Get the jsonKey.
	key, err := j.getKey(kid)
	if err != nil {
		return nil, err
	}

	// Determine the key's algorithm and return the appropriate public key.
	switch keyAlg := token.Header["alg"]; keyAlg {
	case es256, es384, es512:
		return key.ECDSA()
	case ps256, ps384, ps512, rs256, rs384, rs512:
		return key.RSA()
	case hs256, hs384, hs512:
		return key.HMAC()
	default:

		// Assume there's a given key for a custom algorithm.
		if key.precomputed != nil {
			return key.precomputed, nil
		}
		return nil, fmt.Errorf("unable to find given key for kid: %w: %s: feel free to add a feature request or contribute to https://github.com/MicahParks/keyfunc", ErrUnsupportedKeyType, keyAlg)
	}
}

// KeyfuncF3T is a compatibility function that matches the signature of github.com/form3tech-oss/jwt-go's Keyfunc
// function.
func (j *JWKs) KeyfuncF3T(f3tToken *f3t.Token) (interface{}, error) {
	token := &jwt.Token{
		Raw:       f3tToken.Raw,
		Method:    f3tToken.Method,
		Header:    f3tToken.Header,
		Claims:    f3tToken.Claims,
		Signature: f3tToken.Signature,
		Valid:     f3tToken.Valid,
	}
	return j.Keyfunc(token)
}

// KeyfuncLegacy is a compatibility function that matches the signature of the legacy github.com/dgrijalva/jwt-go's
// Keyfunc function.
func (j *JWKs) KeyfuncLegacy(legacyToken *legacy.Token) (interface{}, error) {
	token := &jwt.Token{
		Raw:       legacyToken.Raw,
		Method:    legacyToken.Method,
		Header:    legacyToken.Header,
		Claims:    legacyToken.Claims,
		Signature: legacyToken.Signature,
		Valid:     legacyToken.Valid,
	}
	return j.Keyfunc(token)
}
