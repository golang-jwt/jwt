package jwt

import (
	"errors"
	"strings"
)

var (
	ErrInvalidKey                   = errors.New("key is invalid")
	ErrInvalidEd25519PublicKeyType  = errors.New("key is of invalid type, expected key type: ed25519.PublicKey")
	ErrInvalidEd25519PrivateKeyType = errors.New("key is of invalid type, expected key type: ed25519.PrivateKey")
	ErrInvalidRSAPublicKeyType      = errors.New("key is of invalid type, expected key type: *rsa.PublicKey")
	ErrInvalidRSAPrivateKeyType     = errors.New("key is of invalid type, expected key type: *rsa.PrivateKey")
	ErrInvalidECDSAPublicKeyType    = errors.New("key is of invalid type, expected key type: *ecdsa.PublicKey")
	ErrInvalidECDSAPrivateKeyType   = errors.New("key is of invalid type, expected key type: *ecdsa.PrivateKey")
	ErrInvalidHMACKeyType           = errors.New("key is of invalid type, expected key type: []byte")
	ErrHashUnavailable              = errors.New("the requested hash function is unavailable")
	ErrTokenMalformed               = errors.New("token is malformed")
	ErrTokenUnverifiable            = errors.New("token is unverifiable")
	ErrTokenSignatureInvalid        = errors.New("token signature is invalid")
	ErrTokenRequiredClaimMissing    = errors.New("token is missing required claim")
	ErrTokenInvalidAudience         = errors.New("token has invalid audience")
	ErrTokenExpired                 = errors.New("token is expired")
	ErrTokenUsedBeforeIssued        = errors.New("token used before issued")
	ErrTokenInvalidIssuer           = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject          = errors.New("token has invalid subject")
	ErrTokenNotValidYet             = errors.New("token is not valid yet")
	ErrTokenInvalidClaims           = errors.New("token has invalid claims")
	ErrInvalidType                  = errors.New("invalid type for claim")
)

// joinedError is an error type that works similar to what [errors.Join]
// produces, with the exception that it has a nice error string; mainly its
// error messages are concatenated using a comma, rather than a newline.
type joinedError struct {
	errs []error
}

func (je joinedError) Error() string {
	msg := []string{}
	for _, err := range je.errs {
		msg = append(msg, err.Error())
	}

	return strings.Join(msg, ", ")
}

// joinErrors joins together multiple errors. Useful for scenarios where
// multiple errors next to each other occur, e.g., in claims validation.
func joinErrors(errs ...error) error {
	return &joinedError{
		errs: errs,
	}
}
