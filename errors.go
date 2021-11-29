package jwt

import (
	"errors"
)

// Error constants
var (
	ErrInvalidKey      = errors.New("key is invalid")
	ErrInvalidKeyType  = errors.New("key is of invalid type")
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")

	ErrTokenMalformed        = errors.New("token is malformed")
	ErrTokenUnverifiable     = errors.New("token is unverifiable")
	ErrTokenSignatureInvalid = errors.New("token signature is invalid")

	ErrTokenExpired          = errors.New("token is expired")
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
	ErrTokenNotValidYet      = errors.New("token is not valid yet")
)

// The errors that might occur when parsing and validating a token
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed

	// Standard Claim validation errors
	ValidationErrorAudience      // AUD validation failed
	ValidationErrorExpired       // EXP validation failed
	ValidationErrorIssuedAt      // IAT validation failed
	ValidationErrorIssuer        // ISS validation failed
	ValidationErrorNotValidYet   // NBF validation failed
	ValidationErrorId            // JTI validation failed
	ValidationErrorClaimsInvalid // Generic claims validation error
)

// NewValidationError is a helper for constructing a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText,
		Errors: errorFlags,
	}
}

// ValidationError represents an error from Parse if token is not valid
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text
}

// Error is the implementation of the err interface.
func (e ValidationError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

// Unwrap gives errors.Is and errors.As access to the inner error.
func (e *ValidationError) Unwrap() error {
	return e.Inner
}

// No errors
func (e *ValidationError) valid() bool {
	return e.Errors == 0
}

// Is checks if this ValidationError is of the supplied error type. We are first checking for the exact error message
// by suppling the inner message. If that fails, we the error flags. This way we can supply custom error messages
// and still use errors.Is using the pre-supplied error variables.
func (e *ValidationError) Is(err error) bool {
	// Check, if our inner error is a direct match
	if errors.Is(errors.Unwrap(e), err) {
		return true
	}

	// Otherwise, we need to match using our error flags
	switch err {
	case ErrTokenMalformed:
		return e.Errors&ValidationErrorMalformed != 0
	case ErrTokenUnverifiable:
		return e.Errors&ValidationErrorUnverifiable != 0
	case ErrTokenSignatureInvalid:
		return e.Errors&ValidationErrorUnverifiable != 0
	case ErrTokenExpired:
		return e.Errors&ValidationErrorExpired != 0
	case ErrTokenNotValidYet:
		return e.Errors&ValidationErrorNotValidYet != 0
	case ErrTokenUsedBeforeIssued:
		return e.Errors&ValidationErrorIssuedAt != 0
	}

	return false
}
