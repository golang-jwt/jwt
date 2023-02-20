package jwt

import (
	"errors"
	"strings"
)

// Error constants
var (
	ErrInvalidKey      = errors.New("key is invalid")
	ErrInvalidKeyType  = errors.New("key is of invalid type")
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")

	ErrTokenMalformed            = errors.New("token is malformed")
	ErrTokenUnverifiable         = errors.New("token is unverifiable")
	ErrTokenRequiredClaimMissing = errors.New("a required claim is missing")
	ErrTokenSignatureInvalid     = errors.New("token signature is invalid")

	ErrTokenInvalidAudience  = errors.New("token has invalid audience")
	ErrTokenExpired          = errors.New("token is expired")
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
	ErrTokenInvalidIssuer    = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject   = errors.New("token has invalid subject")
	ErrTokenNotValidYet      = errors.New("token is not valid yet")
	ErrTokenInvalidId        = errors.New("token has invalid id")
	ErrTokenInvalidClaims    = errors.New("token has invalid claims")

	ErrInvalidType = errors.New("invalid type for claim")
)

// The errors that might occur when parsing and validating a token
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed

	// Registered Claim validation errors
	ValidationErrorAudience      // AUD validation failed
	ValidationErrorExpired       // EXP validation failed
	ValidationErrorIssuedAt      // IAT validation failed
	ValidationErrorIssuer        // ISS validation failed
	ValidationErrorSubject       // SUB validation failed
	ValidationErrorNotValidYet   // NBF validation failed
	ValidationErrorId            // JTI validation failed
	ValidationErrorClaimsInvalid // Generic claims validation error
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
func joinErrors(errs []error) error {
	return &joinedError{
		errs: errs,
	}
}

/*
// NewValidationError is a helper for constructing a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText,
		Errors: errorFlags,
	}
}

// ValidationError represents an error from Parse if token is not valid
type ValidationError struct {
	// Inner stores the error returned by external dependencies, e.g.: KeyFunc
	Inner error
	// Errors is a bit-field. See ValidationError... constants
	Errors uint32
	// Text can be used for errors that do not have a valid error just have text
	text string
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

// Is checks if this ValidationError is of the supplied error. We are first
// checking for the exact error message by comparing the inner error message. If
// that fails, we compare using the error flags. This way we can use custom
// error messages (mainly for backwards compatibility) and still leverage
// errors.Is using the global error variables.
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
		return e.Errors&ValidationErrorSignatureInvalid != 0
	case ErrTokenInvalidAudience:
		return e.Errors&ValidationErrorAudience != 0
	case ErrTokenExpired:
		return e.Errors&ValidationErrorExpired != 0
	case ErrTokenUsedBeforeIssued:
		return e.Errors&ValidationErrorIssuedAt != 0
	case ErrTokenInvalidIssuer:
		return e.Errors&ValidationErrorIssuer != 0
	case ErrTokenNotValidYet:
		return e.Errors&ValidationErrorNotValidYet != 0
	case ErrTokenInvalidId:
		return e.Errors&ValidationErrorId != 0
	case ErrTokenInvalidClaims:
		return e.Errors&ValidationErrorClaimsInvalid != 0
	}

	return false
}
*/
