package jwt

import (
	"errors"
)

// Error constants
var (
	ErrInvalidKey      = errors.New("key is invalid")
	ErrInvalidKeyType  = errors.New("key is of invalid type")
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")
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

// NewValidationError constructs a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText,
		Errors: errorFlags,
	}
}

// ValidationError is returned from Parse if the token is not valid.
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text
}

// Error implements the builtin error interface.
func (e ValidationError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

// IncludesAll tells whether an error includes all the bits provided.
// For instance, to check whether an error matches one condition:
//
//     valErr.IncludesAll(ValidationErrorAudience)
//     // will return true if ValidationErrorAudience is present in the Errors field
//     // and false otherwise
//
// or to check if it matches many conditions:
//
//     valErr.IncludesAll(ValidationErrorIssuer, ValidationErrorAudience)
//     // will return true only if BOTH ValidationErrorIssuer AND ValidationErrorAudience
//     // are present on the Errors field and false otherwise.
func (e ValidationError) IncludesAll(flags ...uint32) bool {
	bits := uint32(0)
	for _, flag := range flags {
		bits |= flag
	}
	return (e.Errors & bits) == bits
}

// IncludesAny tells whether an error includes any of the bits provided.
// Checking for matching of one condition is exactly as in IncludesAll.
// To check if an error matches any of several conditions:
//
//     valErr.IncludesAny(ValidationErrorNotValidYet, ValidationErrorExpired)
//     // will return true if:
//     // - ValidationErrorNotValidYet is present
//     // - ValidationErrorExpired is present
//     // - ValidationErrorNotValidYet and ValidationErrorExpired
//     //   are somehow both present
//     // and will return false only if NEITHER NotValidYet NOR Expired are present.
func (e ValidationError) IncludesAny(flags ...uint32) bool {
	bits := uint32(0)
	for _, flag := range flags {
		bits |= flag
	}
	return (e.Errors & bits) != 0
}

// valid returns true if there are no errors.
func (e ValidationError) valid() bool {
	return e.Errors == 0
}
