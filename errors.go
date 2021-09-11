package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var ValidationErrorFormat = func(errs []error) string {

	str := "jwt: errors occurred validating the claims"
	for _, err := range errs {
		errstr := strings.TrimPrefix(err.Error(), "jwt: ")
		if len(errstr) > 0 {
			str = str + "\n\t" + errstr
		}
	}
	return str
}

// Error constants
var (
	ErrMalformedToken              = errors.New("jwt: token is malformed")
	ErrTokenContainsBearer         = errors.New(`jwt: token may not contain "bearer "`)
	ErrInvalidSigningMethod        = errors.New("jwt: invalid signing method")
	ErrUnregisteredSigningMethod   = errors.New("jwt: signing method not registered")
	ErrInvalidKey                  = errors.New("jwt: key is invalid")
	ErrInvalidKeyType              = errors.New("jwt: invalid key type")
	ErrHashUnavailable             = errors.New("jwt: the requested hash function is unavailable")
	ErrTokenNotYetValid            = errors.New("jwt: the token is not yet valid")
	ErrTokenExpired                = errors.New("jwt: the token is expired")
	ErrTokenUsedBeforeIssued       = errors.New("jwt: the token was used before issued")
	ErrNoneSignatureTypeDisallowed = errors.New(`jwt: "none" signature type is not allowed`)
	ErrMissingKeyFunc              = errors.New("jwt: KeyFunc not provided")
	ErrSignatureInvalid            = errors.New("jwt: signature is invalid")
	ErrKeyFuncError                = errors.New("jwt: KeyFunc returned an error")
)

type KeyFuncError struct {
	Err error
}

func (err *KeyFuncError) Error() string {
	return ErrKeyFuncError.Error() + "\n\t" + err.Err.Error()
}

func (err *KeyFuncError) Unwrap() error {
	return err.Err
}

func (err *KeyFuncError) Is(target error) bool {
	if _, ok := target.(*KeyFuncError); ok {
		return true
	}
	if errors.Is(err.Err, target) {
		return true
	}
	return errors.Is(target, ErrKeyFuncError)
}

type SignatureVerificationError struct {
	Algorithm string
	err       error
}

func (err *SignatureVerificationError) Error() string {
	return ErrSignatureInvalid.Error() + " [" + err.Algorithm + "]"
}

func (err *SignatureVerificationError) Is(cmp error) bool {
	if _, ok := cmp.(*SignatureVerificationError); ok {
		return true
	}
	if errors.Is(err.err, cmp) {
		return true
	}
	return errors.Is(err.Unwrap(), cmp)
}

func (err *SignatureVerificationError) Unwrap() error {
	return ErrSignatureInvalid
}

type MalformedTokenError string

func (err MalformedTokenError) Error() string {
	str := ErrMalformedToken.Error()
	if len(err) > 0 {
		str = str + "\n\t" + string(err)
	}
	return str
}

func (err MalformedTokenError) Unwrap() error {
	return ErrMalformedToken
}

type UnregisteredSigningMethodError struct {
	Alg string
}

func (err *UnregisteredSigningMethodError) Error() string {
	return `jwt: signing method "` + err.Alg + `" is not registered`
}

func (err *UnregisteredSigningMethodError) Unwrap() error {
	return ErrUnregisteredSigningMethod
}

type InvalidSigningMethodError struct {
	Alg string
}

func (err *InvalidSigningMethodError) Error() string {
	return `jwt: signing method "` + err.Alg + `" is invalid`
}

func (err *InvalidSigningMethodError) Unwrap() error {
	return ErrInvalidSigningMethod
}

type NotYetValidError struct {
	ValidAt     time.Time
	AttemptedAt time.Time
}

func (err *NotYetValidError) Delta() time.Duration {
	return err.AttemptedAt.Sub(err.ValidAt)
}
func (err *NotYetValidError) Error() string {
	if !err.ValidAt.IsZero() {
		return fmt.Sprintf("token is not valid for another %v", err.Delta())
	} else {
		return ErrTokenNotYetValid.Error()
	}
}
func (err *NotYetValidError) Unwrap() error {
	return ErrTokenNotYetValid
}

type UsedBeforeIssuedError struct {
	IssuedAt    time.Time
	AttemptedAt time.Time
}

func (err *UsedBeforeIssuedError) Delta() time.Duration {
	return err.IssuedAt.Sub(err.AttemptedAt)
}

func (err *UsedBeforeIssuedError) Error() string {
	return fmt.Sprintf("token is not valid for another %v", err.Delta())
}
func (err *UsedBeforeIssuedError) Unwrap() error {
	return ErrTokenUsedBeforeIssued
}

type ExpiredError struct {
	ExpiredAt   time.Time
	AttemptedAt time.Time
}

func (err *ExpiredError) Delta() time.Duration {
	return err.AttemptedAt.Sub(err.ExpiredAt)
}

func (err *ExpiredError) Error() string {
	return fmt.Sprintf("token is expired by %v", err.Delta())
}
func (err *ExpiredError) Unwrap() error {
	return ErrTokenExpired
}

// The errors that might occur when parsing and validating a token
const (
// ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
// ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
// ValidationErrorSignatureInvalid                    // Signature validation failed

// Standard Claim validation errors
// ValidationErrorAudience      // AUD validation failed
// ValidationErrorExpired       // EXP validation failed
// ValidationErrorIssuedAt      // IAT validation failed
// ValidationErrorIssuer        // ISS validation failed
// ValidationErrorNotValidYet   // NBF validation failed
// ValidationErrorId            // JTI validation failed
// ValidationErrorClaimsInvalid // Generic claims validation error
)

// // NewValidationError is a helper for constructing a ValidationError with a string error message
// func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
// 	return &ValidationError{
// 		text:   errorText,
// 		Errors: errorFlags,
// 	}
// }

// // ValidationError represents an error from Parse if token is not valid
// type ValidationError struct {
// 	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
// 	Errors uint32 // bitfield.  see ValidationError... constants
// 	text   string // errors that do not have a valid error just have text
// }

// // Error is the implementation of the err interface.
// func (e ValidationError) Error() string {
// 	if e.Inner != nil {
// 		return e.Inner.Error()
// 	} else if e.text != "" {
// 		return e.text
// 	} else {
// 		return "token is invalid"
// 	}
// }

// // No errors
// func (e *ValidationError) valid() bool {
// 	return e.Errors == 0
// }
