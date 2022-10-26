package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// Validator is the core of the new Validation API. It can either be used to
// modify the validation used during parsing with the [WithValidator] parser
// option or used standalone to validate an already parsed [Claim]. It can be
// further customized with a range of specified [ValidatorOption]s.
type Validator struct {
	// leeway is an optional leeway that can be provided to account for clock skew.
	leeway time.Duration

	// timeFunc is used to supply the current time that is needed for
	// validation. If unspecified, this defaults to time.Now.
	timeFunc func() time.Time

	// verifyIat specifies whether the iat (Issued At) claim will be verified.
	// According to https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6 this
	// only specifies the age of the token, but no validation check is
	// necessary. However, if wanted, it can be checked if the iat is
	// unrealistic, i.e., in the future.
	verifyIat bool

	// expectedAud contains the audiences this token expects. Supplying an empty
	// string will disable aud checking.
	expectedAud string
}

// CustomClaims represents a custom claims interface, which can be built upon the integrated
// claim types, such as map claims or registered claims.
type CustomClaims interface {
	// CustomValidation can be implemented by a user-specific claim to support
	// additional validation steps in addition to the regular validation.
	CustomValidation() error
}

func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{}

	// Apply the validator options
	for _, o := range opts {
		o(v)
	}

	return v
}

// Validate validates the given claims. It will also perform any custom validation if claims implements the CustomValidator interface.
func (v *Validator) Validate(claims Claims) error {
	var now time.Time
	vErr := new(ValidationError)

	// Check, if we have a time func
	if v.timeFunc != nil {
		now = v.timeFunc()
	} else {
		now = time.Now()
	}

	if !v.VerifyExpiresAt(claims, now, false) {
		exp := claims.GetExpirationTime()
		delta := now.Sub(exp.Time)
		vErr.Inner = fmt.Errorf("%s by %s", ErrTokenExpired, delta)
		vErr.Errors |= ValidationErrorExpired
	}

	// Check iat if the option is enabled
	if v.verifyIat && !v.VerifyIssuedAt(claims, now, false) {
		vErr.Inner = ErrTokenUsedBeforeIssued
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !v.VerifyNotBefore(claims, now, false) {
		vErr.Inner = ErrTokenNotValidYet
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if v.expectedAud != "" && !v.VerifyAudience(claims, v.expectedAud, false) {
		vErr.Inner = ErrTokenNotValidYet
		vErr.Errors |= ValidationErrorNotValidYet
	}

	// Finally, we want to give the claim itself some possibility to do some
	// additional custom validation based on their custom claims
	cvt, ok := claims.(CustomClaims)
	if ok {
		if err := cvt.CustomValidation(); err != nil {
			vErr.Inner = err
			vErr.Errors |= ValidationErrorClaimsInvalid
		}
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (v *Validator) VerifyAudience(claims Claims, cmp string, req bool) bool {
	return verifyAud(claims.GetAudience(), cmp, req)
}

// VerifyExpiresAt compares the exp claim against cmp (cmp < exp).
// If req is false, it will return true, if exp is unset.
func (v *Validator) VerifyExpiresAt(claims Claims, cmp time.Time, req bool) bool {
	exp := claims.GetExpirationTime()
	if exp == nil {
		return verifyExp(nil, cmp, req, v.leeway)
	}

	return verifyExp(&exp.Time, cmp, req, v.leeway)
}

// VerifyIssuedAt compares the iat claim against cmp (cmp >= iat).
// If req is false, it will return true, if iat is unset.
func (v *Validator) VerifyIssuedAt(claims Claims, cmp time.Time, req bool) bool {
	iat := claims.GetIssuedAt()
	if iat == nil {
		return verifyIat(nil, cmp, req, v.leeway)
	}

	return verifyIat(&iat.Time, cmp, req, v.leeway)
}

// VerifyNotBefore compares the nbf claim against cmp (cmp >= nbf).
// If req is false, it will return true, if nbf is unset.
func (v *Validator) VerifyNotBefore(claims Claims, cmp time.Time, req bool) bool {
	nbf := claims.GetNotBefore()
	if nbf == nil {
		return verifyNbf(nil, cmp, req, v.leeway)
	}

	return verifyNbf(&nbf.Time, cmp, req, v.leeway)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (v *Validator) VerifyIssuer(claims Claims, cmp string, req bool) bool {
	return verifyIss(claims.GetIssuer(), cmp, req)
}

// ----- helpers

func verifyAud(aud []string, cmp string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}
	// use a var here to keep constant time compare when looping over a number of claims
	result := false

	var stringClaims string
	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(cmp)) != 0 {
			result = true
		}
		stringClaims = stringClaims + a
	}

	// case where "" is sent in one or many aud claims
	if stringClaims == "" {
		return !required
	}

	return result
}

func verifyExp(exp *time.Time, now time.Time, required bool, skew time.Duration) bool {
	if exp == nil {
		return !required
	}

	return now.Before((*exp).Add(+skew))
}

func verifyIat(iat *time.Time, now time.Time, required bool, skew time.Duration) bool {
	if iat == nil {
		return !required
	}

	t := iat.Add(-skew)
	return !now.Before(t)
}

func verifyNbf(nbf *time.Time, now time.Time, required bool, skew time.Duration) bool {
	if nbf == nil {
		return !required
	}

	t := nbf.Add(-skew)
	return !now.Before(t)
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}
