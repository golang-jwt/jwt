package jwt

import (
	"crypto/subtle"
	"time"
)

// validator is the core of the new Validation API. It is automatically used by
// a [Parser] during parsing and can be modified with various parser options.
//
// Note: This struct is intentionally not exported (yet) as we want to
// internally finalize its API. In the future, we might make it publicly available.
type validator struct {
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

	// expectedAud contains the audience this token expects. Supplying an empty
	// string will disable aud checking.
	expectedAud string

	// expectedIss contains the issuer this token expects. Supplying an empty
	// string will disable iss checking.
	expectedIss string

	// expectedSub contains the subject this token expects. Supplying an empty
	// string will disable sub checking.
	expectedSub string
}

// CustomClaims represents a custom claims interface, which can be built upon the integrated
// claim types, such as map claims or registered claims.
type CustomClaims interface {
	// CustomValidation can be implemented by a user-specific claim to support
	// additional validation steps in addition to the regular validation.
	CustomValidation() error
}

// newValidator can be used to create a stand-alone validator with the supplied
// options. This validator can then be used to validate already parsed claims.
func newValidator(opts ...ParserOption) *validator {
	p := NewParser(opts...)
	return p.validator
}

// Validate validates the given claims. It will also perform any custom validation if claims implements the CustomValidator interface.
func (v *validator) Validate(claims Claims) error {
	var now time.Time
	vErr := new(ValidationError)

	// Check, if we have a time func
	if v.timeFunc != nil {
		now = v.timeFunc()
	} else {
		now = time.Now()
	}

	// We always need to check the expiration time, but the claim itself is OPTIONAL
	if !v.VerifyExpiresAt(claims, now, false) {
		vErr.Inner = ErrTokenExpired
		vErr.Errors |= ValidationErrorExpired
	}

	// We always need to check not-before, but the claim itself is OPTIONAL
	if !v.VerifyNotBefore(claims, now, false) {
		vErr.Inner = ErrTokenNotValidYet
		vErr.Errors |= ValidationErrorNotValidYet
	}

	// Check issued-at if the option is enabled
	if v.verifyIat && !v.VerifyIssuedAt(claims, now, false) {
		vErr.Inner = ErrTokenUsedBeforeIssued
		vErr.Errors |= ValidationErrorIssuedAt
	}

	// If we have an expected audience, we also require the audience claim
	if v.expectedAud != "" && !v.VerifyAudience(claims, v.expectedAud, true) {
		vErr.Inner = ErrTokenInvalidAudience
		vErr.Errors |= ValidationErrorAudience
	}

	// If we have an expected issuer, we also require the issuer claim
	if v.expectedIss != "" && !v.VerifyIssuer(claims, v.expectedIss, true) {
		vErr.Inner = ErrTokenInvalidIssuer
		vErr.Errors |= ValidationErrorIssuer
	}

	// If we have an expected subject, we also require the subject claim
	if v.expectedSub != "" && !v.VerifySubject(claims, v.expectedSub, true) {
		vErr.Inner = ErrTokenInvalidSubject
		vErr.Errors |= ValidationErrorSubject
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
func (v *validator) VerifyAudience(claims Claims, cmp string, req bool) bool {
	aud, err := claims.GetAudience()
	if err != nil {
		return false
	}

	return verifyAud(aud, cmp, req)
}

// VerifyExpiresAt compares the exp claim against cmp (cmp < exp).
// If req is false, it will return true, if exp is unset.
func (v *validator) VerifyExpiresAt(claims Claims, cmp time.Time, req bool) bool {
	var time *time.Time = nil

	exp, err := claims.GetExpirationTime()
	if err != nil {
		return false
	} else if exp != nil {
		time = &exp.Time
	}

	return verifyExp(time, cmp, req, v.leeway)
}

// VerifyIssuedAt compares the iat claim against cmp (cmp >= iat).
// If req is false, it will return true, if iat is unset.
func (v *validator) VerifyIssuedAt(claims Claims, cmp time.Time, req bool) bool {
	var time *time.Time = nil

	iat, err := claims.GetIssuedAt()
	if err != nil {
		return false
	} else if iat != nil {
		time = &iat.Time
	}

	return verifyIat(time, cmp, req, v.leeway)
}

// VerifyNotBefore compares the nbf claim against cmp (cmp >= nbf).
// If req is false, it will return true, if nbf is unset.
func (v *validator) VerifyNotBefore(claims Claims, cmp time.Time, req bool) bool {
	var time *time.Time = nil

	nbf, err := claims.GetNotBefore()
	if err != nil {
		return false
	} else if nbf != nil {
		time = &nbf.Time
	}

	return verifyNbf(time, cmp, req, v.leeway)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (v *validator) VerifyIssuer(claims Claims, cmp string, req bool) bool {
	iss, err := claims.GetIssuer()
	if err != nil {
		return false
	}

	return verifyIss(iss, cmp, req)
}

// VerifySubject compares the sub claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (v *validator) VerifySubject(claims Claims, cmp string, req bool) bool {
	iss, err := claims.GetSubject()
	if err != nil {
		return false
	}

	return verifySub(iss, cmp, req)
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

	return iss == cmp
}

func verifySub(sub string, cmp string, required bool) bool {
	if sub == "" {
		return !required
	}

	return sub == cmp
}
