package jwt

import (
	"crypto/subtle"
	"errors"
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

// newValidator can be used to create a stand-alone validator with the supplied
// options. This validator can then be used to validate already parsed claims.
func newValidator(opts ...ParserOption) *validator {
	p := NewParser(opts...)
	return p.validator
}

// Validate validates the given claims. It will also perform any custom
// validation if claims implements the CustomValidator interface.
func (v *validator) Validate(claims Claims) error {
	var (
		now  time.Time
		errs []error = make([]error, 0)
	)

	// Check, if we have a time func
	if v.timeFunc != nil {
		now = v.timeFunc()
	} else {
		now = time.Now()
	}

	// We always need to check the expiration time, but usage of the claim
	// itself is OPTIONAL
	if !v.VerifyExpiresAt(claims, now, false) {
		errs = append(errs, ErrTokenExpired)
	}

	// We always need to check not-before, but usage of the claim itself is
	// OPTIONAL
	if !v.VerifyNotBefore(claims, now, false) {
		errs = append(errs, ErrTokenNotValidYet)
	}

	// Check issued-at if the option is enabled
	if v.verifyIat && !v.VerifyIssuedAt(claims, now, false) {
		errs = append(errs, ErrTokenUsedBeforeIssued)
	}

	// If we have an expected audience, we also require the audience claim
	if v.expectedAud != "" && !v.VerifyAudience(claims, v.expectedAud, true) {
		errs = append(errs, ErrTokenInvalidAudience)
	}

	// If we have an expected issuer, we also require the issuer claim
	if v.expectedIss != "" && !v.VerifyIssuer(claims, v.expectedIss, true) {
		errs = append(errs, ErrTokenInvalidIssuer)
	}

	// If we have an expected subject, we also require the subject claim
	if v.expectedSub != "" && !v.VerifySubject(claims, v.expectedSub, true) {
		errs = append(errs, ErrTokenInvalidSubject)
	}

	// Finally, we want to give the claim itself some possibility to do some
	// additional custom validation based on a custom Validate function.
	cvt, ok := claims.(interface {
		Validate() error
	})
	if ok {
		if err := cvt.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.Join(errs...)
}

// VerifyExpiresAt compares the exp claim in claims against cmp. This function
// will return true if cmp < exp. Additional leeway is taken into account.
//
// If exp is not set, it will return true if the claim is not required,
// otherwise false will be returned.
//
// Additionally, if any error occurs while retrieving the claim, e.g., when its
// the wrong type, false will be returned.
func (v *validator) VerifyExpiresAt(claims Claims, cmp time.Time, required bool) bool {
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return false
	}

	if exp != nil {
		return cmp.Before((exp.Time).Add(+v.leeway))
	} else {
		return !required
	}
}

// VerifyIssuedAt compares the iat claim in claims against cmp. This function
// will return true if cmp >= iat. Additional leeway is taken into account.
//
// If iat is not set, it will return true if the claim is not required,
// otherwise false will be returned.
//
// Additionally, if any error occurs while retrieving the claim, e.g., when its
// the wrong type, false will be returned.
func (v *validator) VerifyIssuedAt(claims Claims, cmp time.Time, required bool) bool {
	iat, err := claims.GetIssuedAt()
	if err != nil {
		return false
	}

	if iat != nil {
		return !cmp.Before(iat.Add(-v.leeway))
	} else {
		return !required
	}
}

// VerifyNotBefore compares the nbf claim in claims against cmp. This function
// will return true if cmp >= nbf. Additional leeway is taken into account.
//
// If nbf is not set, it will return true if the claim is not required,
// otherwise false will be returned.
//
// Additionally, if any error occurs while retrieving the claim, e.g., when its
// the wrong type, false will be returned.
func (v *validator) VerifyNotBefore(claims Claims, cmp time.Time, required bool) bool {
	nbf, err := claims.GetNotBefore()
	if err != nil {
		return false
	}

	if nbf != nil {
		return !cmp.Before(nbf.Add(-v.leeway))
	} else {
		return !required
	}
}

// VerifyAudience compares the aud claim against cmp.
//
// If aud is not set or an empty list, it will return true if the claim is not
// required, otherwise false will be returned.
//
// Additionally, if any error occurs while retrieving the claim, e.g., when its
// the wrong type, false will be returned.
func (v *validator) VerifyAudience(claims Claims, cmp string, required bool) bool {
	aud, err := claims.GetAudience()
	if err != nil {
		return false
	}

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

// VerifyIssuer compares the iss claim in claims against cmp.
//
// If iss is not set, it will return true if the claim is not required,
// otherwise false will be returned.
//
// Additionally, if any error occurs while retrieving the claim, e.g., when its
// the wrong type, false will be returned.
func (v *validator) VerifyIssuer(claims Claims, cmp string, required bool) bool {
	iss, err := claims.GetIssuer()
	if err != nil {
		return false
	}

	if iss == "" {
		return !required
	}

	return iss == cmp
}

// VerifySubject compares the sub claim against cmp.
//
// If sub is not set, it will return true if the claim is not required,
// otherwise false will be returned.
//
// Additionally, if any error occurs while retrieving the claim, e.g., when its
// the wrong type, false will be returned.
func (v *validator) VerifySubject(claims Claims, cmp string, required bool) bool {
	sub, err := claims.GetSubject()
	if err != nil {
		return false
	}

	if sub == "" {
		return !required
	}

	return sub == cmp
}
