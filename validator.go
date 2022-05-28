package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

type Validator struct {
	leeway time.Duration
}

type ClaimsV2 interface {
	GetExpiryAt() *NumericDate
	GetIssuedAt() *NumericDate
	GetNotBefore() *NumericDate
	GetIssuer() string
	GetAudience() ClaimStrings
}

func (v *Validator) Validate(claims ClaimsV2) error {
	vErr := new(ValidationError)
	now := TimeFunc()

	if !v.VerifyExpiresAt(claims, now, false) {
		exp := claims.GetExpiryAt()
		delta := now.Sub(exp.Time)
		vErr.Inner = fmt.Errorf("%s by %s", ErrTokenExpired, delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if !v.VerifyIssuedAt(claims, now, false) {
		vErr.Inner = ErrTokenUsedBeforeIssued
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !v.VerifyNotBefore(claims, now, false) {
		vErr.Inner = ErrTokenNotValidYet
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (v *Validator) VerifyAudience(claims ClaimsV2, cmp string, req bool) bool {
	return verifyAud(claims.GetAudience(), cmp, req)
}

// VerifyExpiresAt compares the exp claim against cmp (cmp < exp).
// If req is false, it will return true, if exp is unset.
func (v *Validator) VerifyExpiresAt(claims ClaimsV2, cmp time.Time, req bool) bool {
	exp := claims.GetExpiryAt()
	if exp == nil {
		return verifyExp(nil, cmp, req, v.leeway)
	}

	return verifyExp(&exp.Time, cmp, req, v.leeway)
}

// VerifyIssuedAt compares the iat claim against cmp (cmp >= iat).
// If req is false, it will return true, if iat is unset.
func (v *Validator) VerifyIssuedAt(claims ClaimsV2, cmp time.Time, req bool) bool {
	iat := claims.GetIssuedAt()
	if iat == nil {
		return verifyIat(nil, cmp, req, v.leeway)
	}

	return verifyIat(&iat.Time, cmp, req, v.leeway)
}

// VerifyNotBefore compares the nbf claim against cmp (cmp >= nbf).
// If req is false, it will return true, if nbf is unset.
func (v *Validator) VerifyNotBefore(claims ClaimsV2, cmp time.Time, req bool) bool {
	nbf := claims.GetNotBefore()
	if nbf == nil {
		return verifyNbf(nil, cmp, req, v.leeway)
	}

	return verifyNbf(&nbf.Time, cmp, req, v.leeway)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (v *Validator) VerifyIssuer(claims ClaimsV2, cmp string, req bool) bool {
	return verifyIss(claims.GetIssuer(), cmp, req)
}

func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{}

	for _, o := range opts {
		o(v)
	}

	return v
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
	if len(stringClaims) == 0 {
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

	t := (*iat).Add(-skew)
	return now.After(t) || now.Equal(t)
}

func verifyNbf(nbf *time.Time, now time.Time, required bool, skew time.Duration) bool {
	if nbf == nil {
		return !required
	}

	t := (*nbf).Add(-skew)
	return now.After(t) || now.Equal(t)
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
