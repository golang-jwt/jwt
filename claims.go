package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// Claims must just have a Valid method that determines
// if the token is invalid for any supported reason
type Claims interface {
	Valid() error
}

// RegisteredClaims are a structured version of the JWT Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the JWT will not be parsed. The typical usecase
// therefore is to embedded this in a user-defined claim type.
//
// See examples for how to use this with your own claim types.
type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience ClaimStrings `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}

// Valid validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c RegisteredClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now, false) {
		delta := now.Sub(c.ExpiresAt.Time)
		vErr.Inner = fmt.Errorf("%s by %s", ErrTokenExpired, delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now, false) {
		vErr.Inner = ErrTokenUsedBeforeIssued
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
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
func (c *RegisteredClaims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// VerifyExpiresAt compares the exp claim against cmp (cmp < exp).
// If req is false, it will return true, if exp is unset.
func (c *RegisteredClaims) VerifyExpiresAt(cmp time.Time, req bool) bool {
	if c.ExpiresAt == nil {
		return verifyExp(nil, cmp, req)
	}

	return verifyExp(&c.ExpiresAt.Time, cmp, req)
}

// VerifyIssuedAt compares the iat claim against cmp (cmp >= iat).
// If req is false, it will return true, if iat is unset.
func (c *RegisteredClaims) VerifyIssuedAt(cmp time.Time, req bool) bool {
	if c.IssuedAt == nil {
		return verifyIat(nil, cmp, req)
	}

	return verifyIat(&c.IssuedAt.Time, cmp, req)
}

// VerifyNotBefore compares the nbf claim against cmp (cmp >= nbf).
// If req is false, it will return true, if nbf is unset.
func (c *RegisteredClaims) VerifyNotBefore(cmp time.Time, req bool) bool {
	if c.NotBefore == nil {
		return verifyNbf(nil, cmp, req)
	}

	return verifyNbf(&c.NotBefore.Time, cmp, req)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *RegisteredClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
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

func verifyExp(exp *time.Time, now time.Time, required bool) bool {
	if exp == nil {
		return !required
	}
	return now.Before(*exp)
}

func verifyIat(iat *time.Time, now time.Time, required bool) bool {
	if iat == nil {
		return !required
	}
	return now.After(*iat) || now.Equal(*iat)
}

func verifyNbf(nbf *time.Time, now time.Time, required bool) bool {
	if nbf == nil {
		return !required
	}
	return now.After(*nbf) || now.Equal(*nbf)
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	return subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0
}
