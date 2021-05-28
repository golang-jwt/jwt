package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// For a type to be a Claims object, it must just have a Valid method that determines
// if the token is invalid for any supported reason
type Claims interface {
	Valid() error
}

// RFC7519Claims are a structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1.
//
// See examples for how to use this with your own claim types
type RFC7519Claims struct {
	Audience  []string     `json:"aud,omitempty"`
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	Id        string       `json:"jti,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	Issuer    string       `json:"iss,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	Subject   string       `json:"sub,omitempty"`
}

// Valid validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c RFC7519Claims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now, false) {
		delta := now.Sub(c.ExpiresAt.Time)
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}

	/*if !c.VerifyIssuedAt(now, false) {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}*/

	return vErr
}

// VerifyExpiresAt compares the exp claim against cmp. If required is false, this method
// will return true if the value matches or is unset
func (c *RFC7519Claims) VerifyExpiresAt(cmp time.Time, req bool) bool {
	if c.ExpiresAt == nil {
		verifyExp(nil, cmp, req)
	}

	return verifyExp(&c.ExpiresAt.Time, cmp, req)
}

// VerifyIssuedAt compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *RFC7519Claims) VerifyIssuedAt(cmp time.Time, req bool) bool {
	if c.IssuedAt == nil {
		return verifyIat(nil, cmp, req)
	}

	return verifyIat(&c.IssuedAt.Time, cmp, req)
}

// StandardClaims are a structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1. They do not follow the
// specification exactly, since they were based on an earlier draft of the
// specification and not updated. The main difference is that they only
// support integer-based date fields and singular audiances.
//
// See examples for how to use this with your own claim types
//
// Deprecated: Use RFC7519Claims instead.
type StandardClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c StandardClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now, false) {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now, false) {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	if c.ExpiresAt == 0 {
		return verifyExp(nil, time.Unix(cmp, 0), req)
	}

	t := time.Unix(c.ExpiresAt, 0)
	return verifyExp(&t, time.Unix(cmp, 0), req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	if c.IssuedAt == 0 {
		return verifyIat(nil, time.Unix(cmp, 0), req)
	}

	t := time.Unix(c.IssuedAt, 0)
	return verifyIat(&t, time.Unix(cmp, 0), req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyNotBefore(cmp int64, req bool) bool {
	if c.NotBefore == 0 {
		return verifyNbf(nil, time.Unix(cmp, 0), req)
	}

	t := time.Unix(c.NotBefore, 0)
	return verifyNbf(&t, time.Unix(cmp, 0), req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// ----- helpers

func verifyAud(aud string, cmp string, required bool) bool {
	if aud == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyExp(exp *time.Time, now time.Time, required bool) bool {
	if exp == nil {
		return !required
	}
	return now.Before(*exp) || now.Equal(*exp)
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
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}
