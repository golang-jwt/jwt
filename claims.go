package jwt

import (
	"crypto/subtle"
	"fmt"
	"math"
	"time"
)

// For a type to be a Claims object, it must just have a Valid method that determines
// if the token is invalid for any supported reason
type Claims interface {
	Valid() error
}

// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types
type StandardClaims struct {
	Audience  string  `json:"aud,omitempty"`
	ExpiresAt float64 `json:"exp,omitempty"`
	Id        string  `json:"jti,omitempty"`
	IssuedAt  float64 `json:"iat,omitempty"`
	Issuer    string  `json:"iss,omitempty"`
	NotBefore float64 `json:"nbf,omitempty"`
	Subject   string  `json:"sub,omitempty"`
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c StandardClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if c.VerifyExpiresAt(now, false) == false {
		delta := now.Sub(parseUnixFloat(c.ExpiresAt))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now, false) == false {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now, false) == false {
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
func (c *StandardClaims) VerifyExpiresAt(cmp time.Time, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuedAt(cmp time.Time, req bool) bool {
	return verifyIat(c.IssuedAt, cmp, req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *StandardClaims) VerifyNotBefore(cmp time.Time, req bool) bool {
	return verifyNbf(c.NotBefore, cmp, req)
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

func verifyExp(exp float64, now time.Time, required bool) bool {
	if exp == 0. {
		return !required
	}

	pexp := parseUnixFloat(exp)

	return pexp.Equal(now) || now.Before(pexp)
}

func verifyIat(iat float64, now time.Time, required bool) bool {
	if iat == 0. {
		return !required
	}

	piat := parseUnixFloat(iat)

	return piat.Equal(now) || now.After(piat)
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}

	return subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0
}

func verifyNbf(nbf float64, now time.Time, required bool) bool {
	if nbf == 0. {
		return !required
	}

	pnbf := parseUnixFloat(nbf)

	return pnbf.Equal(now) || now.After(pnbf)
}

func parseUnixFloat(ts float64) time.Time {
	int, frac := math.Modf(ts)
	return time.Unix(int64(int), int64(frac*(1e9)))
}
