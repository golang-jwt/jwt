package jwt

import (
	"encoding/json"
	"errors"
	"time"
	// "fmt"
)

// Claims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud, _ := m["aud"].(string)
	return verifyAud(aud, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	cmpTime := time.Unix(cmp, 0)

	switch exp := m["exp"].(type) {
	case float64:
		if exp == 0 {
			return verifyExp(nil, cmpTime, req)
		}

		t := timeFromFloat(exp)
		return verifyExp(&t, cmpTime, req)
	case json.Number:
		v, _ := exp.Float64()

		t := timeFromFloat(v)
		return verifyExp(&t, cmpTime, req)
	}

	return !req
}

// VerifyIssuedAt compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	cmpTime := time.Unix(cmp, 0)

	switch exp := m["iat"].(type) {
	case float64:
		if exp == 0 {
			return verifyIat(nil, cmpTime, req)
		}

		t := timeFromFloat(exp)
		return verifyIat(&t, cmpTime, req)
	case json.Number:
		v, _ := exp.Float64()

		t := timeFromFloat(v)
		return verifyIat(&t, cmpTime, req)
	}

	return !req
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss, _ := m["iss"].(string)
	return verifyIss(iss, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	cmpTime := time.Unix(cmp, 0)

	switch exp := m["nbf"].(type) {
	case float64:
		if exp == 0 {
			return verifyNbf(nil, cmpTime, req)
		}

		t := timeFromFloat(exp)
		return verifyNbf(&t, cmpTime, req)
	case json.Number:
		v, _ := exp.Float64()

		t := timeFromFloat(v)
		return verifyNbf(&t, cmpTime, req)
	}

	return !req
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	if !m.VerifyExpiresAt(now, false) {
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= ValidationErrorExpired
	}

	if !m.VerifyIssuedAt(now, false) {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !m.VerifyNotBefore(now, false) {
		vErr.Inner = errors.New("Token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}
