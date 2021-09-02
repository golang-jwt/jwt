package jwt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
)

// MapClaims is a claims type that uses the map[string]interface{} for JSON decoding.
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

func (m MapClaims) ExpiresAt() *time.Time {
	exp := m["exp"]
	switch exp := exp.(type) {
	case float64:
		if exp == 0 {
			return nil
		}
		return &newNumericDateFromSeconds(exp).Time
	case json.Number:
		v, _ := exp.Float64()
		if v == 0 {
			return nil
		}
		return &newNumericDateFromSeconds(v).Time
	default:
		return nil
	}
}

func (m MapClaims) IssuedAt() *time.Time {
	iat := m["iat"]
	switch exp := iat.(type) {
	case float64:
		if exp == 0 {
			return nil
		}
		return &newNumericDateFromSeconds(exp).Time
	case json.Number:
		v, _ := exp.Float64()
		if v == 0 {
			return nil
		}
		return &newNumericDateFromSeconds(v).Time
	default:
		return nil
	}
}

// NotBefore returns the *time.Time parsed nbf field of the MapClaims if present
// or nil otherwise
func (m MapClaims) NotBefore() *time.Time {
	v := m["nbf"]
	switch nbf := v.(type) {
	case float64:
		if nbf == 0 {
			return nil
		}
		return &newNumericDateFromSeconds(nbf).Time
	case json.Number:
		v, _ := nbf.Float64()
		if v == 0 {
			return nil
		}
		return &newNumericDateFromSeconds(v).Time
	default:
		return nil
	}
}

// Issuer returns the iss field of the MapClaims
func (m MapClaims) Issuer() string {
	iss := m["iss"]
	if str, ok := iss.(string); ok {
		return str
	}
	return ""
}

func (m MapClaims) Audience() ([]string, error) {
	var err *multierror.Error
	var aud []string
	switch v := m["aud"].(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = v
	case []interface{}:
		for _, a := range v {
			if vs, ok := a.(string); ok {
				aud = append(aud, vs)
			} else {
				multierror.Append(err, fmt.Errorf("aud entry [%v] is not a string", a))
			}
		}
	}
	return aud, err.ErrorOrNil()
}

// VerifyAudience Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud, err := m.Audience()
	if err != nil {
		return false
	}
	return verifyAud(aud, cmp, req)
}

// VerifyExpiresAt compares the exp claim against cmp (cmp <= exp).
// If req is false, it will return true, if exp is unset.
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	cmpTime := time.Unix(cmp, 0)
	return verifyExp(m.ExpiresAt(), cmpTime, req)
}

// VerifyIssuedAt compares the exp claim against cmp (cmp >= iat).
// If req is false, it will return true, if iat is unset.
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	cmpTime := time.Unix(cmp, 0)

	v, ok := m["iat"]
	if !ok {
		return !req
	}

	switch iat := v.(type) {
	case float64:
		if iat == 0 {
			return verifyIat(nil, cmpTime, req)
		}
		return verifyIat(&newNumericDateFromSeconds(iat).Time, cmpTime, req)
	case json.Number:
		v, _ := iat.Float64()
		return verifyIat(&newNumericDateFromSeconds(v).Time, cmpTime, req)
	}

	return false
}

// VerifyNotBefore compares the nbf claim against cmp (cmp >= nbf).
// If req is false, it will return true, if nbf is unset.
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	return verifyNbf(m.NotBefore(), time.Unix(cmp, 0), req)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(m.Issuer(), cmp, req)
}

// Valid validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid() error {
	var result *multierror.Error
	now := TimeFunc()
	nowUnix := now.Unix()
	if !m.VerifyExpiresAt(nowUnix, false) {
		result = multierror.Append(result, &ExpiredError{
			ExpiredAt:   *m.ExpiresAt(),
			AttemptedAt: now,
		})
	}
	if !m.VerifyIssuedAt(nowUnix, false) {
		result = multierror.Append(result, &UsedBeforeIssuedError{
			IssuedAt:    *m.IssuedAt(),
			AttemptedAt: now,
		})
	}
	if !m.VerifyNotBefore(nowUnix, false) {
		result = multierror.Append(result, &NotYetValidError{
			ValidAt:     *m.NotBefore(),
			AttemptedAt: now,
		})
	}
	return result.ErrorOrNil()

}
