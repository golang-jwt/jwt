package jwt

import (
	"encoding/json"
)

// MapClaims is a claims type that uses the map[string]interface{} for JSON decoding.
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// GetExpiryAt implements the Claims interface.
func (m MapClaims) GetExpiryAt() *NumericDate {
	return m.ParseNumericDate("exp")
}

// GetNotBefore implements the Claims interface.
func (m MapClaims) GetNotBefore() *NumericDate {
	return m.ParseNumericDate("nbf")
}

// GetIssuedAt implements the Claims interface.
func (m MapClaims) GetIssuedAt() *NumericDate {
	return m.ParseNumericDate("iat")
}

// GetAudience implements the Claims interface.
func (m MapClaims) GetAudience() ClaimStrings {
	return m.ParseClaimsString("aud")
}

// GetIssuer implements the Claims interface.
func (m MapClaims) GetIssuer() string {
	return m.ParseString("iss")
}

func (m MapClaims) ParseNumericDate(key string) *NumericDate {
	v, ok := m[key]
	if !ok {
		return nil
	}

	switch exp := v.(type) {
	case float64:
		if exp == 0 {
			return nil
		}

		return newNumericDateFromSeconds(exp)
	case json.Number:
		v, _ := exp.Float64()

		return newNumericDateFromSeconds(v)
	}

	return nil
}

func (m MapClaims) ParseClaimsString(key string) ClaimStrings {
	var aud []string
	switch v := m[key].(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return nil
			}
			aud = append(aud, vs)
		}
	}

	return nil
}

func (m MapClaims) ParseString(key string) string {
	iss, _ := m[key].(string)

	return iss
}
