package jwt

import (
	"encoding/json"
)

// MapClaims is a claims type that uses the map[string]interface{} for JSON decoding.
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// GetExpirationTime implements the Claims interface.
func (m MapClaims) GetExpirationTime() *NumericDate {
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

// ParseNumericDate tries to parse a key in the map claims type as a number
// date. This will succeed, if the underlying type is either a [float64] or a
// [json.Number]. Otherwise, nil will be returned.
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

// ParseClaimsString tries to parse a key in the map claims type as a
// [ClaimsStrings] type, which can either be a string or an array of string.
func (m MapClaims) ParseClaimsString(key string) ClaimStrings {
	var cs []string
	switch v := m[key].(type) {
	case string:
		cs = append(cs, v)
	case []string:
		cs = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return nil
			}
			cs = append(cs, vs)
		}
	}

	return cs
}

// ParseString tries to parse a key in the map claims type as a
// [string] type. Otherwise, an empty string is returned.
func (m MapClaims) ParseString(key string) string {
	iss, _ := m[key].(string)

	return iss
}
