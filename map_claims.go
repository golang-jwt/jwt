package jwt

import (
	"encoding/json"
	"fmt"
)

// MapClaimsKey is a type alias for claim keys in the [MapClaims] type.
type MapClaimsKey string

var (
	// Exp is the "exp" claim key according to RFC 7519 section 4.1.4.
	Exp MapClaimsKey = "exp"

	// Nbf is the "nbf" claim key according to RFC 7519 section 4.1.5.
	Nbf MapClaimsKey = "nbf"

	// Iat is the "iat" claim key according to RFC 7519 section 4.1.6.
	Iat MapClaimsKey = "iat"

	// Aud is the "aud" claim key according to RFC 7519 section 4.1.3.
	Aud MapClaimsKey = "aud"

	// Iss is the "iss" claim key according to RFC 7519 section 4.1.1.
	Iss MapClaimsKey = "iss"

	// Sub is the "sub" claim key according to RFC 7519 section 4.1.2.
	Sub MapClaimsKey = "sub"
)

// MapClaims is a claims type that uses of map of [MapClaimsKey] with value [any]
// for JSON decoding. This is the default claims type if you do not supply one.
type MapClaims map[MapClaimsKey]any

// GetExpirationTime implements the Claims interface.
func (m MapClaims) GetExpirationTime() (*NumericDate, error) {
	return m.parseNumericDate(Exp)
}

// GetNotBefore implements the Claims interface.
func (m MapClaims) GetNotBefore() (*NumericDate, error) {
	return m.parseNumericDate(Nbf)
}

// GetIssuedAt implements the Claims interface.
func (m MapClaims) GetIssuedAt() (*NumericDate, error) {
	return m.parseNumericDate(Iat)
}

// GetAudience implements the Claims interface.
func (m MapClaims) GetAudience() (ClaimStrings, error) {
	return m.parseClaimsString(Aud)
}

// GetIssuer implements the Claims interface.
func (m MapClaims) GetIssuer() (string, error) {
	return m.parseString(Iss)
}

// GetSubject implements the Claims interface.
func (m MapClaims) GetSubject() (string, error) {
	return m.parseString(Sub)
}

// parseNumericDate tries to parse a key in the map claims type as a number
// date. This will succeed, if the underlying type is either a [float64] or a
// [json.Number]. Otherwise, nil will be returned.
func (m MapClaims) parseNumericDate(key MapClaimsKey) (*NumericDate, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}

	switch exp := v.(type) {
	case float64:
		if exp == 0 {
			return nil, nil
		}

		return newNumericDateFromSeconds(exp), nil
	case json.Number:
		v, _ := exp.Float64()

		return newNumericDateFromSeconds(v), nil
	}

	return nil, newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
}

// parseClaimsString tries to parse a key in the map claims type as a
// [ClaimsStrings] type, which can either be a string or an array of string.
func (m MapClaims) parseClaimsString(key MapClaimsKey) (ClaimStrings, error) {
	var cs []string
	switch v := m[key].(type) {
	case string:
		cs = append(cs, v)
	case []string:
		cs = v
	case []any:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return nil, newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
			}
			cs = append(cs, vs)
		}
	}

	return cs, nil
}

// parseString tries to parse a key in the map claims type as a [string] type.
// If the key does not exist, an empty string is returned. If the key has the
// wrong type, an error is returned.
func (m MapClaims) parseString(key MapClaimsKey) (string, error) {
	var (
		ok  bool
		raw any
		iss string
	)
	raw, ok = m[key]
	if !ok {
		return "", nil
	}

	iss, ok = raw.(string)
	if !ok {
		return "", newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
	}

	return iss, nil
}
