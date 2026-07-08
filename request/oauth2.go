package request

import (
	"strings"
)

// Strips 'Bearer ' prefix from bearer token string
func stripBearerPrefixFromTokenString(tok string) (string, error) {
	// Should be a bearer token
	if len(tok) > 6 && strings.EqualFold(tok[:7], "bearer ") {
		return tok[7:], nil
	}
	return tok, nil
}

// AuthorizationHeaderExtractor extracts a bearer token from Authorization header
// Uses PostExtractionFilter to strip "Bearer " prefix from header
var AuthorizationHeaderExtractor = &PostExtractionFilter{
	HeaderExtractor{"Authorization"},
	stripBearerPrefixFromTokenString,
}

// OAuth2Extractor is an Extractor for OAuth2 access tokens. It looks for a
// "Bearer" token in the 'Authorization' header, then for an 'access_token'
// argument. A non-Bearer Authorization header (e.g. Basic auth) is ignored so
// that it does not shadow a valid 'access_token' argument.
var OAuth2Extractor = &MultiExtractor{
	BearerExtractor{},
	ArgumentExtractor{"access_token"},
}
