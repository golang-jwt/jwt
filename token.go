package jwt

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
)

// Keyfunc will be used by the Parse methods as a callback function to supply
// the key for verification.  The function receives the parsed, but unverified
// Token.  This allows you to use properties in the Header of the token (such as
// `kid`) to identify which key to use.
//
// The returned any may be a single key or a VerificationKeySet containing
// multiple keys.
type Keyfunc func(*Token) (any, error)

// VerificationKey represents a public or secret key for verifying a token's signature.
type VerificationKey interface {
	crypto.PublicKey | []uint8
}

// VerificationKeySet is a set of public or secret keys. It is used by the parser to verify a token.
type VerificationKeySet struct {
	Keys []VerificationKey
}

// Registered JOSE header parameter names, for use as keys in [Token.Header]
// instead of string literals. See
// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1 and
// https://datatracker.ietf.org/doc/html/rfc7519#section-5.
const (
	// HeaderAlgorithm identifies the cryptographic algorithm used to secure the JWT.
	HeaderAlgorithm = "alg"
	// HeaderType declares the media type of the complete JWT, e.g. "JWT" or "at+jwt".
	HeaderType = "typ"
	// HeaderContentType declares the media type of the secured content (the payload), used for nested JWTs.
	HeaderContentType = "cty"
	// HeaderKeyID hints at which key was used to secure the JWT.
	HeaderKeyID = "kid"
	// HeaderCritical lists extensions that MUST be understood and processed.
	HeaderCritical = "crit"
)

// Token represents a JWT Token.  Different fields will be used depending on
// whether you're creating or parsing/verifying a token.
type Token struct {
	Raw       string         // Raw contains the raw token.  Populated when you [Parse] a token
	Method    SigningMethod  // Method is the signing method used or to be used
	Header    map[string]any // Header is the first segment of the token in decoded form. Use the Header* constants (e.g. [HeaderType]) as keys rather than string literals.
	Claims    Claims         // Claims is the second segment of the token in decoded form
	Signature []byte         // Signature is the third segment of the token in decoded form.  Populated when you [Parse] or sign a token
	Valid     bool           // Valid specifies if the token is valid.  Populated when you [Parse] a token
}

// New creates a new [Token] with the specified signing method and an empty map
// of claims. Additional options can be specified, but are currently unused.
func New(method SigningMethod, opts ...TokenOption) *Token {
	return NewWithClaims(method, MapClaims{}, opts...)
}

// NewWithClaims creates a new [Token] with the specified signing method and
// claims. Additional options can be specified, but are currently unused.
func NewWithClaims(method SigningMethod, claims Claims, opts ...TokenOption) *Token {
	return &Token{
		Header: map[string]any{
			HeaderType:      "JWT",
			HeaderAlgorithm: method.Alg(),
		},
		Claims: claims,
		Method: method,
	}
}

// SignedString creates and returns a complete, signed JWT. The token is signed
// using the SigningMethod specified in the token. Please refer to
// https://golang-jwt.github.io/jwt/usage/signing_methods/#signing-methods-and-key-types
// for an overview of the different signing methods and their respective key
// types.
func (t *Token) SignedString(key any) (string, error) {
	sstr, err := t.SigningString()
	if err != nil {
		return "", err
	}

	sig, err := t.Method.Sign(sstr, key)
	if err != nil {
		return "", err
	}

	t.Signature = sig

	return sstr + "." + t.EncodeSegment(sig), nil
}

// SigningString generates the signing string.  This is the most expensive part
// of the whole deal. Unless you need this for something special, just go
// straight for the SignedString.
func (t *Token) SigningString() (string, error) {
	h, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}

	c, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}

	return t.EncodeSegment(h) + "." + t.EncodeSegment(c), nil
}

// EncodeSegment encodes a JWT specific base64url encoding with padding
// stripped. In the future, this function might take into account a
// [TokenOption]. Therefore, this function exists as a method of [Token], rather
// than a global function.
func (*Token) EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}
