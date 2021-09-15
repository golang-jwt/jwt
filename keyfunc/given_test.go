package keyfunc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/golang-jwt/jwt/v4/keyfunc"
	"github.com/golang-jwt/jwt/v4/keyfunc/examples/custom/method"
)

const (

	// algAttribute is the JSON attribute for the JWT encryption algorithm.
	algAttribute = "alg"

	// kidAttribute is the JSON attribute for the Key ID.
	kidAttribute = "kid"

	// testKID is the testing KID.
	testKID = "testkid"
)

// TestNewGivenCustom tests that a custom jwt.SigningMethod can be used to create a JWKs and a proper jwt.Keyfunc.
func TestNewGivenCustom(t *testing.T) {

	// Register the signing method.
	jwt.RegisterSigningMethod(method.CustomAlg, func() jwt.SigningMethod {
		return method.EmptyCustom{}
	})

	// Create the map of given keys.
	givenKeys := make(map[string]keyfunc.GivenKey)
	key := addCustom(givenKeys, testKID)

	// Use the custom key to create a JWKs.
	jwks := keyfunc.NewGiven(givenKeys)

	// Create the JWT with the appropriate key ID.
	token := jwt.New(method.EmptyCustom{})
	token.Header[algAttribute] = method.CustomAlg
	token.Header[kidAttribute] = testKID

	// Sign, parse, and validate the JWT.
	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyECDSA tests that a generated ECDSA key can be added to the JWKs and create a proper jwt.Keyfunc.
func TestNewGivenKeyECDSA(t *testing.T) {

	// Create the map of given keys.
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addECDSA(givenKeys, testKID)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	// Use the RSA public key to create a JWKs.
	jwks := keyfunc.NewGiven(givenKeys)

	// Create the JWT with the appropriate key ID.
	token := jwt.New(jwt.SigningMethodES256)
	token.Header[kidAttribute] = testKID

	// Sign, parse, and validate the JWT.
	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyHMAC tests that a generated HMAC key can be added to a JWKs and create a proper jwt.Keyfunc.
func TestNewGivenKeyHMAC(t *testing.T) {

	// Create the map of given keys.
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addHMAC(givenKeys, testKID)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	// Use an HMAC secret to create a given JWKs.
	jwks := keyfunc.NewGiven(givenKeys)

	// Create a JWT with the appropriate key ID.
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header[kidAttribute] = testKID

	// Sign, parse, and validate the JWT.
	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyRSA tests that a generated RSA key can be added to the JWKs and create a proper jwt.Keyfunc.
func TestNewGivenKeyRSA(t *testing.T) {

	// Create the map of given keys.
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addRSA(givenKeys, testKID)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	// Use the RSA public key to create a JWKs.
	jwks := keyfunc.NewGiven(givenKeys)

	// Create the JWT with the appropriate key ID.
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header[kidAttribute] = testKID

	// Sign, parse, and validate the JWT.
	signParseValidate(t, token, key, jwks)
}

// addCustom adds a new key wto the given keys map. The new key is using a test jwt.SigningMethod.
func addCustom(givenKeys map[string]keyfunc.GivenKey, kid string) (key string) {
	key = ""
	givenKeys[kid] = keyfunc.NewGivenCustom(key)
	return key
}

// addECDSA adds a new ECDSA key to the given keys map.
func addECDSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key *ecdsa.PrivateKey, err error) {

	// Create the ECDSA key.
	if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	// Add the new ECDSA public key to the keys map.
	givenKeys[kid] = keyfunc.NewGivenECDSA(&key.PublicKey)

	return key, nil
}

// addHMAC creates a new HMAC secret stuff.
func addHMAC(givenKeys map[string]keyfunc.GivenKey, kid string) (secret []byte, err error) {

	// Create the HMAC secret.
	secret = make([]byte, sha256.BlockSize)
	if _, err = rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to create HMAC secret: %w", err)
	}

	// Add the new HMAC key to the keys map.
	givenKeys[kid] = keyfunc.NewGivenHMAC(secret)

	return secret, nil
}

// addRSA adds a new RSA key to the given keys map.
func addRSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key *rsa.PrivateKey, err error) {

	// Create the RSA key.
	if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, fmt.Errorf("failed to create RSA key: %w", err)
	}

	// Add the new RSA public key to the keys map.
	givenKeys[kid] = keyfunc.NewGivenRSA(&key.PublicKey)

	return key, nil
}

// signParseValidate signs the JWT, parses it using the given JWKs, then validates it.
func signParseValidate(t *testing.T, token *jwt.Token, key interface{}, jwks *keyfunc.JWKs) {

	// Sign the token.
	jwtB64, err := token.SignedString(key)
	if err != nil {
		t.Errorf("Failed to sign the JWT.\nError: %s", err.Error())
		t.FailNow()
	}

	// Parse the JWT using the JWKs.
	var parsed *jwt.Token
	if parsed, err = jwt.Parse(jwtB64, jwks.Keyfunc); err != nil {
		t.Errorf("Failed to parse the JWT.\nError: %s.", err.Error())
		t.FailNow()
	}

	// Confirm the JWT is valid.
	if !parsed.Valid {
		t.Errorf("The JWT was not valid.")
		t.FailNow()
	}
}
