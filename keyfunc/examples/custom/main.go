package main

import (
	"log"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
	"github.com/MicahParks/keyfunc/examples/custom/method"
)

func main() {

	// Declare the custom signing method's key and key ID.
	const key = ""
	const exampleKID = "exampleKeyID"

	// Register the custom signing method.
	jwt.RegisterSigningMethod(method.CustomAlg, func() jwt.SigningMethod {
		return method.EmptyCustom{}
	})

	// Create and sign the token using the custom signing method.
	unsignedToken := jwt.New(method.EmptyCustom{})
	unsignedToken.Header["kid"] = exampleKID
	jwtB64, err := unsignedToken.SignedString(key)
	if err != nil {
		log.Fatalf("Failed to self sign a custom token.\nError: %s.", err.Error())
	}

	// Create the JWKs from the given signing method's key.
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		exampleKID: keyfunc.NewGivenCustom(key),
	})

	// Parse the token.
	var token *jwt.Token
	if token, err = jwt.Parse(jwtB64, jwks.Keyfunc); err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	// Check if the token is valid.
	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}
	log.Println("The token is valid.")
}
