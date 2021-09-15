package main

import (
	"log"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/keyfunc"
)

func main() {

	// Declare the custom signing method's key and key ID.
	key := []byte("example secret")
	const exampleKID = "exampleKeyID"

	// Create and sign the token using the HMAC key.
	unsignedToken := jwt.New(jwt.SigningMethodHS512)
	unsignedToken.Header["kid"] = exampleKID
	jwtB64, err := unsignedToken.SignedString(key)
	if err != nil {
		log.Fatalf("Failed to self sign an HMAC token.\nError: %s.", err.Error())
	}

	// Create the JWKs from the HMAC key.
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		exampleKID: keyfunc.NewGivenHMAC(key),
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
