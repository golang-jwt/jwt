package jwt_test

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// OpenIdConnectEMail represents the "email" claim as defined in
	// OpenID Connect Core 1.0, section 5.1.
	//
	// Reference: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	OpenIdConnectEMail jwt.ClaimsType = "email"
)

// ExampleMapClaims shows how to create a token with custom claims using
// [jwt.MapClaims] and the custom [jwt.ClaimsType].
func ExampleMapClaims() {
	claims := jwt.MapClaims{
		"custom_claim":     "custom_value",
		OpenIdConnectEMail: "me@example.com",
		jwt.Sub:            "me",
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := t.SignedString([]byte("secret"))
	if err != nil {
		panic(err)
	}

	fmt.Println(s)

	// Output:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b21fY2xhaW0iOiJjdXN0b21fdmFsdWUiLCJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwic3ViIjoibWUifQ.ylWqOBiOzsJpcJQarXmPtvgGMP9d72Zc2GtEdriqXko
}
