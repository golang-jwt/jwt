package jwt_test

import (
	"fmt"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// For HMAC signing method, the key can be any []byte. It is recommended to generate
// a key using crypto/rand or something equivalent. You need the same key for signing
// and validating.
var hmacSampleSecret []byte

func init() {
	// Load sample key data
	if keyData, e := os.ReadFile("test/hmacTestKey"); e == nil {
		hmacSampleSecret = keyData
	} else {
		panic(e)
	}
}

// Example creating, signing, and encoding a JWT token using the HMAC signing method
func ExampleNew_hmac() {
	// Create a new token object, specifying signing method
	token := jwt.New(jwt.SigningMethodHS256)

	// Optionally, add claims to the token object
	token.Claims = jwt.MapClaims{"aud": "someone"}

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSampleSecret)

	fmt.Println(tokenString, err)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzb21lb25lIn0.F0J37fS_ENgyQg9nxIE0fMS-DX3A11SMh4bvZ7MzD4M <nil>
}

// Example parsing and validating a token using the HMAC signing method
func ExampleParse_hmac() {
	// sample token string taken from the New example
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.u1riaD1rW97opCoAuRCTy4w58Br-Zk-bh7vLiRIsrpU"

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		log.Fatal(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(err)
	}

	// Output: bar 1.4444784e+09
}
