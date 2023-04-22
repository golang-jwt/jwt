package jwt_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Example (atypical) using the RegisteredClaims type by itself to parse a token.
// The RegisteredClaims type is designed to be embedded into your custom types
// to provide standard validation features.  You can use it alone, but there's
// no way to retrieve other fields after parsing.
// See the CustomClaimsType example for intended usage.
func ExampleNewWithClaims_registeredClaims() {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// Create the Claims
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Unix(2516239022, 0)),
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	// Validate the token
	tk, err := jwt.ParseWithClaims(ss, claims, func(t *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil {
		panic(err)
	}

	issuer, err := tk.Claims.GetIssuer()
	fmt.Printf("%v %v", issuer, err)

	//Output: test <nil>
}

// Example creating a token using a custom claims type. The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of registered claims.
func ExampleNewWithClaims_customClaimsType() {
	_, privateKey, err := ed25519.GenerateKey(nil)

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	// Create claims with multiple fields populated
	claims := MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "test",
			Subject:   "somebody",
			ID:        "1",
			Audience:  []string{"somebody_else"},
		},
	}

	fmt.Printf("foo: %v\n", claims.Foo)

	// Create claims while leaving out some of the optional fields
	claims = MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			// Also fixed dates can be used for the NumericDate
			ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	ss, err := token.SignedString(privateKey)

	fmt.Println(len(ss), err)

	// Output: foo: bar
	// 182 <nil>
}

// Example creating a token using a custom claims type.  The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleParseWithClaims_customClaimsType() {
	tokenString := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiZXhwIjoyNTE2MjM5MDIyfQ.JutXls8z2IUxAtUgCV2Ec7WRVKrTYX5gCByB0mGLJw0qC9xah3YwH9E82U3QZAPQOOXAalhEFP92KYEWAyITDw"

	// Corresponding private key is a426d77a4edabfdef2830223c9e94e68c5ba1006d1d7ba2a8277ada9b3f93d5c9939cf856f57ee490076a5cc0104b7ae7d458be275cd1cc6fb91b509413e7f56
	publicKeyBytes, err := hex.DecodeString("9939cf856f57ee490076a5cc0104b7ae7d458be275cd1cc6fb91b509413e7f56")
	if err != nil {
		panic(err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		fmt.Printf("%v %v", claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		fmt.Println(err)
	}

	// Output: bar test
}

// Example creating a token using a custom claims type and validation options.  The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleParseWithClaims_validationOptions() {
	tokenString := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiZXhwIjoyNTE2MjM5MDIyfQ.JutXls8z2IUxAtUgCV2Ec7WRVKrTYX5gCByB0mGLJw0qC9xah3YwH9E82U3QZAPQOOXAalhEFP92KYEWAyITDw"

	// Corresponding private key is a426d77a4edabfdef2830223c9e94e68c5ba1006d1d7ba2a8277ada9b3f93d5c9939cf856f57ee490076a5cc0104b7ae7d458be275cd1cc6fb91b509413e7f56
	publicKeyBytes, err := hex.DecodeString("9939cf856f57ee490076a5cc0104b7ae7d458be275cd1cc6fb91b509413e7f56")
	if err != nil {
		panic(err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, jwt.WithLeeway(5*time.Second))

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		fmt.Printf("%v %v", claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		fmt.Println(err)
	}

	// Output: bar test
}

type MyCustomClaims struct {
	Foo string `json:"foo"`
	jwt.RegisteredClaims
}

// Validate can be used to execute additional application-specific claims
// validation.
func (m MyCustomClaims) Validate() error {
	if m.Foo != "bar" {
		return errors.New("must be foobar")
	}

	return nil
}

// Example creating a token using a custom claims type and validation options.
// The RegisteredClaims is embedded in the custom type to allow for easy
// encoding, parsing and validation of standard claims and the function
// CustomValidation is implemented.
func ExampleParseWithClaims_customValidation() {
	tokenString := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiZXhwIjoyNTE2MjM5MDIyfQ.JutXls8z2IUxAtUgCV2Ec7WRVKrTYX5gCByB0mGLJw0qC9xah3YwH9E82U3QZAPQOOXAalhEFP92KYEWAyITDw"

	// Corresponding private key is a426d77a4edabfdef2830223c9e94e68c5ba1006d1d7ba2a8277ada9b3f93d5c9939cf856f57ee490076a5cc0104b7ae7d458be275cd1cc6fb91b509413e7f56
	publicKeyBytes, err := hex.DecodeString("9939cf856f57ee490076a5cc0104b7ae7d458be275cd1cc6fb91b509413e7f56")
	if err != nil {
		panic(err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, jwt.WithLeeway(5*time.Second))

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		fmt.Printf("%v %v", claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		fmt.Println(err)
	}

	// Output: bar test
}

// An example of parsing the error types using errors.Is.
func ExampleParse_errorChecking() {
	// Token from another example.  This token is expired
	var tokenString = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiZXhwIjoxNTE2MjM5MDIyfQ.XAxYEk_6fWzMe256fXeT-eDR1vo_t4gqkq3eD4lqKHm8VrvhnOBtIrfXAJvMY6S1c5Lb1CIhPAaCe366xsYJDg"

	// Corresponding private key is 378446363ffa1eb526a61f4b250bd24bd60002d5d20e22fa9b20c786e7f5e2ea8fff42935411c4c9bd3772c4a96a710bf6f2ba5508a71fc6155bcd73eb952837
	publicKeyBytes, err := hex.DecodeString("8fff42935411c4c9bd3772c4a96a710bf6f2ba5508a71fc6155bcd73eb952837")
	if err != nil {
		panic(err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if token.Valid {
		fmt.Println("You look nice today")
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		fmt.Println("That's not even a token")
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		// Invalid signature
		fmt.Println("Invalid signature")
	} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
		// Token is either expired or not active yet
		fmt.Println("Timing is everything")
	} else {
		fmt.Println("Couldn't handle this token:", err)
	}

	// Output: Timing is everything
}
