package jwt_test

import (
	"errors"
	"fmt"
	"os"
	"time"

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
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSampleSecret)

	fmt.Println(tokenString, err)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.u1riaD1rW97opCoAuRCTy4w58Br-Zk-bh7vLiRIsrpU <nil>
}

// Example parsing and validating a token using the HMAC signing method
func ExampleParse_hmac() {
	// sample token string taken from the New example
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.u1riaD1rW97opCoAuRCTy4w58Br-Zk-bh7vLiRIsrpU"

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(err)
	}

	// Output: bar 1.4444784e+09
}

// Example creating a token using a custom claims type. The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of registered claims.
func ExampleNewWithClaims_customClaimsTypeHmac() {
	mySigningKey := []byte("AllYourBase")

	type SomeCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	// Create claims with multiple fields populated
	claims := SomeCustomClaims{
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
	claims = SomeCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			// Also fixed dates can be used for the NumericDate
			ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	fmt.Printf("%v %v", ss, err)

	//Output: foo: bar
	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiZXhwIjoxNTE2MjM5MDIyfQ.xVuY2FZ_MRXMIEgVQ7J-TFtaucVFRXUzHm9LmV41goM <nil>
}

// Example creating a token using a custom claims type.  The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleParseWithClaims_customClaimsTypeHmac() {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiYXVkIjoic2luZ2xlIn0.QAWg1vGvnqRuCFTMcPkjZljXHh8U3L_qUjszOtQbeaA"

	type SomeCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &SomeCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})

	if claims, ok := token.Claims.(*SomeCustomClaims); ok && token.Valid {
		fmt.Printf("%v %v", claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		fmt.Println(err)
	}

	// Output: bar test
}

// Example creating a token using a custom claims type and validation options.  The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleParseWithClaims_validationOptionsHmac() {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiYXVkIjoic2luZ2xlIn0.QAWg1vGvnqRuCFTMcPkjZljXHh8U3L_qUjszOtQbeaA"

	type SomeCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &SomeCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	}, jwt.WithLeeway(5*time.Second))

	if claims, ok := token.Claims.(*SomeCustomClaims); ok && token.Valid {
		fmt.Printf("%v %v", claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		fmt.Println(err)
	}

	// Output: bar test
}

type SomeCustomClaims struct {
	Foo string `json:"foo"`
	jwt.RegisteredClaims
}

// Validate can be used to execute additional application-specific claims
// validation.
func (m SomeCustomClaims) Validate() error {
	if m.Foo != "bar" {
		return errors.New("must be foobar")
	}

	return nil
}

// Example creating a token using a custom claims type and validation options.
// The RegisteredClaims is embedded in the custom type to allow for easy
// encoding, parsing and validation of standard claims and the function
// CustomValidation is implemented.
func ExampleParseWithClaims_customValidationHmac() {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiYXVkIjoic2luZ2xlIn0.QAWg1vGvnqRuCFTMcPkjZljXHh8U3L_qUjszOtQbeaA"

	token, err := jwt.ParseWithClaims(tokenString, &SomeCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	}, jwt.WithLeeway(5*time.Second))

	if claims, ok := token.Claims.(*SomeCustomClaims); ok && token.Valid {
		fmt.Printf("%v %v", claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		fmt.Println(err)
	}

	// Output: bar test
}
