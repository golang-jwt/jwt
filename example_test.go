package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Example creating a token by passing jwt.WithJSONEncoder or jwt.WithBase64Encoder to
// options to specify the custom encoders when sign the token to string.
// You can try other encoders when you get tired of the standard library.
func ExampleNew_customEncoder() {
	mySigningKey := []byte("AllYourBase")

	customJSONEncoderFunc := json.Marshal
	customBase64Encoder := base64.RawURLEncoding
	token := jwt.New(jwt.SigningMethodHS256, jwt.WithJSONEncoder(customJSONEncoderFunc), jwt.WithBase64Encoder(customBase64Encoder))

	ss, err := token.SignedString(mySigningKey)
	fmt.Println(ss, err)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.E9f4bo8SFbMyEfLEOEXEO2RGcO9cQhznYfSKqTjWwrM <nil>
}

// Example (atypical) using the RegisteredClaims type by itself to parse a token.
// The RegisteredClaims type is designed to be embedded into your custom types
// to provide standard validation features.  You can use it alone, but there's
// no way to retrieve other fields after parsing.
// See the CustomClaimsType example for intended usage.
func ExampleNewWithClaims_registeredClaims() {
	mySigningKey := []byte("AllYourBase")

	// Create the Claims
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	fmt.Println(ss, err)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNTE2MjM5MDIyfQ.0XN_1Tpp9FszFOonIBpwha0c_SfnNI22DhTnjMshPg8 <nil>
}

// Example creating a token using a custom claims type. The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of registered claims.
func ExampleNewWithClaims_customClaimsType() {
	mySigningKey := []byte("AllYourBase")

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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	fmt.Println(ss, err)

	// Output: foo: bar
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiZXhwIjoxNTE2MjM5MDIyfQ.xVuY2FZ_MRXMIEgVQ7J-TFtaucVFRXUzHm9LmV41goM <nil>
}

// Example creating a token using a custom claims type.  The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleParseWithClaims_customClaimsType() {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiYXVkIjoic2luZ2xlIn0.QAWg1vGvnqRuCFTMcPkjZljXHh8U3L_qUjszOtQbeaA"

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})
	if err != nil {
		log.Fatal(err)
	} else if claims, ok := token.Claims.(*MyCustomClaims); ok {
		fmt.Println(claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		log.Fatal("unknown claims type, cannot proceed")
	}

	// Output: bar test
}

// Example creating a token using a custom claims type and validation options.  The RegisteredClaims is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleParseWithClaims_validationOptions() {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiYXVkIjoic2luZ2xlIn0.QAWg1vGvnqRuCFTMcPkjZljXHh8U3L_qUjszOtQbeaA"

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	}, jwt.WithLeeway(5*time.Second))
	if err != nil {
		log.Fatal(err)
	} else if claims, ok := token.Claims.(*MyCustomClaims); ok {
		fmt.Println(claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		log.Fatal("unknown claims type, cannot proceed")
	}

	// Output: bar test
}

type MyCustomClaims struct {
	Foo string `json:"foo"`
	jwt.RegisteredClaims
}

// Ensure we implement [jwt.ClaimsValidator] at compile time so we know our custom Validate method is used.
var _ jwt.ClaimsValidator = (*MyCustomClaims)(nil)

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
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiYXVkIjoic2luZ2xlIn0.QAWg1vGvnqRuCFTMcPkjZljXHh8U3L_qUjszOtQbeaA"

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	}, jwt.WithLeeway(5*time.Second))
	if err != nil {
		log.Fatal(err)
	} else if claims, ok := token.Claims.(*MyCustomClaims); ok {
		fmt.Println(claims.Foo, claims.RegisteredClaims.Issuer)
	} else {
		log.Fatal("unknown claims type, cannot proceed")
	}

	// Output: bar test
}

// Example parsing a string to a token with using a custom decoders.
// It's convenient to use the jwt.WithJSONDecoder or jwt.WithBase64Decoder options when create a parser
// to parse string to token by using your favorite JSON or Base64 decoders.
func ExampleParseWithClaims_customDecoder() {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJ0ZXN0IiwiYXVkIjoic2luZ2xlIn0.QAWg1vGvnqRuCFTMcPkjZljXHh8U3L_qUjszOtQbeaA"

	customJSONUnmarshalFunc := json.Unmarshal
	customNewJSONDecoderFunc := json.NewDecoder

	customBase64RawUrlEncoder := base64.RawURLEncoding
	customBase64UrlEncoder := base64.URLEncoding

	jwtParser := jwt.NewParser(jwt.WithJSONDecoder(customJSONUnmarshalFunc, customNewJSONDecoderFunc), jwt.WithBase64Decoder(customBase64RawUrlEncoder, customBase64UrlEncoder))

	token, err := jwtParser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if !token.Valid {
		log.Fatal("invalid")
	} else {
		fmt.Println("valid")
	}

	// Output: valid
}

// An example of parsing the error types using errors.Is.
func ExampleParse_errorChecking() {
	// Token from another example.  This token is expired
	var tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c"

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})

	switch {
	case token.Valid:
		fmt.Println("You look nice today")
	case errors.Is(err, jwt.ErrTokenMalformed):
		fmt.Println("That's not even a token")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		// Invalid signature
		fmt.Println("Invalid signature")
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		// Token is either expired or not active yet
		fmt.Println("Timing is everything")
	default:
		fmt.Println("Couldn't handle this token:", err)
	}

	// Output: Timing is everything
}
