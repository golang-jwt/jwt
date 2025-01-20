package jwt_test

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

type claimsV1 struct {
	jwt.RegisteredClaims
	ID  string
	Exp int64
}

type claimsV2 struct {
	jwt.RegisteredClaims
	ID     string
	UserID string
}

func (c *claimsV1) Valid() error    { return nil }
func (c *claimsV2) Valid() error    { return nil }
func (c *claimsV1) Version() string { return "v1" }
func (c *claimsV2) Version() string { return "v2" }

func (c *claimsV1) Decode(claims jwt.Claims) (map[string]interface{}, error) {
	c, ok := claims.(*claimsV1)
	if !ok {
		return map[string]interface{}{}, errors.New("couldnt decode")
	}

	return map[string]interface{}{
		"id":         "bar",
		"expiration": fmt.Sprint(c.Exp),
	}, nil
}

func (c *claimsV2) Decode(claims jwt.Claims) (map[string]interface{}, error) {
	c, ok := claims.(*claimsV2)
	if !ok {
		return map[string]interface{}{}, errors.New("couldnt decode")
	}

	return map[string]interface{}{
		"id":      " test",
		"user_id": fmt.Sprint(c.UserID),
	}, nil
}

func ExampleParseWitVersionedClaims_customClaimsType() {
	tokenStringV1 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsInZlcnNpb24iOiJ2MSJ9.eyJJRCI6IjEyMyIsIkV4cCI6MTIzfQ.qbEStFoXm9UspByQtuSVa7vxP3z4-eGeLWf3mlONPgI"
	tokenStringV2 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsInZlcnNpb24iOiJ2MiJ9.eyJJRCI6IjEyMyIsIlVzZXJJRCI6IjEyMyJ9.HM6A9inm-Lo8S-2JhS1W7zyqOUWNcMROOfIYnQP2Rcw"

	jwtVersions := map[string]jwt.VersionedClaims{
		"v1": &claimsV1{},
		"v2": &claimsV2{},
	}

	claimsDataV1, err := jwt.ParseWithVersionedClaims(tokenStringV1, jwtVersions, func(token *jwt.Token) (interface{}, error) {
		return []byte("1"), nil
	})

	claimsDataV2, err := jwt.ParseWithVersionedClaims(tokenStringV2, jwtVersions, func(token *jwt.Token) (interface{}, error) {
		return []byte("1"), nil
	})

	if err != nil {
		log.Fatal(err)
	} else if len(claimsDataV1) > 0 && len(claimsDataV1) > 0 {
		fmt.Println(claimsDataV1["id"].(string) + claimsDataV2["id"].(string))
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
