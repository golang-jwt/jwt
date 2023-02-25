package jwt_test

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/test"
)

var errKeyFuncError error = fmt.Errorf("error loading key")

var (
	jwtTestDefaultKey      *rsa.PublicKey
	jwtTestRSAPrivateKey   *rsa.PrivateKey
	jwtTestEC256PublicKey  crypto.PublicKey
	jwtTestEC256PrivateKey crypto.PrivateKey
	paddedKey              crypto.PublicKey
)

type keyFuncKind int

const (
	keyFuncDefault keyFuncKind = iota
	keyFuncECDSA
	keyFuncPadded
	keyFuncEmpty
	keyFuncError
	keyFuncNil
)

func getKeyFunc[T jwt.Claims](kind keyFuncKind) jwt.KeyfuncFor[T] {
	switch kind {
	case keyFuncDefault:
		return func(t *jwt.TokenFor[T]) (interface{}, error) { return jwtTestDefaultKey, nil }
	case keyFuncECDSA:
		return func(t *jwt.TokenFor[T]) (interface{}, error) { return jwtTestEC256PublicKey, nil }
	case keyFuncPadded:
		return func(t *jwt.TokenFor[T]) (interface{}, error) { return paddedKey, nil }
	case keyFuncEmpty:
		return func(t *jwt.TokenFor[T]) (interface{}, error) { return nil, nil }
	case keyFuncError:
		return func(t *jwt.TokenFor[T]) (interface{}, error) { return nil, errKeyFuncError }
	case keyFuncNil:
		return nil
	default:
		panic("unknown keyfunc kind")
	}
}

func init() {
	// Load public keys
	jwtTestDefaultKey = test.LoadRSAPublicKeyFromDisk("test/sample_key.pub")
	jwtTestEC256PublicKey = test.LoadECPublicKeyFromDisk("test/ec256-public.pem")

	// Load padded public key - note there is only a public key for this key pair and should only be used for the
	// two test cases below.
	paddedKey = test.LoadECPublicKeyFromDisk("test/examplePaddedKey-public.pem")

	// Load private keys
	jwtTestRSAPrivateKey = test.LoadRSAPrivateKeyFromDisk("test/sample_key")
	jwtTestEC256PrivateKey = test.LoadECPrivateKeyFromDisk("test/ec256-private.pem")
}

var jwtTestData = []struct {
	name          string
	tokenString   string
	keyfuncKind   keyFuncKind
	claims        jwt.Claims
	valid         bool
	err           []error
	parserOpts    []jwt.ParserOption
	signingMethod jwt.SigningMethod // The method to sign the JWT token for test purpose
}{
	{
		name:          "invalid JWT",
		tokenString:   "thisisnotreallyajwt",
		keyfuncKind:   keyFuncDefault,
		claims:        nil,
		valid:         false,
		err:           []error{jwt.ErrTokenMalformed},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "invalid JSON claim",
		tokenString:   "eyJhbGciOiJSUzI1NiIsInppcCI6IkRFRiJ9.eNqqVkqtKFCyMjQ1s7Q0sbA0MtFRyk3NTUot8kxRslIKLbZQggn4JeamAoUcfRz99HxcXRWeze172tr4bFq7Ui0AAAD__w.jBXD4LT4aq4oXTgDoPkiV6n4QdSZPZI1Z4J8MWQC42aHK0oXwcovEU06dVbtB81TF-2byuu0-qi8J0GUttODT67k6gCl6DV_iuCOV7gczwTcvKslotUvXzoJ2wa0QuujnjxLEE50r0p6k0tsv_9OIFSUZzDksJFYNPlJH2eFG55DROx4TsOz98az37SujZi9GGbTc9SLgzFHPrHMrovRZ5qLC_w4JrdtsLzBBI11OQJgRYwV8fQf4O8IsMkHtetjkN7dKgUkJtRarNWOk76rpTPppLypiLU4_J0-wrElLMh1TzUVZW6Fz2cDHDDBACJgMmKQ2pOFEDK_vYZN74dLCF5GiTZV6DbXhNxO7lqT7JUN4a3p2z96G7WNRjblf2qZeuYdQvkIsiK-rCbSIE836XeY5gaBgkOzuEvzl_tMrpRmb5Oox1ibOfVT2KBh9Lvqsb1XbQjCio2CLE2ViCLqoe0AaRqlUyrk3n8BIG-r0IW4dcw96CEryEMIjsjVp9mtPXamJzf391kt8Rf3iRBqwv3zP7Plg1ResXbmsFUgOflAUPcYmfLug4W3W52ntcUlTHAKXrNfaJL9QQiYAaDukG-ZHDytsOWTuuXw7lVxjt-XYi1VbRAIjh1aIYSELEmEpE4Ny74htQtywYXMQNfJpB0nNn8IiWakgcYYMJ0TmKM",
		keyfuncKind:   keyFuncDefault,
		claims:        nil,
		valid:         false,
		err:           []error{jwt.ErrTokenMalformed},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "bearer in JWT",
		tokenString:   "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfuncKind:   keyFuncDefault,
		claims:        nil,
		valid:         false,
		err:           []error{jwt.ErrTokenMalformed},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "basic",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         true,
		err:           nil,
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "basic expired",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		valid:         false,
		err:           []error{jwt.ErrTokenExpired},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "basic nbf",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		valid:         false,
		err:           []error{jwt.ErrTokenNotValidYet},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "expired and nbf",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		valid:         false,
		err:           []error{jwt.ErrTokenNotValidYet, jwt.ErrTokenExpired},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "basic invalid",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         false,
		err:           []error{jwt.ErrTokenSignatureInvalid, rsa.ErrVerification},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "basic nokeyfunc",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfuncKind:   keyFuncNil,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         false,
		err:           []error{jwt.ErrTokenUnverifiable},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "basic nokey",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfuncKind:   keyFuncEmpty,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         false,
		err:           []error{jwt.ErrTokenSignatureInvalid},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "basic errorkey",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfuncKind:   keyFuncError,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         false,
		err:           []error{jwt.ErrTokenUnverifiable, errKeyFuncError},
		parserOpts:    nil,
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "invalid signing method",
		tokenString:   "",
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         false,
		err:           []error{jwt.ErrTokenSignatureInvalid},
		parserOpts:    []jwt.ParserOption{jwt.WithValidMethods([]string{"HS256"})},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "valid RSA signing method",
		tokenString:   "",
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256", "HS256"})},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "ECDSA signing method not accepted",
		tokenString:   "",
		keyfuncKind:   keyFuncECDSA,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         false,
		err:           []error{jwt.ErrTokenSignatureInvalid},
		parserOpts:    []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256", "HS256"})},
		signingMethod: jwt.SigningMethodES256,
	},
	{
		name:          "valid ECDSA signing method",
		tokenString:   "",
		keyfuncKind:   keyFuncECDSA,
		claims:        jwt.MapClaims{"foo": "bar"},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithValidMethods([]string{"HS256", "ES256"})},
		signingMethod: jwt.SigningMethodES256,
	},
	{
		name:          "JSON Number",
		tokenString:   "",
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": json.Number("123.4")},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "JSON Number - basic expired",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		valid:         false,
		err:           []error{jwt.ErrTokenExpired},
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "JSON Number - basic nbf",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		valid:         false,
		err:           []error{jwt.ErrTokenNotValidYet},
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "JSON Number - expired and nbf",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		valid:         false,
		err:           []error{jwt.ErrTokenNotValidYet, jwt.ErrTokenExpired},
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "SkipClaimsValidation during token parsing",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber(), jwt.WithoutClaimsValidation()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:        "RFC7519 Claims",
		tokenString: "",
		keyfuncKind: keyFuncDefault,
		claims: &jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 10)),
		},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:        "RFC7519 Claims - single aud",
		tokenString: "",
		keyfuncKind: keyFuncDefault,
		claims: &jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"test"},
		},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:        "RFC7519 Claims - multiple aud",
		tokenString: "",
		keyfuncKind: keyFuncDefault,
		claims: &jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"test", "test"},
		},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:        "RFC7519 Claims - single aud with wrong type",
		tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOjF9.8mAIDUfZNQT3TGm1QFIQp91OCpJpQpbB1-m9pA2mkHc", // { "aud": 1 }
		keyfuncKind: keyFuncDefault,
		claims: &jwt.RegisteredClaims{
			Audience: nil, // because of the unmarshal error, this will be empty
		},
		valid:         false,
		err:           []error{jwt.ErrTokenMalformed},
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:        "RFC7519 Claims - multiple aud with wrong types",
		tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsidGVzdCIsMV19.htEBUf7BVbfSmVoTFjXf3y6DLmDUuLy1vTJ14_EX7Ws", // { "aud": ["test", 1] }
		keyfuncKind: keyFuncDefault,
		claims: &jwt.RegisteredClaims{
			Audience: nil, // because of the unmarshal error, this will be empty
		},
		valid:         false,
		err:           []error{jwt.ErrTokenMalformed},
		parserOpts:    []jwt.ParserOption{jwt.WithJSONNumber()},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "RFC7519 Claims - nbf with 60s skew",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        &jwt.RegisteredClaims{NotBefore: jwt.NewNumericDate(time.Now().Add(time.Second * 100))},
		valid:         false,
		err:           []error{jwt.ErrTokenNotValidYet},
		parserOpts:    []jwt.ParserOption{jwt.WithLeeway(time.Minute)},
		signingMethod: jwt.SigningMethodRS256,
	},
	{
		name:          "RFC7519 Claims - nbf with 120s skew",
		tokenString:   "", // autogen
		keyfuncKind:   keyFuncDefault,
		claims:        &jwt.RegisteredClaims{NotBefore: jwt.NewNumericDate(time.Now().Add(time.Second * 100))},
		valid:         true,
		err:           nil,
		parserOpts:    []jwt.ParserOption{jwt.WithLeeway(2 * time.Minute)},
		signingMethod: jwt.SigningMethodRS256,
	},
}

// signToken creates and returns a signed JWT token using signingMethod.
func signToken(claims jwt.Claims, signingMethod jwt.SigningMethod) string {
	var privateKey interface{}
	switch signingMethod {
	case jwt.SigningMethodRS256:
		privateKey = jwtTestRSAPrivateKey
	case jwt.SigningMethodES256:
		privateKey = jwtTestEC256PrivateKey
	default:
		return ""
	}
	return test.MakeSampleToken(claims, signingMethod, privateKey)
}

// cloneToken is necesssary to "forget" the type information back to a generic jwt.Claims.
// Assignment of parameterized types is currently (1.20) not supported.
func cloneToken[T jwt.Claims](tin *jwt.TokenFor[T]) *jwt.TokenFor[jwt.Claims] {
	tout := &jwt.TokenFor[jwt.Claims]{}
	tout.Claims = tin.Claims
	tout.Header = tin.Header
	tout.Method = tin.Method
	tout.Raw = tin.Raw
	tout.Signature = tin.Signature
	tout.Valid = tin.Valid
	return tout
}

func TestParser_Parse(t *testing.T) {
	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		t.Run(data.name, func(t *testing.T) {
			// If the token string is blank, use helper function to generate string
			if data.tokenString == "" {
				data.tokenString = signToken(data.claims, data.signingMethod)
			}

			// Parse the token
			var token *jwt.TokenFor[jwt.Claims]
			var err error
			switch data.claims.(type) {
			case nil:
				parser := jwt.NewParser(data.parserOpts...)
				_, err = parser.Parse(data.tokenString, getKeyFunc[jwt.MapClaims](data.keyfuncKind))
			case jwt.MapClaims:
				parser := jwt.NewParser(data.parserOpts...)
				t, e := parser.Parse(data.tokenString, getKeyFunc[jwt.MapClaims](data.keyfuncKind))
				err = e
				token = cloneToken(t)
			case *jwt.RegisteredClaims:
				parser := jwt.NewParserFor[*jwt.RegisteredClaims](data.parserOpts...)
				t, e := parser.Parse(data.tokenString, getKeyFunc[*jwt.RegisteredClaims](data.keyfuncKind))
				err = e
				token = cloneToken(t)
			default:
				t.Fatalf("unexpected claims type: %T", data.claims)
			}

			// Verify result matches expectation
			if data.claims != nil && !reflect.DeepEqual(data.claims, token.Claims) {
				t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
			}

			if data.valid && err != nil {
				t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
			}

			if !data.valid && err == nil {
				t.Fatalf("[%v] Invalid token passed validation", data.name)
			}

			// Since the returned token is nil in the ErrTokenMalformed, we
			// cannot make the comparison here
			if !errors.Is(err, jwt.ErrTokenMalformed) &&
				((err == nil && !token.Valid) || (err != nil && token.Valid)) {
				t.Errorf("[%v] Inconsistent behavior between returned error and token.Valid", data.name)
			}

			if data.err != nil {
				if err == nil {
					t.Errorf("[%v] Expecting error(s). Didn't get one.", data.name)
				} else {
					all := false
					for _, e := range data.err {
						all = errors.Is(err, e)
					}

					if !all {
						t.Errorf("[%v] Errors don't match expectation.  %v should contain all of %v", data.name, err, data.err)
					}
				}
			}

			if data.valid {
				if token.Signature == "" {
					t.Errorf("[%v] Signature is left unpopulated after parsing", data.name)
				}
				if !token.Valid {
					// The 'Valid' field should be set to true when invoking Parse()
					t.Errorf("[%v] Token.Valid field mismatch. Expecting true, got %v", data.name, token.Valid)
				}
			}
		})
	}
}

func TestParser_ParseUnverified(t *testing.T) {
	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// Skip test data, that intentionally contains malformed tokens, as they would lead to an error
		if len(data.err) == 1 && errors.Is(data.err[0], jwt.ErrTokenMalformed) {
			continue
		}

		t.Run(data.name, func(t *testing.T) {
			// If the token string is blank, use helper function to generate string
			if data.tokenString == "" {
				data.tokenString = signToken(data.claims, data.signingMethod)
			}

			// Parse the token
			var token *jwt.TokenFor[jwt.Claims]
			var err error
			switch data.claims.(type) {
			case jwt.MapClaims:
				parser := jwt.NewParser(data.parserOpts...)
				t, _, e := parser.ParseUnverified(data.tokenString)
				err = e
				token = cloneToken(t)
			case *jwt.RegisteredClaims:
				parser := jwt.NewParserFor[*jwt.RegisteredClaims](data.parserOpts...)
				t, _, e := parser.ParseUnverified(data.tokenString)
				err = e
				token = cloneToken(t)
			}

			// Verify result matches expectation
			if !reflect.DeepEqual(data.claims, token.Claims) {
				t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
			}

			if data.valid && err != nil {
				t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
			}
			if token.Valid {
				// The 'Valid' field should not be set to true when invoking ParseUnverified()
				t.Errorf("[%v] Token.Valid field mismatch. Expecting false, got %v", data.name, token.Valid)
			}
			if token.Signature != "" {
				// The signature was not validated, hence the 'Signature' field is not populated.
				t.Errorf("[%v] Token.Signature field mismatch. Expecting '', got %v", data.name, token.Signature)
			}
		})
	}
}

var setPaddingTestData = []struct {
	name          string
	tokenString   string
	claims        jwt.Claims
	paddedDecode  bool
	strictDecode  bool
	signingMethod jwt.SigningMethod
	keyFuncKind   keyFuncKind
	valid         bool
}{
	{
		name:          "Validated non-padded token with padding disabled",
		tokenString:   "",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  false,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         true,
	},
	{
		name:          "Validated non-padded token with padding enabled",
		tokenString:   "",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  true,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         true,
	},
	{
		name:          "Error for padded token with padding disabled",
		tokenString:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ==.20kGGJaYekGTRFf8b0TwhuETcR8lv5z2363X5jf7G1yTWVTwOmte5Ii8L8_OQbYwPoiVHmZY6iJPbt_DhCN42AeFY74BcsUhR-BVrYUVhKK0RppuzEcSlILDNeQsJDLEL035CPm1VO6Jrgk7enQPIctVxUesRgswP71OpGvJxy3j1k_J8p0WzZvRZTe1D_2Misa0UDGwnEIHhmr97fIpMSZjFxlcygQw8QN34IHLHIXMaTY1eiCf4CCr6rOS9wUeu7P3CPkmFq9XhxBT_LLCmIMhHnxP5x27FUJE_JZlfek0MmARcrhpsZS2sFhHAiWrjxjOE27jkDtv1nEwn65wMw==",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  false,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         false,
	},
	{
		name:          "Validated padded token with padding enabled",
		tokenString:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ==.20kGGJaYekGTRFf8b0TwhuETcR8lv5z2363X5jf7G1yTWVTwOmte5Ii8L8_OQbYwPoiVHmZY6iJPbt_DhCN42AeFY74BcsUhR-BVrYUVhKK0RppuzEcSlILDNeQsJDLEL035CPm1VO6Jrgk7enQPIctVxUesRgswP71OpGvJxy3j1k_J8p0WzZvRZTe1D_2Misa0UDGwnEIHhmr97fIpMSZjFxlcygQw8QN34IHLHIXMaTY1eiCf4CCr6rOS9wUeu7P3CPkmFq9XhxBT_LLCmIMhHnxP5x27FUJE_JZlfek0MmARcrhpsZS2sFhHAiWrjxjOE27jkDtv1nEwn65wMw==",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  true,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         true,
	},
	{
		name:          "Error for example padded token with padding disabled",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3grw==",
		claims:        nil,
		paddedDecode:  false,
		signingMethod: jwt.SigningMethodES256,
		keyFuncKind:   keyFuncPadded,
		valid:         false,
	},
	{
		name:          "Validated example padded token with padding enabled",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3grw==",
		claims:        nil,
		paddedDecode:  true,
		signingMethod: jwt.SigningMethodES256,
		keyFuncKind:   keyFuncPadded,
		valid:         true,
	},
	// DecodeStrict tests, DecodePaddingAllowed=false
	{
		name: "Validated non-padded token with padding disabled, non-strict decode, non-tweaked signature",
		tokenString: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ.bI15h-7mN0f-2diX5I4ErgNQy1uM-rJS5Sz7O0iTWtWSBxY1h6wy8Ywxe5EZTEO6GiIfk7Lk-72Ex-c5aA40QKhPwWB9BJ8O_LfKpezUVBOn0jRItDnVdsk4ccl2zsOVkbA4U4QvdrSbOYMbwoRHzDXfTFpoeMWtn3ez0aENJ8dh4E1echHp5ByI9Pu2aBsvM1WVcMt_BySweCL3f4T7jNZeXDr7Txd00yUd2gdsHYPjXorOvsgaBKN5GLsWd1zIY5z-2gCC8CRSN-IJ4NNX5ifh7l-bOXE2q7szTqa9pvyE9y6TQJhNMSE2FotRce_TOPBWgGpQ-K2I7E8x7wZ8O" +
			"g",
		claims:        nil,
		paddedDecode:  false,
		strictDecode:  false,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         true,
	},
	{
		name: "Validated non-padded token with padding disabled, non-strict decode, tweaked signature",
		tokenString: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ.bI15h-7mN0f-2diX5I4ErgNQy1uM-rJS5Sz7O0iTWtWSBxY1h6wy8Ywxe5EZTEO6GiIfk7Lk-72Ex-c5aA40QKhPwWB9BJ8O_LfKpezUVBOn0jRItDnVdsk4ccl2zsOVkbA4U4QvdrSbOYMbwoRHzDXfTFpoeMWtn3ez0aENJ8dh4E1echHp5ByI9Pu2aBsvM1WVcMt_BySweCL3f4T7jNZeXDr7Txd00yUd2gdsHYPjXorOvsgaBKN5GLsWd1zIY5z-2gCC8CRSN-IJ4NNX5ifh7l-bOXE2q7szTqa9pvyE9y6TQJhNMSE2FotRce_TOPBWgGpQ-K2I7E8x7wZ8O" +
			"h",
		claims:        nil,
		paddedDecode:  false,
		strictDecode:  false,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         true,
	},
	{
		name: "Validated non-padded token with padding disabled, strict decode, non-tweaked signature",
		tokenString: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ.bI15h-7mN0f-2diX5I4ErgNQy1uM-rJS5Sz7O0iTWtWSBxY1h6wy8Ywxe5EZTEO6GiIfk7Lk-72Ex-c5aA40QKhPwWB9BJ8O_LfKpezUVBOn0jRItDnVdsk4ccl2zsOVkbA4U4QvdrSbOYMbwoRHzDXfTFpoeMWtn3ez0aENJ8dh4E1echHp5ByI9Pu2aBsvM1WVcMt_BySweCL3f4T7jNZeXDr7Txd00yUd2gdsHYPjXorOvsgaBKN5GLsWd1zIY5z-2gCC8CRSN-IJ4NNX5ifh7l-bOXE2q7szTqa9pvyE9y6TQJhNMSE2FotRce_TOPBWgGpQ-K2I7E8x7wZ8O" +
			"g",
		claims:        nil,
		paddedDecode:  false,
		strictDecode:  true,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         true,
	},
	{
		name: "Error for non-padded token with padding disabled, strict decode, tweaked signature",
		tokenString: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ.bI15h-7mN0f-2diX5I4ErgNQy1uM-rJS5Sz7O0iTWtWSBxY1h6wy8Ywxe5EZTEO6GiIfk7Lk-72Ex-c5aA40QKhPwWB9BJ8O_LfKpezUVBOn0jRItDnVdsk4ccl2zsOVkbA4U4QvdrSbOYMbwoRHzDXfTFpoeMWtn3ez0aENJ8dh4E1echHp5ByI9Pu2aBsvM1WVcMt_BySweCL3f4T7jNZeXDr7Txd00yUd2gdsHYPjXorOvsgaBKN5GLsWd1zIY5z-2gCC8CRSN-IJ4NNX5ifh7l-bOXE2q7szTqa9pvyE9y6TQJhNMSE2FotRce_TOPBWgGpQ-K2I7E8x7wZ8O" +
			"h",
		claims:        nil,
		paddedDecode:  false,
		strictDecode:  true,
		signingMethod: jwt.SigningMethodRS256,
		keyFuncKind:   keyFuncDefault,
		valid:         false,
	},
	// DecodeStrict tests, DecodePaddingAllowed=true
	{
		name: "Validated padded token with padding enabled, non-strict decode, non-tweaked signature",
		tokenString: "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3gr" +
			"w==",
		claims:        nil,
		paddedDecode:  true,
		strictDecode:  false,
		signingMethod: jwt.SigningMethodES256,
		keyFuncKind:   keyFuncPadded,
		valid:         true,
	},
	{
		name: "Validated padded token with padding enabled, non-strict decode, tweaked signature",
		tokenString: "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3gr" +
			"x==",
		claims:        nil,
		paddedDecode:  true,
		strictDecode:  false,
		signingMethod: jwt.SigningMethodES256,
		keyFuncKind:   keyFuncPadded,
		valid:         true,
	},
	{
		name: "Validated padded token with padding enabled, strict decode, non-tweaked signature",
		tokenString: "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3gr" +
			"w==",
		claims:        nil,
		paddedDecode:  true,
		strictDecode:  true,
		signingMethod: jwt.SigningMethodES256,
		keyFuncKind:   keyFuncPadded,
		valid:         true,
	},
	{
		name: "Error for padded token with padding enabled, strict decode, tweaked signature",
		tokenString: "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3gr" +
			"x==",
		claims:        nil,
		paddedDecode:  true,
		strictDecode:  true,
		signingMethod: jwt.SigningMethodES256,
		keyFuncKind:   keyFuncPadded,
		valid:         false,
	},
}

// Extension of Parsing, this is to test out functionality specific to switching codecs with padding.
func TestSetPadding(t *testing.T) {
	for _, data := range setPaddingTestData {
		t.Run(data.name, func(t *testing.T) {
			jwt.DecodePaddingAllowed = data.paddedDecode
			jwt.DecodeStrict = data.strictDecode

			// If the token string is blank, use helper function to generate string
			if data.tokenString == "" {
				data.tokenString = signToken(data.claims, data.signingMethod)
			}

			// Parse the token
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())

			// Figure out correct claims type
			token, err := parser.Parse(data.tokenString, getKeyFunc[jwt.MapClaims](data.keyFuncKind))

			if (err == nil) != data.valid || token.Valid != data.valid {
				t.Errorf("[%v] Error Parsing Token with decoding padding set to %v: %v",
					data.name,
					data.paddedDecode,
					err,
				)
			}
		})
		jwt.DecodePaddingAllowed = false
		jwt.DecodeStrict = false
	}
}

func BenchmarkParseUnverified(b *testing.B) {
	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = signToken(data.claims, data.signingMethod)
		}

		// Figure out correct claims type
		switch data.claims.(type) {
		case jwt.MapClaims:
			parser := jwt.NewParser(data.parserOpts...)
			b.Run("map_claims", func(b *testing.B) {
				benchmarkParsing(b, parser, data.tokenString)
			})
		case *jwt.RegisteredClaims:
			parser := jwt.NewParser(data.parserOpts...)
			b.Run("registered_claims", func(b *testing.B) {
				benchmarkParsing(b, parser, data.tokenString)
			})
		}

	}
}

// Helper method for benchmarking various parsing methods
func benchmarkParsing[T jwt.Claims](b *testing.B, parser *jwt.Parser[T], tokenString string) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := parser.ParseUnverified(tokenString)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Helper method for benchmarking various signing methods
func benchmarkSigning(b *testing.B, method jwt.SigningMethod, key interface{}) {
	b.Helper()
	t := jwt.New(method)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := t.SignedString(key); err != nil {
				b.Fatal(err)
			}
		}
	})
}
