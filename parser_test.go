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

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/test"
)

var errKeyFuncError error = fmt.Errorf("error loading key")

var (
	jwtTestDefaultKey      *rsa.PublicKey
	jwtTestRSAPrivateKey   *rsa.PrivateKey
	jwtTestEC256PublicKey  crypto.PublicKey
	jwtTestEC256PrivateKey crypto.PrivateKey
	paddedKey              crypto.PublicKey
	defaultKeyFunc         jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	ecdsaKeyFunc           jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestEC256PublicKey, nil }
	paddedKeyFunc          jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return paddedKey, nil }
	emptyKeyFunc           jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, nil }
	errorKeyFunc           jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, errKeyFuncError }
	nilKeyFunc             jwt.Keyfunc = nil
)

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
	keyfunc       jwt.Keyfunc
	claims        jwt.Claims
	valid         bool
	errors        uint32
	err           []error
	parser        *jwt.Parser
	signingMethod jwt.SigningMethod // The method to sign the JWT token for test purpose
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic expired",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorExpired,
		[]error{jwt.ErrTokenExpired},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		jwt.ValidationErrorNotValidYet,
		[]error{jwt.ErrTokenNotValidYet},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"expired and nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		false,
		jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired,
		[]error{jwt.ErrTokenNotValidYet},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		[]error{jwt.ErrTokenSignatureInvalid, rsa.ErrVerification},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic nokeyfunc",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nilKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
		[]error{jwt.ErrTokenUnverifiable},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		emptyKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		[]error{jwt.ErrTokenSignatureInvalid},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic errorkey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		errorKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorUnverifiable,
		[]error{jwt.ErrTokenUnverifiable, errKeyFuncError},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"invalid signing method",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		[]error{jwt.ErrTokenSignatureInvalid},
		&jwt.Parser{ValidMethods: []string{"HS256"}},
		jwt.SigningMethodRS256,
	},
	{
		"valid RSA signing method",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
		&jwt.Parser{ValidMethods: []string{"RS256", "HS256"}},
		jwt.SigningMethodRS256,
	},
	{
		"ECDSA signing method not accepted",
		"",
		ecdsaKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		jwt.ValidationErrorSignatureInvalid,
		[]error{jwt.ErrTokenSignatureInvalid},
		&jwt.Parser{ValidMethods: []string{"RS256", "HS256"}},
		jwt.SigningMethodES256,
	},
	{
		"valid ECDSA signing method",
		"",
		ecdsaKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
		&jwt.Parser{ValidMethods: []string{"HS256", "ES256"}},
		jwt.SigningMethodES256,
	},
	{
		"JSON Number",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": json.Number("123.4")},
		true,
		0,
		nil,
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"Standard Claims",
		"",
		defaultKeyFunc,
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * 10).Unix(),
		},
		true,
		0,
		nil,
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"JSON Number - basic expired",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		jwt.ValidationErrorExpired,
		[]error{jwt.ErrTokenExpired},
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"JSON Number - basic nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		false,
		jwt.ValidationErrorNotValidYet,
		[]error{jwt.ErrTokenNotValidYet},
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"JSON Number - expired and nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired,
		[]error{jwt.ErrTokenNotValidYet},
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"SkipClaimsValidation during token parsing",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		true,
		0,
		nil,
		&jwt.Parser{UseJSONNumber: true, SkipClaimsValidation: true},
		jwt.SigningMethodRS256,
	},
	{
		"RFC7519 Claims",
		"",
		defaultKeyFunc,
		&jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 10)),
		},
		true,
		0,
		nil,
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"RFC7519 Claims - single aud",
		"",
		defaultKeyFunc,
		&jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"test"},
		},
		true,
		0,
		nil,
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"RFC7519 Claims - multiple aud",
		"",
		defaultKeyFunc,
		&jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"test", "test"},
		},
		true,
		0,
		nil,
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"RFC7519 Claims - single aud with wrong type",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOjF9.8mAIDUfZNQT3TGm1QFIQp91OCpJpQpbB1-m9pA2mkHc", // { "aud": 1 }
		defaultKeyFunc,
		&jwt.RegisteredClaims{
			Audience: nil, // because of the unmarshal error, this will be empty
		},
		false,
		jwt.ValidationErrorMalformed,
		[]error{jwt.ErrTokenMalformed},
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
	},
	{
		"RFC7519 Claims - multiple aud with wrong types",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsidGVzdCIsMV19.htEBUf7BVbfSmVoTFjXf3y6DLmDUuLy1vTJ14_EX7Ws", // { "aud": ["test", 1] }
		defaultKeyFunc,
		&jwt.RegisteredClaims{
			Audience: nil, // because of the unmarshal error, this will be empty
		},
		false,
		jwt.ValidationErrorMalformed,
		[]error{jwt.ErrTokenMalformed},
		&jwt.Parser{UseJSONNumber: true},
		jwt.SigningMethodRS256,
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

func TestParser_Parse(t *testing.T) {

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		t.Run(data.name, func(t *testing.T) {

			// If the token string is blank, use helper function to generate string
			if data.tokenString == "" {
				data.tokenString = signToken(data.claims, data.signingMethod)
			}

			// Parse the token
			var token *jwt.Token
			var ve *jwt.ValidationError
			var err error
			var parser = data.parser
			if parser == nil {
				parser = new(jwt.Parser)
			}
			// Figure out correct claims type
			switch data.claims.(type) {
			case jwt.MapClaims:
				token, err = parser.ParseWithClaims(data.tokenString, jwt.MapClaims{}, data.keyfunc)
			case *jwt.StandardClaims:
				token, err = parser.ParseWithClaims(data.tokenString, &jwt.StandardClaims{}, data.keyfunc)
			case *jwt.RegisteredClaims:
				token, err = parser.ParseWithClaims(data.tokenString, &jwt.RegisteredClaims{}, data.keyfunc)
			}

			// Verify result matches expectation
			if !reflect.DeepEqual(data.claims, token.Claims) {
				t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
			}

			if data.valid && err != nil {
				t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
			}

			if !data.valid && err == nil {
				t.Errorf("[%v] Invalid token passed validation", data.name)
			}

			if (err == nil && !token.Valid) || (err != nil && token.Valid) {
				t.Errorf("[%v] Inconsistent behavior between returned error and token.Valid", data.name)
			}

			if data.errors != 0 {
				if err == nil {
					t.Errorf("[%v] Expecting error. Didn't get one.", data.name)
				} else {
					if errors.As(err, &ve) {
						// compare the bitfield part of the error
						if e := ve.Errors; e != data.errors {
							t.Errorf("[%v] Errors don't match expectation.  %v != %v", data.name, e, data.errors)
						}

						if err.Error() == errKeyFuncError.Error() && ve.Inner != errKeyFuncError {
							t.Errorf("[%v] Inner error does not match expectation.  %v != %v", data.name, ve.Inner, errKeyFuncError)
						}
					}
				}
			}

			if data.err != nil {
				if err == nil {
					t.Errorf("[%v] Expecting error(s). Didn't get one.", data.name)
				} else {
					var all = false
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
		if data.errors&jwt.ValidationErrorMalformed != 0 {
			continue
		}

		t.Run(data.name, func(t *testing.T) {
			// If the token string is blank, use helper function to generate string
			if data.tokenString == "" {
				data.tokenString = signToken(data.claims, data.signingMethod)
			}

			// Parse the token
			var token *jwt.Token
			var err error
			var parser = data.parser
			if parser == nil {
				parser = new(jwt.Parser)
			}
			// Figure out correct claims type
			switch data.claims.(type) {
			case jwt.MapClaims:
				token, _, err = parser.ParseUnverified(data.tokenString, jwt.MapClaims{})
			case *jwt.StandardClaims:
				token, _, err = parser.ParseUnverified(data.tokenString, &jwt.StandardClaims{})
			case *jwt.RegisteredClaims:
				token, _, err = parser.ParseUnverified(data.tokenString, &jwt.RegisteredClaims{})
			}

			if err != nil {
				t.Errorf("[%v] Invalid token", data.name)
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
	signingMethod jwt.SigningMethod
	keyfunc       jwt.Keyfunc
	valid         bool
}{
	{
		name:          "Validated non-padded token with padding disabled",
		tokenString:   "",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  false,
		signingMethod: jwt.SigningMethodRS256,
		keyfunc:       defaultKeyFunc,
		valid:         true,
	},
	{
		name:          "Validated non-padded token with padding enabled",
		tokenString:   "",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  true,
		signingMethod: jwt.SigningMethodRS256,
		keyfunc:       defaultKeyFunc,
		valid:         true,
	},
	{
		name:          "Error for padded token with padding disabled",
		tokenString:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ==.20kGGJaYekGTRFf8b0TwhuETcR8lv5z2363X5jf7G1yTWVTwOmte5Ii8L8_OQbYwPoiVHmZY6iJPbt_DhCN42AeFY74BcsUhR-BVrYUVhKK0RppuzEcSlILDNeQsJDLEL035CPm1VO6Jrgk7enQPIctVxUesRgswP71OpGvJxy3j1k_J8p0WzZvRZTe1D_2Misa0UDGwnEIHhmr97fIpMSZjFxlcygQw8QN34IHLHIXMaTY1eiCf4CCr6rOS9wUeu7P3CPkmFq9XhxBT_LLCmIMhHnxP5x27FUJE_JZlfek0MmARcrhpsZS2sFhHAiWrjxjOE27jkDtv1nEwn65wMw==",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  false,
		signingMethod: jwt.SigningMethodRS256,
		keyfunc:       defaultKeyFunc,
		valid:         false,
	},
	{
		name:          "Validated padded token with padding enabled",
		tokenString:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ==.20kGGJaYekGTRFf8b0TwhuETcR8lv5z2363X5jf7G1yTWVTwOmte5Ii8L8_OQbYwPoiVHmZY6iJPbt_DhCN42AeFY74BcsUhR-BVrYUVhKK0RppuzEcSlILDNeQsJDLEL035CPm1VO6Jrgk7enQPIctVxUesRgswP71OpGvJxy3j1k_J8p0WzZvRZTe1D_2Misa0UDGwnEIHhmr97fIpMSZjFxlcygQw8QN34IHLHIXMaTY1eiCf4CCr6rOS9wUeu7P3CPkmFq9XhxBT_LLCmIMhHnxP5x27FUJE_JZlfek0MmARcrhpsZS2sFhHAiWrjxjOE27jkDtv1nEwn65wMw==",
		claims:        jwt.MapClaims{"foo": "paddedbar"},
		paddedDecode:  true,
		signingMethod: jwt.SigningMethodRS256,
		keyfunc:       defaultKeyFunc,
		valid:         true,
	},
	{
		name:          "Error for example padded token with padding disabled",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3grw==",
		claims:        nil,
		paddedDecode:  false,
		signingMethod: jwt.SigningMethodES256,
		keyfunc:       paddedKeyFunc,
		valid:         false,
	},
	{
		name:          "Validated example padded token with padding enabled",
		tokenString:   "eyJ0eXAiOiJKV1QiLCJraWQiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vIiwiY2xpZW50IjoiN0xUY29QWnJWNDR6ZVg2WUs5VktBcHZPM3EiLCJzaWduZXIiOiJhcm46YXdzOmVsYXN0aWNsb2FkYmFsYW5jaW5nIiwiZXhwIjoxNjI5NDcwMTAxfQ==.eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3OGFiY2QiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6IjEyMzQ1Njc4LWFiY2QtMTIzNC1hYmNkLTEyMzQ1Njc4YWJjZCIsImV4cCI6MTYyOTQ3MDEwMSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbS8ifQ==.sx0muJ754glJvwWgkHaPrOI3L1gaPjRLLUvOQRk0WitnqC5Dtt1knorcbOzlEcH9zwPM2jYYIAYQz_qEyM3grw==",
		claims:        nil,
		paddedDecode:  true,
		signingMethod: jwt.SigningMethodES256,
		keyfunc:       paddedKeyFunc,
		valid:         true,
	},
}

// Extension of Parsing, this is to test out functionality specific to switching codecs with padding.
func TestSetPadding(t *testing.T) {
	for _, data := range setPaddingTestData {
		t.Run(data.name, func(t *testing.T) {

			// If the token string is blank, use helper function to generate string
			jwt.DecodePaddingAllowed = data.paddedDecode

			if data.tokenString == "" {
				data.tokenString = signToken(data.claims, data.signingMethod)

			}

			// Parse the token
			var token *jwt.Token
			var err error
			parser := new(jwt.Parser)
			parser.SkipClaimsValidation = true

			// Figure out correct claims type
			token, err = parser.ParseWithClaims(data.tokenString, jwt.MapClaims{}, data.keyfunc)

			if (err == nil) != data.valid || token.Valid != data.valid {
				t.Errorf("[%v] Error Parsing Token with decoding padding set to %v: %v",
					data.name,
					data.paddedDecode,
					err,
				)
			}

		})
		jwt.DecodePaddingAllowed = false

	}
}

func BenchmarkParseUnverified(b *testing.B) {

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = signToken(data.claims, data.signingMethod)
		}

		// Parse the token
		var parser = data.parser
		if parser == nil {
			parser = new(jwt.Parser)
		}
		// Figure out correct claims type
		switch data.claims.(type) {
		case jwt.MapClaims:
			b.Run("map_claims", func(b *testing.B) {
				benchmarkParsing(b, parser, data.tokenString, jwt.MapClaims{})
			})
		case *jwt.StandardClaims:
			b.Run("standard_claims", func(b *testing.B) {
				benchmarkParsing(b, parser, data.tokenString, &jwt.StandardClaims{})
			})
		}
	}
}

// Helper method for benchmarking various parsing methods
func benchmarkParsing(b *testing.B, parser *jwt.Parser, tokenString string, claims jwt.Claims) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
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
