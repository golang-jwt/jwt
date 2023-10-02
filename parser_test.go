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
	defaultKeyFunc         jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	ecdsaKeyFunc           jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestEC256PublicKey, nil }
	paddedKeyFunc          jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return paddedKey, nil }
	emptyKeyFunc           jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, nil }
	errorKeyFunc           jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, errKeyFuncError }
	nilKeyFunc             jwt.Keyfunc = nil
	multipleZeroKeyFunc    jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return []interface{}{}, nil }
	multipleEmptyKeyFunc   jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) {
		return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{nil, nil}}, nil
	}
	multipleVerificationKeysFunc jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) {
		return []jwt.VerificationKey{jwtTestDefaultKey, jwtTestEC256PublicKey}, nil
	}
	multipleLastKeyFunc jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) {
		return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{jwtTestEC256PublicKey, jwtTestDefaultKey}}, nil
	}
	multipleFirstKeyFunc jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) {
		return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{jwtTestDefaultKey, jwtTestEC256PublicKey}}, nil
	}
	multipleAltTypedKeyFunc jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) {
		return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{jwtTestDefaultKey, jwtTestDefaultKey}}, nil
	}
	emptyVerificationKeySetFunc jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) {
		return jwt.VerificationKeySet{}, nil
	}
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
	err           []error
	parser        *jwt.Parser
	signingMethod jwt.SigningMethod // The method to sign the JWT token for test purpose
}{
	{
		"invalid JWT",
		"thisisnotreallyajwt",
		defaultKeyFunc,
		nil,
		false,
		[]error{jwt.ErrTokenMalformed},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"invalid JSON claim",
		"eyJhbGciOiJSUzI1NiIsInppcCI6IkRFRiJ9.eNqqVkqtKFCyMjQ1s7Q0sbA0MtFRyk3NTUot8kxRslIKLbZQggn4JeamAoUcfRz99HxcXRWeze172tr4bFq7Ui0AAAD__w.jBXD4LT4aq4oXTgDoPkiV6n4QdSZPZI1Z4J8MWQC42aHK0oXwcovEU06dVbtB81TF-2byuu0-qi8J0GUttODT67k6gCl6DV_iuCOV7gczwTcvKslotUvXzoJ2wa0QuujnjxLEE50r0p6k0tsv_9OIFSUZzDksJFYNPlJH2eFG55DROx4TsOz98az37SujZi9GGbTc9SLgzFHPrHMrovRZ5qLC_w4JrdtsLzBBI11OQJgRYwV8fQf4O8IsMkHtetjkN7dKgUkJtRarNWOk76rpTPppLypiLU4_J0-wrElLMh1TzUVZW6Fz2cDHDDBACJgMmKQ2pOFEDK_vYZN74dLCF5GiTZV6DbXhNxO7lqT7JUN4a3p2z96G7WNRjblf2qZeuYdQvkIsiK-rCbSIE836XeY5gaBgkOzuEvzl_tMrpRmb5Oox1ibOfVT2KBh9Lvqsb1XbQjCio2CLE2ViCLqoe0AaRqlUyrk3n8BIG-r0IW4dcw96CEryEMIjsjVp9mtPXamJzf391kt8Rf3iRBqwv3zP7Plg1ResXbmsFUgOflAUPcYmfLug4W3W52ntcUlTHAKXrNfaJL9QQiYAaDukG-ZHDytsOWTuuXw7lVxjt-XYi1VbRAIjh1aIYSELEmEpE4Ny74htQtywYXMQNfJpB0nNn8IiWakgcYYMJ0TmKM",
		defaultKeyFunc,
		nil,
		false,
		[]error{jwt.ErrTokenMalformed},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"bearer in JWT",
		"bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		nil,
		false,
		[]error{jwt.ErrTokenMalformed},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"multiple keys, last matches",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		multipleLastKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"multiple keys not []interface{} type, all match",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		multipleAltTypedKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"multiple keys, first matches",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		multipleFirstKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"public keys slice, not allowed",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		multipleVerificationKeysFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{jwt.ErrTokenSignatureInvalid},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic expired",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
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
		[]error{jwt.ErrTokenNotValidYet, jwt.ErrTokenExpired},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
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
		[]error{jwt.ErrTokenSignatureInvalid},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"multiple nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		multipleEmptyKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{jwt.ErrTokenSignatureInvalid},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"empty verification key set",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		emptyVerificationKeySetFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{jwt.ErrTokenUnverifiable},
		nil,
		jwt.SigningMethodRS256,
	},
	{
		"zero length key list",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		multipleZeroKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
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
		[]error{jwt.ErrTokenSignatureInvalid},
		jwt.NewParser(jwt.WithValidMethods([]string{"HS256"})),
		jwt.SigningMethodRS256,
	},
	{
		"valid RSA signing method",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "HS256"})),
		jwt.SigningMethodRS256,
	},
	{
		"ECDSA signing method not accepted",
		"",
		ecdsaKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		false,
		[]error{jwt.ErrTokenSignatureInvalid},
		jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "HS256"})),
		jwt.SigningMethodES256,
	},
	{
		"valid ECDSA signing method",
		"",
		ecdsaKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		nil,
		jwt.NewParser(jwt.WithValidMethods([]string{"HS256", "ES256"})),
		jwt.SigningMethodES256,
	},
	{
		"JSON Number",
		"",
		defaultKeyFunc,
		jwt.MapClaims{"foo": json.Number("123.4")},
		true,
		nil,
		jwt.NewParser(jwt.WithJSONNumber()),
		jwt.SigningMethodRS256,
	},
	{
		"JSON Number - basic expired",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		[]error{jwt.ErrTokenExpired},
		jwt.NewParser(jwt.WithJSONNumber()),
		jwt.SigningMethodRS256,
	},
	{
		"JSON Number - basic nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		false,
		[]error{jwt.ErrTokenNotValidYet},
		jwt.NewParser(jwt.WithJSONNumber()),
		jwt.SigningMethodRS256,
	},
	{
		"JSON Number - expired and nbf",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		[]error{jwt.ErrTokenNotValidYet, jwt.ErrTokenExpired},
		jwt.NewParser(jwt.WithJSONNumber()),
		jwt.SigningMethodRS256,
	},
	{
		"SkipClaimsValidation during token parsing",
		"", // autogen
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		true,
		nil,
		jwt.NewParser(jwt.WithJSONNumber(), jwt.WithoutClaimsValidation()),
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
		nil,
		jwt.NewParser(jwt.WithJSONNumber()),
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
		nil,
		jwt.NewParser(jwt.WithJSONNumber()),
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
		nil,
		jwt.NewParser(jwt.WithJSONNumber()),
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
		[]error{jwt.ErrTokenMalformed},
		jwt.NewParser(jwt.WithJSONNumber()),
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
		[]error{jwt.ErrTokenMalformed},
		jwt.NewParser(jwt.WithJSONNumber()),
		jwt.SigningMethodRS256,
	},
	{
		"RFC7519 Claims - nbf with 60s skew",
		"", // autogen
		defaultKeyFunc,
		&jwt.RegisteredClaims{NotBefore: jwt.NewNumericDate(time.Now().Add(time.Second * 100))},
		false,
		[]error{jwt.ErrTokenNotValidYet},
		jwt.NewParser(jwt.WithLeeway(time.Minute)),
		jwt.SigningMethodRS256,
	},
	{
		"RFC7519 Claims - nbf with 120s skew",
		"", // autogen
		defaultKeyFunc,
		&jwt.RegisteredClaims{NotBefore: jwt.NewNumericDate(time.Now().Add(time.Second * 100))},
		true,
		nil,
		jwt.NewParser(jwt.WithLeeway(2 * time.Minute)),
		jwt.SigningMethodRS256,
	},
	{
		"rejects if exp is required but missing",
		"", // autogen
		defaultKeyFunc,
		&jwt.RegisteredClaims{},
		false,
		[]error{jwt.ErrTokenInvalidClaims},
		jwt.NewParser(jwt.WithExpirationRequired()),
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
			var err error
			var parser = data.parser
			if parser == nil {
				parser = jwt.NewParser()
			}
			// Figure out correct claims type
			switch data.claims.(type) {
			case jwt.MapClaims:
				token, err = parser.ParseWithClaims(data.tokenString, jwt.MapClaims{}, data.keyfunc)
			case *jwt.RegisteredClaims:
				token, err = parser.ParseWithClaims(data.tokenString, &jwt.RegisteredClaims{}, data.keyfunc)
			case nil:
				token, err = parser.ParseWithClaims(data.tokenString, nil, data.keyfunc)
			}

			// Verify result matches expectation
			if data.claims != nil && !reflect.DeepEqual(data.claims, token.Claims) {
				t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
			}

			if data.valid && err != nil {
				t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
			}

			if !data.valid && err == nil {
				t.Errorf("[%v] Invalid token passed validation", data.name)
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
				if len(token.Signature) == 0 {
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
			if len(token.Signature) != 0 {
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
	// DecodeStrict tests, DecodePaddingAllowed=false
	{
		name: "Validated non-padded token with padding disabled, non-strict decode, non-tweaked signature",
		tokenString: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJwYWRkZWRiYXIifQ.bI15h-7mN0f-2diX5I4ErgNQy1uM-rJS5Sz7O0iTWtWSBxY1h6wy8Ywxe5EZTEO6GiIfk7Lk-72Ex-c5aA40QKhPwWB9BJ8O_LfKpezUVBOn0jRItDnVdsk4ccl2zsOVkbA4U4QvdrSbOYMbwoRHzDXfTFpoeMWtn3ez0aENJ8dh4E1echHp5ByI9Pu2aBsvM1WVcMt_BySweCL3f4T7jNZeXDr7Txd00yUd2gdsHYPjXorOvsgaBKN5GLsWd1zIY5z-2gCC8CRSN-IJ4NNX5ifh7l-bOXE2q7szTqa9pvyE9y6TQJhNMSE2FotRce_TOPBWgGpQ-K2I7E8x7wZ8O" +
			"g",
		claims:        nil,
		paddedDecode:  false,
		strictDecode:  false,
		signingMethod: jwt.SigningMethodRS256,
		keyfunc:       defaultKeyFunc,
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
		keyfunc:       defaultKeyFunc,
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
		keyfunc:       defaultKeyFunc,
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
		keyfunc:       defaultKeyFunc,
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
		keyfunc:       paddedKeyFunc,
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
		keyfunc:       paddedKeyFunc,
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
		keyfunc:       paddedKeyFunc,
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
		keyfunc:       paddedKeyFunc,
		valid:         false,
	},
}

// Extension of Parsing, this is to test out functionality specific to switching codecs with padding.
func TestSetPadding(t *testing.T) {
	for _, data := range setPaddingTestData {
		t.Run(data.name, func(t *testing.T) {
			// If the token string is blank, use helper function to generate string
			if data.tokenString == "" {
				data.tokenString = signToken(data.claims, data.signingMethod)
			}

			// Parse the token
			var token *jwt.Token
			var err error
			var opts []jwt.ParserOption = []jwt.ParserOption{jwt.WithoutClaimsValidation()}

			if data.paddedDecode {
				opts = append(opts, jwt.WithPaddingAllowed())
			}
			if data.strictDecode {
				opts = append(opts, jwt.WithStrictDecoding())
			}

			parser := jwt.NewParser(opts...)

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
		case *jwt.RegisteredClaims:
			b.Run("registered_claims", func(b *testing.B) {
				benchmarkParsing(b, parser, data.tokenString, &jwt.RegisteredClaims{})
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
