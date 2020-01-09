package jwt_test

import (
	"crypto/rsa"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// 2 valid rsa pubkeys that's not the one used to sign the payload
const (
	wrongRSAPubKeyData1 = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAycU1W/hMRWNLkaJPEwWg
j36URuSaRTV0BEvY+L0nRseCnEdlIsj8LCI+ydk3HlJqj3QicuCP9U0W5JAP4PYB
Xs+dV/J38fqdYfI1myXRG2wU5USziF3OC3YYZIXiPe41IltP7LSUmyRO/F6jAcUj
ZmRP2sxhIjY/77nQbx1F3ZMF2i91CRyaIfyd2pC8pwA4VElBTZaP9j3xXEsA8VIX
F/PSVcDsm3GoxVkwQbJTr54GedsRMoex574rvt8iujiNQ7Cb0uXWFIfnlD1thnne
4ws5ekuVhT6lq1KDB2z4e/pN2cOEzzSmfJJK1AWS79R4sAO8Fm/8cpWx6MRhlAbv
HwIDAQAB
-----END PUBLIC KEY-----`
	wrongRSAPubKeyData2 = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06q+yHMtXDj3qa3qELcg
bS/48HWbylEi+smx+xa8yupMTMtne6WFvxiS3lU/+TXQj+hdHzwpLj+W24QCON1o
JqxYDLWVJ2YpmrwkU/IDbhoPKfpYchy6Zmg2bnr93FDcvc4oL2/UYaiG+3w8fS+D
BcHug7ILLmY5RnwqzdcYfQ5waX2QCK75kmtB+TBqtS3xAr2m2omdla91YeARSu3O
lVjB6h9QNfbR6KCZRalMWlNGpp0tG0faU9mEescY4zfqt2inQFAr+MuXjJhg0tW8
kO6LskiW1+SbBlNrJeQDXUjC/vz6/8X1DvDeczd9tqbAxfV57yRjIxkfsDYxehai
6QIDAQAB
-----END PUBLIC KEY-----`
)

var rsaTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic RS256",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"RS256",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic RS384",
		"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.W-jEzRfBigtCWsinvVVuldiuilzVdU5ty0MvpLaSaqK9PlAWWlDQ1VIQ_qSKzwL5IXaZkvZFJXT3yL3n7OUVu7zCNJzdwznbC8Z-b0z2lYvcklJYi2VOFRcGbJtXUqgjk2oGsiqUMUMOLP70TTefkpsgqDxbRh9CDUfpOJgW-dU7cmgaoswe3wjUAUi6B6G2YEaiuXC0XScQYSYVKIzgKXJV8Zw-7AN_DBUI4GkTpsvQ9fVVjZM9csQiEXhYekyrKu1nu_POpQonGd8yqkIyXPECNmmqH5jH4sFiF67XhD7_JpkvLziBpI-uh86evBUadmHhb9Otqw3uV3NTaXLzJw",
		"RS384",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic RS512",
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ",
		"RS512",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"RS256",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestRSAVerify(t *testing.T) {
	keyData, _ := ioutil.ReadFile("test/sample_key.pub")
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)
	wrongKey1, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(wrongRSAPubKeyData1))
	wrongKey2, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(wrongRSAPubKeyData2))

	for _, data := range rsaTestData {
		parts := strings.Split(data.tokenString, ".")

		method := jwt.GetSigningMethod(data.alg)
		err := method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}

		// test key rotations
		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], []*rsa.PublicKey{})
		if err == nil {
			t.Errorf("[%v] Empty key list passed validation", data.name)
		}
		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], []*rsa.PublicKey{wrongKey1, wrongKey2})
		if err == nil {
			t.Errorf("[%v] Wrong keys passed validation", data.name)
		}

		if !data.valid {
			continue
		}

		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], []*rsa.PublicKey{wrongKey1, key, wrongKey2})
		if err != nil {
			t.Errorf("[%v] Error while verifying key list: %v", data.name, err)
		}
	}
}

func TestRSASign(t *testing.T) {
	keyData, _ := ioutil.ReadFile("test/sample_key")
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	for _, data := range rsaTestData {
		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			method := jwt.GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), key)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}
			if sig != parts[2] {
				t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", data.name, sig, parts[2])
			}
		}
	}
}

func TestRSAVerifyWithPreParsedPrivateKey(t *testing.T) {
	key, _ := ioutil.ReadFile("test/sample_key.pub")
	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	testData := rsaTestData[0]
	parts := strings.Split(testData.tokenString, ".")
	err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], parsedKey)
	if err != nil {
		t.Errorf("[%v] Error while verifying key: %v", testData.name, err)
	}
}

func TestRSAWithPreParsedPrivateKey(t *testing.T) {
	key, _ := ioutil.ReadFile("test/sample_key")
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	testData := rsaTestData[0]
	parts := strings.Split(testData.tokenString, ".")
	sig, err := jwt.SigningMethodRS256.Sign(strings.Join(parts[0:2], "."), parsedKey)
	if err != nil {
		t.Errorf("[%v] Error signing token: %v", testData.name, err)
	}
	if sig != parts[2] {
		t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", testData.name, sig, parts[2])
	}
}

func TestRSAKeyParsing(t *testing.T) {
	key, _ := ioutil.ReadFile("test/sample_key")
	secureKey, _ := ioutil.ReadFile("test/privateSecure.pem")
	pubKey, _ := ioutil.ReadFile("test/sample_key.pub")
	badKey := []byte("All your base are belong to key")

	// Test parsePrivateKey
	if _, e := jwt.ParseRSAPrivateKeyFromPEM(key); e != nil {
		t.Errorf("Failed to parse valid private key: %v", e)
	}

	if k, e := jwt.ParseRSAPrivateKeyFromPEM(pubKey); e == nil {
		t.Errorf("Parsed public key as valid private key: %v", k)
	}

	if k, e := jwt.ParseRSAPrivateKeyFromPEM(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}

	if _, e := jwt.ParseRSAPrivateKeyFromPEMWithPassword(secureKey, "password"); e != nil {
		t.Errorf("Failed to parse valid private key with password: %v", e)
	}

	if k, e := jwt.ParseRSAPrivateKeyFromPEMWithPassword(secureKey, "123132"); e == nil {
		t.Errorf("Parsed private key with invalid password %v", k)
	}

	// Test parsePublicKey
	if _, e := jwt.ParseRSAPublicKeyFromPEM(pubKey); e != nil {
		t.Errorf("Failed to parse valid public key: %v", e)
	}

	if k, e := jwt.ParseRSAPublicKeyFromPEM(key); e == nil {
		t.Errorf("Parsed private key as valid public key: %v", k)
	}

	if k, e := jwt.ParseRSAPublicKeyFromPEM(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}

}

func BenchmarkRSAParsing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/sample_key")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := jwt.ParseRSAPrivateKeyFromPEM(key); err != nil {
				b.Fatalf("Unable to parse RSA private key: %v", err)
			}
		}
	})
}

func BenchmarkRS256Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/sample_key")
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, jwt.SigningMethodRS256, parsedKey)
}

func BenchmarkRS384Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/sample_key")
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, jwt.SigningMethodRS384, parsedKey)
}

func BenchmarkRS512Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/sample_key")
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, jwt.SigningMethodRS512, parsedKey)
}

func validateWithManualRotation(payload string, keys []*rsa.PublicKey) bool {
	claims := new(jwt.RegisteredClaims)
	for _, key := range keys {
		token, err := jwt.ParseWithClaims(payload, claims, func(_ *jwt.Token) (interface{}, error) {
			return key, nil
		})
		if err != nil {
			continue
		}
		if !token.Valid {
			continue
		}
		if _, ok := token.Claims.(*jwt.RegisteredClaims); ok {
			return true
		}
	}
	return false
}

func validateWithNativeRotation(payload string, keys []*rsa.PublicKey) bool {

	token, err := jwt.ParseWithClaims(payload, new(jwt.RegisteredClaims), func(_ *jwt.Token) (interface{}, error) {
		return keys, nil
	})
	if err != nil {
		return false
	}
	if !token.Valid {
		return false
	}
	_, ok := token.Claims.(*jwt.RegisteredClaims)
	return ok
}

func BenchmarkRS256VerifyRotation(b *testing.B) {
	// prepare keys
	keyData, err := ioutil.ReadFile("test/sample_key")
	if err != nil {
		b.Fatalf("Unable to load rsa private key from disk: %v", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		b.Fatalf("Unable to parse rsa private key: %v", err)
	}

	keyData, err = ioutil.ReadFile("test/sample_key.pub")
	if err != nil {
		b.Fatalf("Unable to load rsa public key from disk: %v", err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		b.Fatalf("Unable to parse rsa public key: %v", err)
	}
	wrongKey1, err := jwt.ParseRSAPublicKeyFromPEM([]byte(wrongRSAPubKeyData1))
	if err != nil {
		b.Fatalf("Unable to parse wrong rsa public key 1: %v", err)
	}
	wrongKey2, err := jwt.ParseRSAPublicKeyFromPEM([]byte(wrongRSAPubKeyData2))
	if err != nil {
		b.Fatalf("Unable to parse wrong rsa public key 2: %v", err)
	}
	keys := []*rsa.PublicKey{wrongKey1, wrongKey2, key}

	// prepare the payloads
	now := time.Now()
	after := jwt.NewNumericDate(now.Add(time.Hour))
	goodClaim := &jwt.RegisteredClaims{
		ExpiresAt: after,
	}
	before := jwt.NewNumericDate(now.Add(-time.Hour))
	expiredClaim := &jwt.RegisteredClaims{
		ExpiresAt: before,
	}

	goodPayload, err := (&jwt.Token{
		Raw:    "foo",
		Method: jwt.SigningMethodRS256,
		Claims: goodClaim,
		Header: map[string]interface{}{
			"alg": "RS256",
		},
	}).SignedString(privateKey)
	if err != nil {
		b.Fatalf("Unable to sign the good payload: %v", err)
	}

	expiredPayload, err := (&jwt.Token{
		Raw:    "foo",
		Method: jwt.SigningMethodRS256,
		Claims: expiredClaim,
		Header: map[string]interface{}{
			"alg": "RS256",
		},
	}).SignedString(privateKey)
	if err != nil {
		b.Fatalf("Unable to sign the good payload: %v", err)
	}

	for _, c := range []struct {
		label   string
		payload string
		valid   bool
	}{
		{
			label:   "good",
			payload: goodPayload,
			valid:   true,
		},
		{
			label:   "expired",
			payload: expiredPayload,
			valid:   false,
		},
	} {
		b.Run(c.label, func(b *testing.B) {
			for _, f := range []struct {
				label string
				f     func(payload string, keys []*rsa.PublicKey) bool
			}{
				{
					label: "manual",
					f:     validateWithManualRotation,
				},
				{
					label: "native",
					f:     validateWithNativeRotation,
				},
			} {
				b.Run(f.label, func(b *testing.B) {
					b.ReportAllocs()

					got := f.f(c.payload, keys)
					if got != c.valid {
						b.Fatalf("got %v, want %v", got, c.valid)
					}

					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							f.f(c.payload, keys)
						}
					})
				})
			}
		})
	}
}
