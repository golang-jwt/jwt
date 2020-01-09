package jwt_test

import (
	"crypto"
	"crypto/ed25519"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

var ed25519TestData = []struct {
	name        string
	keys        map[string]string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic Ed25519",
		map[string]string{"private": "test/ed25519-private.pem", "public": "test/ed25519-public.pem"},
		"eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw",
		"EdDSA",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic Ed25519",
		map[string]string{"private": "test/ed25519-private.pem", "public": "test/ed25519-public.pem"},
		"eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXoifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw",
		"EdDSA",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestEd25519Verify(t *testing.T) {
	// This is a different ed25519 pub key from the one that can be used to verify
	// the data.
	const wrongPubKeyData = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADXYgR79f8XWn19vwmxtYb/H4hFiaQDBm1xUsgaqr/3Q=
-----END PUBLIC KEY-----`

	for _, data := range ed25519TestData {
		var err error

		key, _ := ioutil.ReadFile(data.keys["public"])

		ed25519Key, err := jwt.ParseEdPublicKeyFromPEM(key)
		if err != nil {
			t.Errorf("Unable to parse Ed25519 public key: %v", err)
		}

		parts := strings.Split(data.tokenString, ".")

		method := jwt.GetSigningMethod(data.alg)

		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], ed25519Key)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}

		// test key rotations
		invalidKey, err := jwt.ParseEdPublicKeyFromPEM([]byte(wrongPubKeyData))
		if err != nil {
			t.Errorf("Unable to parse wrong Ed25519 public key: %v", err)
		}

		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], []ed25519.PublicKey{})
		if err == nil {
			t.Errorf("[%v] Empty keys passed validation", data.name)
		}

		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], []ed25519.PublicKey{invalidKey.(ed25519.PublicKey)})
		if err == nil {
			t.Errorf("[%v] Invalid keys passed validation", data.name)
		}

		if !data.valid {
			continue
		}

		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], []ed25519.PublicKey{
			invalidKey.(ed25519.PublicKey),
			ed25519Key.(ed25519.PublicKey),
		})
		if err != nil {
			t.Errorf("[%v] Error while verifying invalid+valid ed25519 keys: %v", data.name, err)
		}

		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], []crypto.PublicKey{
			invalidKey,
			ed25519Key,
		})
		if err != nil {
			t.Errorf("[%v] Error while verifying invalid+valid crypto keys: %v", data.name, err)
		}
	}
}

func TestEd25519Sign(t *testing.T) {
	for _, data := range ed25519TestData {
		var err error
		key, _ := ioutil.ReadFile(data.keys["private"])

		ed25519Key, err := jwt.ParseEdPrivateKeyFromPEM(key)
		if err != nil {
			t.Errorf("Unable to parse Ed25519 private key: %v", err)
		}

		parts := strings.Split(data.tokenString, ".")

		method := jwt.GetSigningMethod(data.alg)

		sig, err := method.Sign(strings.Join(parts[0:2], "."), ed25519Key)
		if err != nil {
			t.Errorf("[%v] Error signing token: %v", data.name, err)
		}
		if sig == parts[2] && !data.valid {
			t.Errorf("[%v] Identical signatures\nbefore:\n%v\nafter:\n%v", data.name, parts[2], sig)
		}
	}
}
