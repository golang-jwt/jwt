package jwt_test

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
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
