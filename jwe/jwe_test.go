package jwe_test

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/jwe"
	"os"
	"testing"
)

func TestParseEncrypted(t *testing.T) {
	originalToken := "eyJoZWFkZXIiOiJ2YWx1ZSJ9.ZW5jcnlwdGVkS2V5.aXY.Y2lwaGVydGV4dA.dGFn"

	jweToken, err := jwe.ParseEncrypted(originalToken)

	if err != nil {
		t.Error(err)
		return
	}

	rawToken, err := jweToken.CompactSerialize()
	if err != nil {
		t.Error(err)
		return
	}

	if rawToken != originalToken {
		t.Error(fmt.Errorf("tokens are different: %s != %s", rawToken, originalToken))
	}
}

func TestLifeCycle(t *testing.T) {
	keyData, _ := os.ReadFile("../test/sample_key.pub")
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	originalText := "The true sign of intelligence is not knowledge but imagination."
	token, err := jwe.NewJWE(jwe.RSA_OAEP, key, jwe.A256GCM, []byte(originalText))

	if err != nil {
		t.Error(err)
		return
	}

	privKeyData, _ := os.ReadFile("../test/sample_key")
	privKey, _ := jwt.ParseRSAPrivateKeyFromPEM(privKeyData)

	text, err := token.Decrypt(privKey)
	if err != nil {
		t.Error(err)
		return
	}

	if string(text) != originalText {
		t.Error(fmt.Errorf("texts are different: %s != %s", string(text), originalText))
	}
}
