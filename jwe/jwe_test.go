package jwe_test

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4/jwe"
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
