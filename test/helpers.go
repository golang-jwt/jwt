package test

import (
	"crypto"
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

func LoadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

// MakeSampleToken creates and returns a encoded JWT token that has been signed with the specified cryptographic key.
func MakeSampleToken(c jwt.Claims, method jwt.SigningMethod, key interface{}) string {
	token := jwt.NewWithClaims(method, c)
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

func LoadECPrivateKeyFromDisk(location string) crypto.PrivateKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseECPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadECPublicKeyFromDisk(location string) crypto.PublicKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseECPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}
