package jwe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
)

var (
	ErrUnsupportedKeyType      = errors.New("unsupported key type")
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key algorithm")
)

type KeyAlgorithm string

var RSA_OAEP = KeyAlgorithm("RSA-OAEP")

func rsaEncrypt(key *rsa.PublicKey, cek []byte, alg KeyAlgorithm) ([]byte, error) {
	switch alg {
	case RSA_OAEP:
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, key, cek, []byte{})
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

func rsaDecrypt(key *rsa.PrivateKey, encryptedKey []byte, alg KeyAlgorithm) ([]byte, error) {
	switch alg {
	case RSA_OAEP:
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, key, encryptedKey, []byte{})
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

func encryptKey(key interface{}, cek []byte, alg KeyAlgorithm) ([]byte, error) {
	switch pbk := key.(type) {
	case *rsa.PublicKey:
		return rsaEncrypt(pbk, cek, alg)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

func decryptKey(key interface{}, encryptedKey []byte, alg KeyAlgorithm) ([]byte, error) {
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		return rsaDecrypt(pk, encryptedKey, alg)
	default:
		return nil, ErrUnsupportedKeyType
	}
}
