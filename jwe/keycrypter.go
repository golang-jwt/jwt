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

var KeyAlgorithmRSAOAEP = KeyAlgorithm("RSA-OAEP")

type rsaEncrypter struct {
	key *rsa.PublicKey
}

func (r *rsaEncrypter) Encrypt(cek []byte, alg KeyAlgorithm) ([]byte, error) {
	switch alg {
	case KeyAlgorithmRSAOAEP:
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, r.key, cek, []byte{})
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

type rsaDecrypter struct {
	key *rsa.PrivateKey
}

func (r *rsaDecrypter) Decrypt(encryptedKey []byte, alg KeyAlgorithm) ([]byte, error) {
	switch alg {
	case KeyAlgorithmRSAOAEP:
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, r.key, encryptedKey, []byte{})
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

func createEncrypter(key interface{}) (*rsaEncrypter, error) {
	switch pbk := key.(type) {
	case *rsa.PublicKey:
		return &rsaEncrypter{
			key: pbk,
		}, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

func createDecrypter(key interface{}) (*rsaDecrypter, error) {
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		return &rsaDecrypter{
			key: pk,
		}, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}
