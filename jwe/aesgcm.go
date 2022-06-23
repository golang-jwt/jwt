package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

var (
	ErrInvalidKeySize            = errors.New("invalid key size")
	ErrInvalidTagSize            = errors.New("invalid tag size")
	ErrInvalidNonceSize          = errors.New("invalid nonce size")
	ErrUnsupportedEncryptionType = errors.New("unsupported encryption type")
)

const TagSizeAESGCM = 16

type EncryptionType string

var A256GCM = EncryptionType("A256GCM")

type cipherAESGCM struct {
	keySize int
	getAEAD func(key []byte) (cipher.AEAD, error)
}

func (ci cipherAESGCM) encrypt(key, aad, plaintext []byte) (iv []byte, ciphertext []byte, tag []byte, err error) {
	if len(key) != ci.keySize {
		return nil, nil, nil, ErrInvalidKeySize
	}

	aead, err := ci.getAEAD(key)
	if err != nil {
		return nil, nil, nil, err
	}

	iv = make([]byte, aead.NonceSize())
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, nil, err
	}

	res := aead.Seal(nil, iv, plaintext, aad)
	tagIndex := len(res) - TagSizeAESGCM

	return iv, res[:tagIndex], res[tagIndex:], nil
}

func (ci cipherAESGCM) decrypt(key, aad, iv []byte, ciphertext []byte, tag []byte) ([]byte, error) {
	if len(key) != ci.keySize {
		return nil, ErrInvalidKeySize
	}

	if len(tag) != TagSizeAESGCM {
		return nil, ErrInvalidTagSize
	}

	aead, err := ci.getAEAD(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aead.NonceSize() {
		return nil, ErrInvalidNonceSize
	}

	return aead.Open(nil, iv, append(ciphertext, tag...), aad)
}

func newAESGCM(keySize int) *cipherAESGCM {
	return &cipherAESGCM{
		keySize: keySize,
		getAEAD: func(key []byte) (cipher.AEAD, error) {
			aesCipher, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}

			return cipher.NewGCM(aesCipher)
		},
	}
}

func getCipher(alg EncryptionType) (*cipherAESGCM, error) {
	switch alg {
	case A256GCM:
		return newAESGCM(32), nil
	default:
		return nil, ErrUnsupportedEncryptionType
	}
}
