package jwe

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// NewJWE creates a new JWE token.
// The plaintext will be encrypted with the method using a cek(Content Encryption Key).
// The cek will be encrypted with the alg using the key.
func NewJWE(alg KeyAlgorithm, key interface{}, method EncryptionType, plaintext []byte) (*jwe, error) {
	jwe := &jwe{}

	jwe.protected.Enc = method
	chipher, err := getCipher(method)
	if err != nil {
		return nil, err
	}

	// Generate a random Content Encryption Key (CEK).
	cek, err := generateKey(chipher.keySize)
	if err != nil {
		return nil, err
	}

	// Encrypt the CEK with the recipient's public key to produce the JWE Encrypted Key.
	jwe.protected.Alg = alg
	encrypter, err := createEncrypter(key)
	if err != nil {
		return nil, err
	}
	jwe.recipientKey, err = encrypter.Encrypt(cek, alg)
	if err != nil {
		return nil, err
	}

	// Serialize Authenticated Data
	rawProtected, err := json.Marshal(jwe.protected)
	if err != nil {
		return nil, err
	}
	rawProtectedBase64 := base64.RawURLEncoding.EncodeToString(rawProtected)

	// Perform authenticated encryption on the plaintext
	jwe.iv, jwe.ciphertext, jwe.tag, err = chipher.encrypt(cek, []byte(rawProtectedBase64), plaintext)
	if err != nil {
		return nil, err
	}

	return jwe, nil
}

type jwe struct {
	protected struct {
		Alg KeyAlgorithm   `json:"alg,omitempty"`
		Enc EncryptionType `json:"enc,omitempty"`
	}
	recipientKey []byte
	iv           []byte
	ciphertext   []byte
	tag          []byte
}

// CompactSerialize serialize JWE to compact form.
// https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
func (jwe *jwe) CompactSerialize() (string, error) {
	rawProtected, err := json.Marshal(jwe.protected)
	if err != nil {
		return "", err
	}

	protected := base64.RawURLEncoding.EncodeToString(rawProtected)
	encryptedKey := base64.RawURLEncoding.EncodeToString(jwe.recipientKey)
	iv := base64.RawURLEncoding.EncodeToString(jwe.iv)
	ciphertext := base64.RawURLEncoding.EncodeToString(jwe.ciphertext)
	tag := base64.RawURLEncoding.EncodeToString(jwe.tag)

	return strings.Join([]string{protected, encryptedKey, iv, ciphertext, tag}, "."), nil
}
