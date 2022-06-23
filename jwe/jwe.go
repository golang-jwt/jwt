package jwe

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func NewJWE(alg KeyAlgorithm, key interface{}, method EncryptionType, plaintext []byte) (*jwe, error) {
	jwe := &jwe{}

	jwe.protected = make(map[string]string)
	jwe.protected["enc"] = string(method)
	chipher, err := getCipher(method)
	if err != nil {
		return nil, err
	}

	cek, err := generateKey(chipher.keySize)
	if err != nil {
		return nil, err
	}

	jwe.protected["alg"] = string(alg)
	jwe.recipientKey, err = encryptKey(key, cek, alg)
	if err != nil {
		return nil, err
	}

	rawProtected, err := json.Marshal(jwe.protected)
	if err != nil {
		return nil, err
	}
	rawProtectedBase64 := base64.RawURLEncoding.EncodeToString(rawProtected)

	jwe.iv, jwe.ciphertext, jwe.tag, err = chipher.encrypt(cek, []byte(rawProtectedBase64), plaintext)
	if err != nil {
		return nil, err
	}

	return jwe, nil
}

type jwe struct {
	protected    map[string]string
	recipientKey []byte
	iv           []byte
	ciphertext   []byte
	tag          []byte
}

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
