package jwe

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

func (jwe jwe) Decrypt(key interface{}) ([]byte, error) {

	method, ok := jwe.protected["enc"]
	if !ok {
		return nil, errors.New("no \"enc\" header")
	}
	cipher, err := getCipher(EncryptionType(method))
	if err != nil {
		return nil, err
	}

	alg, ok := jwe.protected["alg"]
	if !ok {
		return nil, errors.New("no \"alg\" header")
	}
	cek, err := decryptKey(key, jwe.recipientKey, KeyAlgorithm(alg))
	if err != nil {
		return nil, err
	}

	rawProtected, err := json.Marshal(jwe.protected)
	if err != nil {
		return nil, err
	}
	rawProtectedBase64 := base64.RawURLEncoding.EncodeToString(rawProtected)

	data, err := cipher.decrypt(cek, []byte(rawProtectedBase64), jwe.iv, jwe.ciphertext, jwe.tag)

	return data, err
}
