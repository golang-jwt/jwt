package jwe

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

func (jwe jwe) Decrypt(key interface{}) ([]byte, error) {

	method := jwe.protected.Enc
	if len(method) == 0 {
		return nil, errors.New("no \"enc\" header")
	}
	cipher, err := getCipher(EncryptionType(method))
	if err != nil {
		return nil, err
	}

	alg := jwe.protected.Alg
	if len(alg) == 0 {
		return nil, errors.New("no \"alg\" header")
	}
	decrypter, err := createDecrypter(key)
	if err != nil {
		return nil, err
	}
	// Decrypt JWE Encrypted Key with the recipient's private key to produce CEK.
	cek, err := decrypter.Decrypt(jwe.recipientKey, alg)
	if err != nil {
		return nil, err
	}

	// Serialize Authenticated Data
	rawProtected, err := json.Marshal(jwe.protected)
	if err != nil {
		return nil, err
	}
	rawProtectedBase64 := base64.RawURLEncoding.EncodeToString(rawProtected)

	// Perform authenticated decryption on the ciphertext
	data, err := cipher.decrypt(cek, []byte(rawProtectedBase64), jwe.iv, jwe.ciphertext, jwe.tag)

	return data, err
}
