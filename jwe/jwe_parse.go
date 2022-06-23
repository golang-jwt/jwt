package jwe

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

func ParseEncrypted(input string) (*jwe, error) {

	if strings.HasPrefix(input, "{") {
		return nil, errors.New("don't support full JWE")
	}

	return parseEncryptedCompact(input)
}

func parseEncryptedCompact(input string) (*jwe, error) {
	parts := strings.Split(input, ".")

	if len(parts) != 5 {
		return nil, errors.New("encrypted token contains an invalid number of segments")
	}

	jwe := &jwe{}

	rawProtected, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	if rawProtected == nil || len(rawProtected) == 0 {
		return nil, errors.New("protected headers are empty")
	}

	err = json.Unmarshal(rawProtected, &jwe.protected)
	if err != nil {
		return nil, errors.New("protected headers are not in JSON format")
	}

	jwe.recipientKey, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	jwe.iv, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	jwe.ciphertext, err = base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	jwe.tag, err = base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	return jwe, nil
}
