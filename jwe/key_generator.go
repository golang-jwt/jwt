package jwe

import (
	"crypto/rand"
	"io"
)

var RandReader = rand.Reader

func generateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)

	_, err := io.ReadFull(RandReader, key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
