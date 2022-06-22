package jwe

import "crypto/rand"

func generateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
