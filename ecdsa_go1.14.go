//+build !go1.15

package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"math/bits"
)

// Implements the Sign method from SigningMethod
// For this signing method, key must be an ecdsa.PrivateKey struct
func (m *SigningMethodECDSA) Sign(signingString string, key interface{}) (string, error) {
	// Get the key
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return "", ErrInvalidKeyType
	}

	// Create the hasher
	if !m.Hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return r, s
	if r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil)); err == nil {
		curveBits := ecdsaKey.Curve.Params().BitSize

		if m.CurveBits != curveBits {
			return "", ErrInvalidKey
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		// We serialize the outputs (r and s) into big-endian byte arrays
		// padded with zeros on the left to make sure the sizes work out.
		// Output must be 2*keyBytes long.
		out := make([]byte, 2*keyBytes)
		fillBytesInt(r, out[0:keyBytes]) // r is assigned to the first half of output.
		fillBytesInt(s, out[keyBytes:])  // s is assigned to the second half of output.

		return EncodeSegment(out), nil
	} else {
		return "", err
	}
}

func fillBytesInt(x *big.Int, buf []byte) []byte {
	// Clear whole buffer. (This gets optimized into a memclr.)
	for i := range buf {
		buf[i] = 0
	}
	// The following is mostly copied from the original go source code - however it is the only way of doing this.

	// Start at the end of the buffer as x.Bits() is a little endian and work for wards
	i := len(buf)

	// Walk the words from x.Bits()
	for _, d := range x.Bits() {
		// Now each word is Uintsize (usually 64 bits) in length - but a byte is 8 bits so each byte must be split in Uintsize/8 slices
		for j := 0; j < (bits.UintSize / 8); j++ {
			// Move forward one step
			i--
			if i >= 0 {
				// set the value of the current buf[i] to the byte value of
				buf[i] = byte(d)
			} else if byte(d) != 0 {
				panic("math/big: buffer too small to fit value") // use the same panic string for complete compatibility
			}
			// shift the word 8 bits and reloop.
			d >>= 8
		}
	}

	return buf
}
