package jwt

import "errors"

// SigningMethodNone implements the none signing method.  This is required by the spec
// but you probably should never use it.
var SigningMethodNone *signingMethodNone

const UnsafeAllowNoneSignatureType unsafeNoneMagicConstant = "none signing method allowed"

// var NoneSignatureTypeDisallowedError error

type signingMethodNone struct{}
type unsafeNoneMagicConstant string

func init() {
	SigningMethodNone = &signingMethodNone{}
	RegisterSigningMethod(SigningMethodNone.Alg(), func() SigningMethod {
		return SigningMethodNone
	})
}

func (m *signingMethodNone) Alg() string {
	return "none"
}

// Only allow 'none' alg type if UnsafeAllowNoneSignatureType is specified as the key
func (m *signingMethodNone) Verify(signingString, signature string, key interface{}) (err error) {
	// Key must be UnsafeAllowNoneSignatureType to prevent accidentally
	// accepting 'none' signing method
	if _, ok := key.(unsafeNoneMagicConstant); !ok {
		return ErrNoneSignatureTypeDisallowed
	}
	// If signing method is none, signature must be an empty string
	if signature != "" {
		return errors.New(`jwt: if signing method is "none", signature must be an empty string`)
	}
	// Accept 'none' signing method.
	return nil
}

// Only allow 'none' signing if UnsafeAllowNoneSignatureType is specified as the key
func (m *signingMethodNone) Sign(signingString string, key interface{}) (string, error) {
	if _, ok := key.(unsafeNoneMagicConstant); ok {
		return "", nil
	}
	return "", ErrNoneSignatureTypeDisallowed
}
