package jwt

type (
	signingMethodNone       struct{}
	unsafeNoneMagicConstant string
)

const UnsafeAllowNoneSignatureType unsafeNoneMagicConstant = "none signing method allowed"

var (
	// The none signing method is required by the spec, but you should probably never use it.
	SigningMethodNone                = newSigningMethodNone()
	NoneSignatureTypeDisallowedError = NewValidationError("'none' signature type is not allowed", ValidationErrorSignatureInvalid)
)

// newSigningMethodNone creates a new SigningMethodNone struct and
// registers it as a signing method.
func newSigningMethodNone() *signingMethodNone {
	m := &signingMethodNone{}
	Register(m)
	return m
}

func (m *signingMethodNone) Alg() string {
	return "none"
}

// Only allow 'none' alg type if UnsafeAllowNoneSignatureType is specified as the key
func (m *signingMethodNone) Verify(signingString, signature string, key interface{}) (err error) {
	// Key must be UnsafeAllowNoneSignatureType to prevent accidentally
	// accepting 'none' signing method
	if _, ok := key.(unsafeNoneMagicConstant); !ok {
		return NoneSignatureTypeDisallowedError
	}
	// If signing method is none, signature must be an empty string
	if signature != "" {
		return NewValidationError(
			"'none' signing method with non-empty signature",
			ValidationErrorSignatureInvalid,
		)
	}

	// Accept 'none' signing method.
	return nil
}

// Only allow 'none' signing if UnsafeAllowNoneSignatureType is specified as the key
func (m *signingMethodNone) Sign(signingString string, key interface{}) (string, error) {
	if _, ok := key.(unsafeNoneMagicConstant); ok {
		return "", nil
	}
	return "", NoneSignatureTypeDisallowedError
}
