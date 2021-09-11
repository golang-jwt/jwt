package jwt

import (
	"sync"
)

type signingMethodFunc = func() SigningMethod

var signingMethods = map[string]signingMethodFunc{}
var signingMethodsMutex = new(sync.Mutex)

// SigningMethod can be used add new methods for signing or verifying tokens.
type SigningMethod interface {
	Verify(signingString, signature string, key interface{}) error // Returns nil if signature is valid
	Sign(signingString string, key interface{}) (string, error)    // Returns encoded signature or error
	Alg() string                                                   // returns the alg identifier for this method (example: 'HS256')
}

// RegisterSigningMethod registers the "alg" name and a factory function for signing method.
// This is typically done during init() in the method's implementation
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethodsMutex.Lock()
	defer signingMethodsMutex.Unlock()
	copy := map[string]signingMethodFunc{}
	for k, sm := range signingMethods {
		copy[k] = sm
	}
	copy[alg] = f
	signingMethods = copy
}

// GetSigningMethod retrieves a signing method from an "alg" string
func GetSigningMethod(alg string) SigningMethod {
	if methodF, ok := signingMethods[alg]; ok {
		return methodF()
	}
	return nil
}
