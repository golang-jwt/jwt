package jwt

import (
	"sync"
)

var signingMethods = map[string]func() SigningMethod{}
var signingMethodLock = new(sync.RWMutex)

// SigningMethod can be used add new methods for signing or verifying tokens.
type SigningMethod interface {
	Verify(signingString, signature string, key interface{}) error // Returns nil if signature is valid
	Sign(signingString string, key interface{}) (string, error)    // Returns encoded signature or error
	Alg() string                                                   // returns the alg identifier for this method (example: 'HS256')
}

// Register internally creates a new function that returns the given
// SigningMethod. The function will be stored as a value in a thread safe map,
// where the algorithm name is the key.
func Register(m SigningMethod) {
	signingMethodLock.Lock()
	defer signingMethodLock.Unlock()
	signingMethods[m.Alg()] = func() SigningMethod { return m }
}

// RegisterSigningMethod will use the given algorithm name as the key
// and store the given function as the value.
// Deprecated: use the Register function instead
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethodLock.Lock()
	defer signingMethodLock.Unlock()
	signingMethods[alg] = f
}

// GetSigningMethod will return a SigningMethod from a given "alg" string.
// Returns nil if the algorithm name was not found.
func GetSigningMethod(alg string) SigningMethod {
	signingMethodLock.RLock()
	defer signingMethodLock.RUnlock()
	if methodF, ok := signingMethods[alg]; ok {
		return methodF()
	}
	return nil
}
