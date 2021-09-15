package keyfunc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (

	// ErrKIDNotFound indicates that the given key ID was not found in the JWKs.
	ErrKIDNotFound = errors.New("the given key ID was not found in the JWKs")

	// ErrMissingAssets indicates there are required assets missing to create a public key.
	ErrMissingAssets = errors.New("required assets are missing to create a public key")
)

// ErrorHandler is a function signature that consumes an error.
type ErrorHandler func(err error)

// jsonKey represents a raw key inside a JWKs.
type jsonKey struct {
	Curve       string `json:"crv"`
	Exponent    string `json:"e"`
	ID          string `json:"kid"`
	Modulus     string `json:"n"`
	X           string `json:"x"`
	Y           string `json:"y"`
	precomputed interface{}
}

// JWKs represents a JSON Web Key Set.
type JWKs struct { // It's JWKs, not JWKS https://datatracker.ietf.org/doc/html/rfc7517#section-2
	cancel              context.CancelFunc
	client              *http.Client
	ctx                 context.Context
	givenKeys           map[string]GivenKey
	givenKIDOverride    bool
	jwksURL             string
	keys                map[string]*jsonKey
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     *time.Duration
	refreshRateLimit    *time.Duration
	refreshRequests     chan context.CancelFunc
	refreshTimeout      *time.Duration
	refreshUnknownKID   bool
}

// rawJWKs represents a JWKs in JSON format.
type rawJWKs struct {
	Keys []jsonKey `json:"keys"`
}

// NewJSON creates a new JWKs from a raw JSON message.
func NewJSON(jwksBytes json.RawMessage) (jwks *JWKs, err error) {

	// Turn the raw JWKs into the correct Go type.
	var rawKS rawJWKs
	if err = json.Unmarshal(jwksBytes, &rawKS); err != nil {
		return nil, err
	}

	// Iterate through the keys in the raw JWKs. Add them to the JWKs.
	jwks = &JWKs{
		keys: make(map[string]*jsonKey, len(rawKS.Keys)),
	}
	for _, key := range rawKS.Keys {
		key := key
		jwks.keys[key.ID] = &key
	}

	return jwks, nil
}

// EndBackground ends the background goroutine to update the JWKs. It can only happen once and is only effective if the
// JWKs has a background goroutine refreshing the JWKs keys.
func (j *JWKs) EndBackground() {
	if j.cancel != nil {
		j.cancel()
	}
}

// getKey gets the jsonKey from the given KID from the JWKs. It may refresh the JWKs if configured to.
func (j *JWKs) getKey(kid string) (jsonKey *jsonKey, err error) {

	// Get the jsonKey from the JWKs.
	var ok bool
	j.mux.RLock()
	jsonKey, ok = j.keys[kid]
	j.mux.RUnlock()

	// Check if the key was present.
	if !ok {

		// Check to see if configured to refresh on unknown kid.
		if j.refreshUnknownKID {

			// Create a context for refreshing the JWKs.
			ctx, cancel := context.WithCancel(j.ctx)

			// Refresh the JWKs.
			select {
			case <-j.ctx.Done():
				return
			case j.refreshRequests <- cancel:
			default:

				// If the j.refreshRequests channel is full, return the error early.
				return nil, ErrKIDNotFound
			}

			// Wait for the JWKs refresh to done.
			<-ctx.Done()

			// Lock the JWKs for async safe use.
			j.mux.RLock()
			defer j.mux.RUnlock()

			// Check if the JWKs refresh contained the requested key.
			if jsonKey, ok = j.keys[kid]; ok {
				return jsonKey, nil
			}
		}

		return nil, ErrKIDNotFound
	}

	return jsonKey, nil
}
