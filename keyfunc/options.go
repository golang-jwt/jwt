package keyfunc

import (
	"context"
	"net/http"
	"time"
)

// Options represents the configuration options for a JWKs.
//
// If RefreshInterval and or RefreshUnknownKID is not nil, then a background goroutine will be launched to refresh the
// remote JWKs under the specified circumstances.
//
// When using a background refresh goroutine, make sure to use RefreshRateLimit if paired with RefreshUnknownKID. Also
// make sure to end the background refresh goroutine with the JWKs.EndBackground method when it's no longer needed.
type Options struct {

	// Client is the HTTP client used to get the JWKs via HTTP.
	Client *http.Client

	// Ctx is the context for the keyfunc's background refresh. When the context expires or is canceled, the background
	// goroutine will end.
	Ctx context.Context

	// GivenKeys is a map of JWT key IDs, `kid`, to their given keys. If the JWKs has a background refresh goroutine,
	// these values persist across JWKs refreshes. By default, if the remote JWKs resource contains a key with the same
	// `kid` any given keys with the same `kid` will be overwritten by the keys from the remote JWKs. Use the
	// GivenKIDOverride option to flip this behavior.
	GivenKeys map[string]GivenKey

	// GivenKIDOverride will make a GivenKey override any keys with the same ID (`kid`) in the remote JWKs. The is only
	// effectual if GivenKeys is provided.
	GivenKIDOverride *bool

	// RefreshErrorHandler is a function that consumes errors that happen during a JWKs refresh. This is only effectual
	// if a background refresh goroutine is active.
	RefreshErrorHandler ErrorHandler

	// RefreshInterval is the duration to refresh the JWKs in the background via a new HTTP request. If this is not nil,
	// then a background goroutine will be used to refresh the JWKs once per the given interval. Make sure to call the
	// JWKs.EndBackground method to end this goroutine when it's no longer needed.
	RefreshInterval time.Duration

	// RefreshRateLimit limits the rate at which refresh requests are granted. Only one refresh request can be queued
	// at a time any refresh requests received while there is already a queue are ignored. It does not make sense to
	// have RefreshInterval's value shorter than this.
	RefreshRateLimit time.Duration

	// RefreshTimeout is the duration for the context timeout used to create the HTTP request for a refresh of the JWKs.
	// This defaults to one minute. This is only effectual if RefreshInterval is not nil.
	RefreshTimeout time.Duration

	// RefreshUnknownKID indicates that the JWKs refresh request will occur every time a kid that isn't cached is seen.
	// This is done through a background goroutine. Without specifying a RefreshInterval a malicious client could
	// self-sign X JWTs, send them to this service, then cause potentially high network usage proportional to X. Make
	// sure to call the JWKs.EndBackground method to end this goroutine when it's no longer needed.
	RefreshUnknownKID *bool
}

// applyOptions applies the given options to the given JWKs.
func applyOptions(jwks *JWKs, options Options) {
	if options.Client != nil {
		jwks.client = options.Client
	}
	if options.Ctx != nil {
		jwks.ctx, jwks.cancel = context.WithCancel(options.Ctx)
	}
	if options.GivenKeys != nil {
		if jwks.givenKeys == nil {
			jwks.givenKeys = make(map[string]GivenKey)
		}
		for kid, key := range options.GivenKeys {
			jwks.givenKeys[kid] = key
		}
	}
	if options.GivenKIDOverride != nil {
		jwks.givenKIDOverride = *options.GivenKIDOverride
	}
	if options.RefreshErrorHandler != nil {
		jwks.refreshErrorHandler = options.RefreshErrorHandler
	}
	if options.RefreshInterval != 0 {
		jwks.refreshInterval = options.RefreshInterval
	}
	if options.RefreshRateLimit != 0 {
		jwks.refreshRateLimit = options.RefreshRateLimit
	}
	if options.RefreshTimeout != 0 {
		jwks.refreshTimeout = options.RefreshTimeout
	}
	if options.RefreshUnknownKID != nil {
		jwks.refreshUnknownKID = *options.RefreshUnknownKID
	}
}
