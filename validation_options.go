package jwt

import "time"

// validator is magic
type validator struct {
	// Leeway to provide to the current time when validating time values
	leeway time.Duration
}
