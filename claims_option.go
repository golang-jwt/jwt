package jwt

import "time"

// ClaimsValidationOptions represents options that can be used for claims validation
type ClaimsValidationOptions struct {
	Leeway time.Duration
}

func ClaimsValidation() *ClaimsValidationOptions {
	return &ClaimsValidationOptions{}
}

func (c *ClaimsValidationOptions) SetClockSkew(d time.Duration) {
	c.Leeway = d
}

// MergeClaimsValidationOptions combines the given ClaimsValidationOptions instancs into a single ClaimsValidationOptions
// in a last-one-wins fashion
func MergeClaimsValidationOptions(opts ...*ClaimsValidationOptions) *ClaimsValidationOptions {
	c := ClaimsValidation()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if opt.Leeway != 0 {
			c.Leeway = opt.Leeway
		}
	}
	return c
}
