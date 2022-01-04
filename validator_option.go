package jwt

import "time"

// ValidatorOptions represents options that can be used for claims validation
type ValidatorOptions struct {
	Leeway time.Duration
}

func Validator() *ValidatorOptions {
	return &ValidatorOptions{}
}

// MergeValidatorOptions combines the given ValidatorOptions instances into a single ValidatorOptions
// in a last-one-wins fashion
func MergeValidatorOptions(opts ...*ValidatorOptions) *ValidatorOptions {
	v := Validator()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if opt.Leeway != 0 {
			v.Leeway = opt.Leeway
		}
	}
	return v
}
