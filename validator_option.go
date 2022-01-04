package jwt

import "time"

// ValidatorOptions represents options that can be used for claims validation
type ValidatorOptions struct {
	leeway time.Duration  // Leeway to provide when validating time values
}

func Validator() *ValidatorOptions {
	return &ValidatorOptions{}
}

func (v *ValidatorOptions) SetLeeway(d time.Duration) {
	v.leeway = d
}

// MergeValidatorOptions combines the given ValidatorOptions instances into a single ValidatorOptions
// in a last-one-wins fashion
func MergeValidatorOptions(opts ...*ValidatorOptions) *ValidatorOptions {
	v := Validator()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if opt.leeway != 0 {
			v.SetLeeway(opt.leeway)
		}
	}
	return v
}
