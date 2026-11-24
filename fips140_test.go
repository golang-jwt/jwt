//go:build go1.24
// +build go1.24

package jwt_test

import "crypto/fips140"

func fips140Enabled() bool {
	return fips140.Enabled()
}
