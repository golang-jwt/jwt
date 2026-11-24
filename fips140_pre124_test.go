//go:build !go1.24

package jwt_test

func fips140Enabled() bool {
	return false
}
