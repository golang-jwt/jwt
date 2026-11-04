//go:build !go1.27

package jwt_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestMLDSAUnavailable(t *testing.T) {
	for _, alg := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		if jwt.GetSigningMethod(alg) != nil {
			t.Errorf("%s is registered before Go 1.27", alg)
		}
	}
}
