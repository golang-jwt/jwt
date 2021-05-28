package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestNumericDate(t *testing.T) {
	var s struct {
		Iat jwt.NumericDate `json:"iat"`
		Exp jwt.NumericDate `json:"exp"`
	}

	err := json.Unmarshal([]byte(`{"iat": 1516239022, "exp": 1516239022.1234567}`), &s)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	fmt.Printf("%+v", s)
}
