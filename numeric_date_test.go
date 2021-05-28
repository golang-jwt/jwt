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

	raw := `{"iat":1516239022,"exp":1516239022.123456}`

	err := json.Unmarshal([]byte(raw), &s)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	fmt.Printf("%+v\n", s)

	b, _ := json.Marshal(s)

	fmt.Printf("%s\n", string(raw))
	fmt.Printf("%s\n", string(b))

	if raw != string(b) {
		t.Errorf("Serialized format of numeric date mismatch. Expecting: %s  Got: %s", string(raw), string(b))
	}
}
