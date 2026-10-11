package jwt_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNumericDate(t *testing.T) {
	var s struct {
		Iat jwt.NumericDate `json:"iat"`
		Exp jwt.NumericDate `json:"exp"`
	}

	oldPrecision := jwt.TimePrecision

	jwt.TimePrecision = time.Microsecond

	raw := `{"iat":1516239022.000000,"exp":1516239022.123450}`

	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	b, _ := json.Marshal(s)

	if raw != string(b) {
		t.Errorf("Serialized format of numeric date mismatch. Expecting: %s  Got: %s", raw, string(b))
	}

	jwt.TimePrecision = oldPrecision
}

func TestSingleArrayMarshal(t *testing.T) {
	jwt.MarshalSingleStringAsArray = false

	s := jwt.ClaimStrings{"test"}
	expected := `"test"`

	b, err := json.Marshal(s)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if expected != string(b) {
		t.Errorf("Serialized format of string array mismatch. Expecting: %s  Got: %s", expected, string(b))
	}

	jwt.MarshalSingleStringAsArray = true

	expected = `["test"]`

	b, err = json.Marshal(s)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if expected != string(b) {
		t.Errorf("Serialized format of string array mismatch. Expecting: %s  Got: %s", expected, string(b))
	}
}

func TestNumericDate_MarshalJSON(t *testing.T) {
	// Do not run this test in parallel because it's changing
	// global state.
	oldPrecision := jwt.TimePrecision
	t.Cleanup(func() {
		jwt.TimePrecision = oldPrecision
	})

	tt := []struct {
		in        time.Time
		want      string
		precision time.Duration
	}{
		{time.Unix(5243700879, 0), "5243700879", time.Second},
		{time.Unix(5243700879, 0), "5243700879.000", time.Millisecond},
		{time.Unix(5243700879, 0), "5243700879.000000", time.Microsecond},
		{time.Unix(5243700879, 0), "5243700879.000000000", time.Nanosecond},
		//
		{time.Unix(4239425898, 0), "4239425898", time.Second},
		{time.Unix(4239425898, 0), "4239425898.000", time.Millisecond},
		{time.Unix(4239425898, 0), "4239425898.000000", time.Microsecond},
		{time.Unix(4239425898, 0), "4239425898.000000000", time.Nanosecond},
		//
		{time.Unix(253402271999, 0), "253402271999", time.Second},
		{time.Unix(253402271999, 0), "253402271999.000", time.Millisecond},
		{time.Unix(253402271999, 0), "253402271999.000000", time.Microsecond},
		{time.Unix(253402271999, 0), "253402271999.000000000", time.Nanosecond},
		//
		{time.Unix(0, 1644285000210402000), "1644285000", time.Second},
		{time.Unix(0, 1644285000210402000), "1644285000.210", time.Millisecond},
		{time.Unix(0, 1644285000210402000), "1644285000.210402", time.Microsecond},
		{time.Unix(0, 1644285000210402000), "1644285000.210402000", time.Nanosecond},
		//
		{time.Unix(0, 1644285315063096000), "1644285315", time.Second},
		{time.Unix(0, 1644285315063096000), "1644285315.063", time.Millisecond},
		{time.Unix(0, 1644285315063096000), "1644285315.063096", time.Microsecond},
		{time.Unix(0, 1644285315063096000), "1644285315.063096000", time.Nanosecond},
		// Maximum time that a go time.Time can represent
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807", time.Second},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807.999", time.Millisecond},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807.999999", time.Microsecond},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807.999999999", time.Nanosecond},
		// Strange precisions
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807", time.Second},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775756", time.Minute},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854774016", time.Hour},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854745216", 24 * time.Hour},
	}

	for i, tc := range tt {
		jwt.TimePrecision = tc.precision
		by, err := jwt.NewNumericDate(tc.in).MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if got := string(by); got != tc.want {
			t.Errorf("[%d]: failed encoding: got %q want %q", i, got, tc.want)
		}
	}
}

func TestGetSignatureAfterSigning(t *testing.T) {
	token := jwt.New(jwt.SigningMethodHS256, nil)
	signedString, err := token.SignedString([]byte("test12345"))
	if err != nil {
		t.Fatal(err)
	}

	sigStr := signedString[strings.LastIndex(signedString, ".")+1:]
	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sig, token.Signature) {
		t.Errorf("token.Signature not equal to signature in signed string")
	}
}

func TestNumericDate_RoundtripMillisecondPrecision(t *testing.T) {
	oldPrecision := jwt.TimePrecision
	t.Cleanup(func() {
		jwt.TimePrecision = oldPrecision
	})

	jwt.TimePrecision = time.Millisecond

	// Specific cases reported in issue #536
	specificCases := []int64{123, 125, 100, 1, 0, 999}
	for _, ms := range specificCases {
		expected := time.Unix(1700000000, ms*int64(time.Millisecond))
		data, err := json.Marshal(jwt.NewNumericDate(expected))
		if err != nil {
			t.Fatalf("failed to marshal NumericDate (%d ms): %v", ms, err)
		}

		var actual jwt.NumericDate
		if err := json.Unmarshal(data, &actual); err != nil {
			t.Fatalf("failed to unmarshal NumericDate (%d ms): %v", ms, err)
		}

		if !actual.Equal(expected) {
			t.Errorf("round-trip mismatch for %d ms: got %v (%s), want %v", ms, actual.Time, string(data), expected)
		}
	}

	// Full sweep across all 1000 millisecond fractions of a second
	for ms := int64(0); ms < 1000; ms++ {
		expected := time.Unix(1700000000, ms*int64(time.Millisecond))
		data, err := json.Marshal(jwt.NewNumericDate(expected))
		if err != nil {
			t.Fatalf("failed to marshal NumericDate (%d ms): %v", ms, err)
		}

		var actual jwt.NumericDate
		if err := json.Unmarshal(data, &actual); err != nil {
			t.Fatalf("failed to unmarshal NumericDate (%d ms): %v", ms, err)
		}

		if !actual.Equal(expected) {
			t.Fatalf("round-trip mismatch for %d ms: got %v (%s), want %v", ms, actual.Time, string(data), expected)
		}
	}
}

func TestNumericDate_RoundtripSubsecondPrecisions(t *testing.T) {
	oldPrecision := jwt.TimePrecision
	t.Cleanup(func() {
		jwt.TimePrecision = oldPrecision
	})

	testCases := []struct {
		name      string
		precision time.Duration
		samples   []time.Time
	}{
		{
			name:      "microsecond",
			precision: time.Microsecond,
			samples: []time.Time{
				time.Unix(1700000000, 123456*int64(time.Microsecond)),
				time.Unix(1700000000, 100*int64(time.Microsecond)),
				time.Unix(1700000000, 1*int64(time.Microsecond)),
				time.Unix(1700000000, 999999*int64(time.Microsecond)),
				time.Unix(1700000000, 0),
			},
		},
		{
			name:      "nanosecond",
			precision: time.Nanosecond,
			samples: []time.Time{
				time.Unix(1700000000, 123456789),
				time.Unix(1700000000, 100),
				time.Unix(1700000000, 1),
				time.Unix(1700000000, 999999999),
				time.Unix(1700000000, 0),
			},
		},
		{
			name:      "negative timestamps",
			precision: time.Millisecond,
			samples: []time.Time{
				time.Unix(-1700000000, -123*int64(time.Millisecond)),
				time.Unix(-1700000000, -125*int64(time.Millisecond)),
				time.Unix(-1700000000, -100*int64(time.Millisecond)),
				time.Unix(-1700000000, -1*int64(time.Millisecond)),
				time.Unix(-1, -500*int64(time.Millisecond)),
				time.Unix(0, -123*int64(time.Millisecond)),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwt.TimePrecision = tc.precision
			for _, expected := range tc.samples {
				data, err := json.Marshal(jwt.NewNumericDate(expected))
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}

				var actual jwt.NumericDate
				if err := json.Unmarshal(data, &actual); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}

				if !actual.Equal(expected) {
					t.Errorf("round-trip mismatch: got %v (%s), want %v", actual.Time, string(data), expected)
				}
			}
		})
	}
}

func TestNumericDate_MapClaimsPrecision(t *testing.T) {
	oldPrecision := jwt.TimePrecision
	t.Cleanup(func() {
		jwt.TimePrecision = oldPrecision
	})

	jwt.TimePrecision = time.Millisecond

	for _, ms := range []int64{123, 125, 100, 1} {
		expected := time.Unix(1700000000, ms*int64(time.Millisecond))
		jsonStr := []byte(fmt.Sprintf(`{"exp":1700000000.%03d}`, ms))

		// 1. Unmarshal into MapClaims (default float64)
		var claims jwt.MapClaims
		if err := json.Unmarshal(jsonStr, &claims); err != nil {
			t.Fatalf("failed to unmarshal MapClaims: %v", err)
		}

		exp, err := claims.GetExpirationTime()
		if err != nil {
			t.Fatalf("failed to get expiration time: %v", err)
		}

		if !exp.Equal(expected) {
			t.Errorf("MapClaims float64 precision mismatch for %d ms: got %v, want %v", ms, exp.Time, expected)
		}

		// 2. Unmarshal with UseNumber (json.Number)
		var claimsNumber jwt.MapClaims
		dec := json.NewDecoder(bytes.NewReader(jsonStr))
		dec.UseNumber()
		if err := dec.Decode(&claimsNumber); err != nil {
			t.Fatalf("failed to decode MapClaims with UseNumber: %v", err)
		}

		expNumber, err := claimsNumber.GetExpirationTime()
		if err != nil {
			t.Fatalf("failed to get expiration time with UseNumber: %v", err)
		}

		if !expNumber.Equal(expected) {
			t.Errorf("MapClaims json.Number precision mismatch for %d ms: got %v, want %v", ms, expNumber.Time, expected)
		}
	}
}

