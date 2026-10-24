package jwt_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// TestNumericDate_RoundTrip is a regression test for
// https://github.com/golang-jwt/jwt/issues/536: marshalling a NumericDate
// and unmarshalling the result back used to lose a millisecond for about
// half of all sub-second values, because the float64 arithmetic used to
// reconstruct the timestamp in newNumericDateFromSeconds could land a
// fraction of a nanosecond below the intended value and then get truncated
// away instead of rounded.
func TestNumericDate_RoundTrip(t *testing.T) {
	oldPrecision := jwt.TimePrecision
	t.Cleanup(func() {
		jwt.TimePrecision = oldPrecision
	})

	t.Run("every millisecond in a second", func(t *testing.T) {
		jwt.TimePrecision = time.Millisecond

		for ms := int64(0); ms < 1000; ms++ {
			want := time.Unix(1700000000, ms*int64(time.Millisecond))

			b, err := json.Marshal(jwt.NewNumericDate(want))
			if err != nil {
				t.Fatalf("ms=%d: Marshal: %s", ms, err)
			}

			var got jwt.NumericDate
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("ms=%d: Unmarshal(%s): %s", ms, b, err)
			}

			if !got.Equal(want) {
				t.Errorf("ms=%d: round-trip through %s produced %s, want %s", ms, b, got, want)
			}
		}
	})

	t.Run("exact issue #536 repro values", func(t *testing.T) {
		jwt.TimePrecision = time.Millisecond

		for _, ms := range []int64{123, 125, 100, 1} {
			want := time.Unix(1700000000, ms*int64(time.Millisecond))

			b, err := json.Marshal(jwt.NewNumericDate(want))
			if err != nil {
				t.Fatalf("ms=%d: Marshal: %s", ms, err)
			}

			var got jwt.NumericDate
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("ms=%d: Unmarshal(%s): %s", ms, b, err)
			}

			if !got.Equal(want) {
				t.Errorf("ms=%d: round-trip through %s produced %s, want %s", ms, b, got, want)
			}
		}
	})

	t.Run("every microsecond in a millisecond", func(t *testing.T) {
		jwt.TimePrecision = time.Microsecond

		for us := int64(0); us < 1000; us++ {
			want := time.Unix(1700000000, 123*int64(time.Millisecond)+us*int64(time.Microsecond))

			b, err := json.Marshal(jwt.NewNumericDate(want))
			if err != nil {
				t.Fatalf("us=%d: Marshal: %s", us, err)
			}

			var got jwt.NumericDate
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("us=%d: Unmarshal(%s): %s", us, b, err)
			}

			if !got.Equal(want) {
				t.Errorf("us=%d: round-trip through %s produced %s, want %s", us, b, got, want)
			}
		}
	})
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
