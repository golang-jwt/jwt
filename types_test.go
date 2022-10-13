package jwt_test

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
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
		t.Errorf("Serialized format of numeric date mismatch. Expecting: %s  Got: %s", string(raw), string(b))
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
		t.Errorf("Serialized format of string array mismatch. Expecting: %s  Got: %s", string(expected), string(b))
	}

	jwt.MarshalSingleStringAsArray = true

	expected = `["test"]`

	b, err = json.Marshal(s)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if expected != string(b) {
		t.Errorf("Serialized format of string array mismatch. Expecting: %s  Got: %s", string(expected), string(b))
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

func TestNumericDate_UnmarshalJSON(t *testing.T) {
	// Do not run this test in parallel because it's changing
	// global state.
	oldPrecision := jwt.TimePrecision
	t.Cleanup(func() {
		jwt.TimePrecision = oldPrecision
	})

	tt := []struct {
		in        string
		want      time.Time
		precision time.Duration
	}{
		{"1171341224178364428", time.Unix(1171341224178364428, 0), time.Second},
		{"6177993877186497701", time.Unix(6177993877186497701, 0), time.Second},
		{"2972952087035143528", time.Unix(2972952087035143528, 0), time.Second},
		{"3726679734411825289", time.Unix(3726679734411825289, 0), time.Second},
		//
		{"1558047135914538388.01664915", time.Unix(1558047135914538388, 16649150), time.Nanosecond},
		{"6559213345742516891.991797301", time.Unix(6559213345742516891, 991797301), time.Nanosecond},
		{"5442511928169084612.389300587", time.Unix(5442511928169084612, 389300587), time.Nanosecond},
		{"7390680480197750952.11208761", time.Unix(7390680480197750952, 112087610), time.Nanosecond},
		//
		{"0.000000001", time.Unix(0, 1), time.Nanosecond},
		{"0.999999999", time.Unix(0, 999999999), time.Nanosecond},
		{"9223372036854775807.000000001", time.Unix(math.MaxInt64, 1), time.Nanosecond},
		{"9223372036854775807.999999999", time.Unix(math.MaxInt64, 999999999), time.Nanosecond},
	}

	for i, tc := range tt {
		jwt.TimePrecision = tc.precision
		by := []byte(tc.in)
		var got jwt.NumericDate
		err := json.Unmarshal(by, &got)
		if err != nil {
			t.Fatal(err)
		}
		want := jwt.NewNumericDate(tc.want)
		if got != *want {
			t.Errorf("[%d]: failed encoding: got %q want %q", i, got, want)
		}
	}
}
