package jwt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// TimePrecision sets the precision of times and dates within this library.
// This has an influence on the precision of times when comparing expiry or
// other related time fields. Furthermore, it is also the precision of times
// when serializing.
//
// For backwards compatibility the default precision is set to seconds, so that
// no fractional timestamps are generated.
//
// TODO(oxisto): the tests seem to fail sometimes, if the precision is microseconds because the difference is literally 1 microsecond
var TimePrecision = time.Second

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

// NewNumericDate constructs a new *NumericDate from a standard library time.Time struct.
// It will truncate the timestamp according to the precision specified in TimePrecision.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.Truncate(TimePrecision)}
}

// newNumericDateFromSeconds creates a new *NumericDate out of a float64 representing a
// UNIX epoch with the float fraction representing non-integer seconds.
func newNumericDateFromSeconds(f float64) *NumericDate {
	return NewNumericDate(time.Unix(0, int64(f*float64(time.Second))))
}

// MarshalJSON is an implementation of the json.RawMessage interface and serializes the UNIX epoch
// represented in NumericDate to a byte array, using the precision specified in TimePrecision.
func (date NumericDate) MarshalJSON() (b []byte, err error) {
	f := float64(date.Truncate(TimePrecision).UnixNano()) / float64(time.Second)

	return []byte(strconv.FormatFloat(f, 'f', -1, 64)), nil
}

// UnmarshalJSON is an implementation of the json.RawMessage interface and deserializses a
// NumericDate from a JSON representation, i.e. a json.Number. This number represents an UNIX epoch
// with either integer or non-integer seconds.
func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var (
		number json.Number
		f      float64
	)

	if err = json.Unmarshal(b, &number); err != nil {
		// TODO(oxisto): Once we are on Go 1.13+, we should use %w instead of %s here
		return fmt.Errorf("could not parse NumericData: %s", err)
	}

	if f, err = number.Float64(); err != nil {
		// TODO(oxisto): Once we are on Go 1.13+, we should use %w instead of %s here
		return fmt.Errorf("could not convert json number value to float: %s", err)
	}

	n := newNumericDateFromSeconds(f)
	*date = *n

	return nil
}
