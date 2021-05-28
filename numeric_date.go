package jwt

import (
	"encoding/json"
	"fmt"
	"time"
)

// TimePrecision sets the precision of times and dates within this library.
// This has an influence on the precision of times when comparing expiry or
// other related time fields. Furthermore, it is also the precision of times
// when serializing.

// TODO(oxisto): the tests seem to fail sometimes, if the precision is microseconds because the difference is literally 1 microsecond
var TimePrecision = time.Second

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

func FromTime(t time.Time) *NumericDate {
	return &NumericDate{t.Truncate(TimePrecision)}
}

func NewNumericDate(f float64) *NumericDate {
	return FromTime(time.Unix(0, int64(f*float64(time.Second))))
}

func (date NumericDate) MarshalJSON() (b []byte, err error) {
	f := float64(date.Truncate(TimePrecision).UnixNano()) / float64(time.Second)

	return json.Marshal(f)
}

func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var number json.Number

	if err = json.Unmarshal(b, &number); err != nil {
		// TODO(oxisto): Once we are on Go 1.13+, we should use %w here
		return fmt.Errorf("could not parse NumericData: %s", err)
	}

	f, _ := number.Float64()
	n := NewNumericDate(f)
	*date = *n

	return nil
}
