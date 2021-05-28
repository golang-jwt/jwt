package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// TimePrecision sets the precision of times and dates within this library.
// This has an influence on the precision of times when comparing expiry or
// other related time fields. Furthermore, it is also the precision of times
// when serializing.
var TimePrecision = time.Microsecond

// NumericDate represents a JSON numeric value, as referenced at
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

	// since this can be a non-integer, we parse it as float and construct a time.Time object out if
	if err = json.Unmarshal(b, &number); err != nil {
		// TODO(oxisto): This makes use of the new errors API introduced in 1.13, might need to remove it again
		return fmt.Errorf("could not parse NumericData: %w", err)
	}

	f, _ := number.Float64()
	n := NewNumericDate(f)
	*date = *n

	return nil
}

func timeFromFloat(f float64) time.Time {
	var (
		seconds float64
		frac    float64
	)

	seconds, frac = math.Modf(f)

	fmt.Printf("f: %f, sec: %f, frac: %f, nsec: %d, converted: %d\n", f, seconds, frac, int64(frac*float64(1e9)), int64(frac))

	return time.Unix(int64(seconds), int64(frac*float64(1e9)))
}
