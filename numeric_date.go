package jwt

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// NumericDate represents a JSON numeric value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var (
		f float64
	)

	// since this can be a non-integer, we parse it as float and construct a time.Time object out if

	// TODO(oxisto): Another approach would be to use json.Unmarshal into a json.Number
	if f, err = strconv.ParseFloat(string(b), 64); err != nil {
		// TODO(oxisto): This makes use of the new errors API introduced in 1.13, might need to remove it again
		return fmt.Errorf("could not parse NumericData: %w", err)
	}

	(*date).Time = timeFromFloat(f)

	return nil
}

func timeFromFloat(f float64) time.Time {
	var (
		seconds float64
		frac    float64
	)

	seconds, frac = math.Modf(f)

	return time.Unix(int64(seconds), int64(frac*1e9))
}
