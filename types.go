package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// TimePrecision sets the precision of times and dates within this library. This
// has an influence on the precision of times when comparing expiry or other
// related time fields. Furthermore, it is also the precision of times when
// serializing.
//
// For backwards compatibility the default precision is set to seconds, so that
// no fractional timestamps are generated.
var TimePrecision = time.Second

// MarshalSingleStringAsArray modifies the behavior of the ClaimStrings type,
// especially its MarshalJSON function.
//
// If it is set to true (the default), it will always serialize the type as an
// array of strings, even if it just contains one element, defaulting to the
// behavior of the underlying []string. If it is set to false, it will serialize
// to a single string, if it contains one element. Otherwise, it will serialize
// to an array of strings.
var MarshalSingleStringAsArray = true

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
	if !math.IsNaN(f) && !math.IsInf(f, 0) {
		formatted := strconv.FormatFloat(f, 'f', -1, 64)
		if n, err := newNumericDateFromNumber(json.Number(formatted)); err == nil {
			return n
		}
	}
	round, frac := math.Modf(f)
	return NewNumericDate(time.Unix(int64(round), int64(math.Round(frac*1e9))))
}

// newNumericDateFromNumber creates a new *NumericDate out of a [json.Number] representing a
// UNIX epoch with decimal seconds, avoiding floating point precision loss.
func newNumericDateFromNumber(number json.Number) (*NumericDate, error) {
	s := number.String()
	if strings.ContainsAny(s, "eE") {
		f, err := number.Float64()
		if err != nil {
			return nil, fmt.Errorf("could not convert json number value to float: %w", err)
		}
		round, frac := math.Modf(f)
		return NewNumericDate(time.Unix(int64(round), int64(math.Round(frac*1e9)))), nil
	}

	parts := strings.SplitN(s, ".", 2)
	secStr := parts[0]
	isNegative := strings.HasPrefix(secStr, "-")

	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil {
		f, errFloat := number.Float64()
		if errFloat != nil {
			return nil, fmt.Errorf("could not convert json number value to float: %w", errFloat)
		}
		round, frac := math.Modf(f)
		return NewNumericDate(time.Unix(int64(round), int64(math.Round(frac*1e9)))), nil
	}

	var nsec int64
	if len(parts) == 2 && len(parts[1]) > 0 {
		fracStr := parts[1]
		if len(fracStr) <= 9 {
			padded := fracStr + strings.Repeat("0", 9-len(fracStr))
			n, err := strconv.ParseInt(padded, 10, 64)
			if err != nil {
				f, _ := number.Float64()
				round, frac := math.Modf(f)
				return NewNumericDate(time.Unix(int64(round), int64(math.Round(frac*1e9)))), nil
			}
			nsec = n
		} else {
			n, err := strconv.ParseInt(fracStr[:9], 10, 64)
			if err != nil {
				f, _ := number.Float64()
				round, frac := math.Modf(f)
				return NewNumericDate(time.Unix(int64(round), int64(math.Round(frac*1e9)))), nil
			}
			nsec = n
			if fracStr[9] >= '5' {
				nsec++
			}
			if nsec >= 1_000_000_000 {
				nsec -= 1_000_000_000
				if isNegative {
					sec--
				} else {
					sec++
				}
			}
		}
	}

	if isNegative {
		nsec = -nsec
	}

	return NewNumericDate(time.Unix(sec, nsec)), nil
}

// MarshalJSON is an implementation of the json.RawMessage interface and serializes the UNIX epoch
// represented in NumericDate to a byte array, using the precision specified in TimePrecision.
func (date NumericDate) MarshalJSON() (b []byte, err error) {
	var prec int
	if TimePrecision < time.Second {
		prec = int(math.Round(math.Log10(float64(time.Second) / float64(TimePrecision))))
	}
	truncatedDate := date.Truncate(TimePrecision)

	// For very large timestamps, UnixNano would overflow an int64, but this
	// function requires nanosecond level precision, so we have to use the
	// following technique to get round the issue:
	//
	// 1. Take the normal unix timestamp to form the whole number part of the
	//    output,
	// 2. Take the result of the Nanosecond function, which returns the offset
	//    within the second of the particular unix time instance, to form the
	//    decimal part of the output
	// 3. Concatenate them to produce the final result
	var (
		seconds           string
		nanosecondsOffset string
	)
	if truncatedDate.Unix() < 0 && truncatedDate.Nanosecond() > 0 && prec > 0 {
		sec := truncatedDate.Unix() + 1
		if sec == 0 {
			seconds = "-0"
		} else {
			seconds = strconv.FormatInt(sec, 10)
		}
		nanos := int64(time.Second) - int64(truncatedDate.Nanosecond())
		nanosecondsOffset = strconv.FormatFloat(float64(nanos)/float64(time.Second), 'f', prec, 64)
	} else {
		seconds = strconv.FormatInt(truncatedDate.Unix(), 10)
		nanosecondsOffset = strconv.FormatFloat(float64(truncatedDate.Nanosecond())/float64(time.Second), 'f', prec, 64)
	}

	output := append([]byte(seconds), []byte(nanosecondsOffset)[1:]...)

	return output, nil
}

// UnmarshalJSON is an implementation of the json.RawMessage interface and
// deserializes a [NumericDate] from a JSON representation, i.e. a
// [json.Number]. This number represents an UNIX epoch with either integer or
// non-integer seconds.
func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var number json.Number

	if err = json.Unmarshal(b, &number); err != nil {
		return fmt.Errorf("could not parse NumericData: %w", err)
	}

	n, err := newNumericDateFromNumber(number)
	if err != nil {
		return err
	}
	*date = *n

	return nil
}

// ClaimStrings is basically just a slice of strings, but it can be either
// serialized from a string array or just a string. This type is necessary,
// since the "aud" claim can either be a single string or an array.
type ClaimStrings []string

func (s *ClaimStrings) UnmarshalJSON(data []byte) (err error) {
	var value any

	if err = json.Unmarshal(data, &value); err != nil {
		return err
	}

	var aud []string

	switch v := value.(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = ClaimStrings(v)
	case []any:
		for _, vv := range v {
			vs, ok := vv.(string)
			if !ok {
				return ErrInvalidType
			}
			aud = append(aud, vs)
		}
	case nil:
		return nil
	default:
		return ErrInvalidType
	}

	*s = aud

	return
}

func (s ClaimStrings) MarshalJSON() (b []byte, err error) {
	// This handles a special case in the JWT RFC. If the string array, e.g.
	// used by the "aud" field, only contains one element, it MAY be serialized
	// as a single string. This may or may not be desired based on the ecosystem
	// of other JWT library used, so we make it configurable by the variable
	// MarshalSingleStringAsArray.
	if len(s) == 1 && !MarshalSingleStringAsArray {
		return json.Marshal(s[0])
	}

	return json.Marshal([]string(s))
}
