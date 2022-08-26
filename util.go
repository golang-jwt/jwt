package jwt

import (
	"encoding/json"
	"strconv"
)

// ByteArrayVal interface to byte array
func ByteArrayVal(value interface{}) (key []byte) {
	if value == nil {
		return
	}
	switch value.(type) {
	case float64:
		ft := value.(float64)
		key = []byte(strconv.FormatFloat(ft, 'f', -1, 64))
	case float32:
		ft := value.(float32)
		key = []byte(strconv.FormatFloat(float64(ft), 'f', -1, 64))
	case int:
		it := value.(int)
		key = []byte(strconv.Itoa(it))
	case uint:
		it := value.(uint)
		key = []byte(strconv.Itoa(int(it)))
	case int8:
		it := value.(int8)
		key = []byte(strconv.Itoa(int(it)))
	case uint8:
		it := value.(uint8)
		key = []byte(strconv.Itoa(int(it)))
	case int16:
		it := value.(int16)
		key = []byte(strconv.Itoa(int(it)))
	case uint16:
		it := value.(uint16)
		key = []byte(strconv.Itoa(int(it)))
	case int32:
		it := value.(int32)
		key = []byte(strconv.Itoa(int(it)))
	case uint32:
		it := value.(uint32)
		key = []byte(strconv.Itoa(int(it)))
	case int64:
		it := value.(int64)
		key = []byte(strconv.FormatInt(it, 10))
	case uint64:
		it := value.(uint64)
		key = []byte(strconv.FormatUint(it, 10))
	case string:
		key = []byte(value.(string))
	case []byte:
		key = value.([]byte)
	default:
		newValue, _ := json.Marshal(value)
		key = newValue
	}
	return
}
