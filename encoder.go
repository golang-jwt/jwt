package jwt

import "io"

// Base64Encoder is an interface that allows to implement custom Base64 encoding
// algorithms.
type Base64EncodeFunc func(src []byte) string

// Base64Decoder is an interface that allows to implement custom Base64 decoding
// algorithms.
type Base64DecodeFunc func(s string) ([]byte, error)

// JSONEncoder is an interface that allows to implement custom JSON encoding
// algorithms.
type JSONMarshalFunc func(v any) ([]byte, error)

// JSONUnmarshal is an interface that allows to implement custom JSON unmarshal
// algorithms.
type JSONUnmarshalFunc func(data []byte, v any) error

type JSONDecoder interface {
	UseNumber()
	Decode(v any) error
}

type JSONNewDecoderFunc[T JSONDecoder] func(r io.Reader) T
