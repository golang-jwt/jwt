package jwt

import "io"

// Base64Encoding represents an object that can encode and decode base64. A
// common example is [encoding/base64.Encoding].
type Base64Encoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

type StrictFunc[T Base64Encoding] func() T

type Stricter[T Base64Encoding] interface {
	Strict() T
}

func DoStrict[S Base64Encoding, T Stricter[S]](x T) Base64Encoding {
	return x.Strict()
}

// JSONMarshalFunc is a function type that allows to implement custom JSON
// encoding algorithms.
type JSONMarshalFunc func(v any) ([]byte, error)

// JSONUnmarshalFunc is a function type that allows to implement custom JSON
// unmarshal algorithms.
type JSONUnmarshalFunc func(data []byte, v any) error

type JSONDecoder interface {
	UseNumber()
	Decode(v any) error
}

type JSONNewDecoderFunc[T JSONDecoder] func(r io.Reader) T
