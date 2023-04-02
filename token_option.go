package jwt

// TokenOption is a reserved type, which provides some forward compatibility,
// if we ever want to introduce token creation-related options.
type TokenOption func(*Token)

func WithJSONEncoder(f JSONMarshalFunc) TokenOption {
	return func(token *Token) {
		token.jsonEncoder = f
	}
}

func WithBase64Encoder(f Base64EncodeFunc) TokenOption {
	return func(token *Token) {
		token.base64Encoder = f
	}
}
