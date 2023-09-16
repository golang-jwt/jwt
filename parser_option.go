package jwt

import (
	"io"
	"time"
)

// ParserOption is used to implement functional-style options that modify the
// behavior of the parser. To add new options, just create a function (ideally
// beginning with With or Without) that returns an anonymous function that takes
// a *Parser type as input and manipulates its configuration accordingly.
type ParserOption func(*Parser)

// WithValidMethods is an option to supply algorithm methods that the parser
// will check. Only those methods will be considered valid. It is heavily
// encouraged to use this option in order to prevent attacks such as
// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/.
func WithValidMethods(methods []string) ParserOption {
	return func(p *Parser) {
		p.validMethods = methods
	}
}

// WithJSONNumber is an option to configure the underlying JSON parser with
// UseNumber.
func WithJSONNumber() ParserOption {
	return func(p *Parser) {
		p.useJSONNumber = true
	}
}

// WithoutClaimsValidation is an option to disable claims validation. This
// option should only be used if you exactly know what you are doing.
func WithoutClaimsValidation() ParserOption {
	return func(p *Parser) {
		p.skipClaimsValidation = true
	}
}

// WithLeeway returns the ParserOption for specifying the leeway window.
func WithLeeway(leeway time.Duration) ParserOption {
	return func(p *Parser) {
		p.validator.leeway = leeway
	}
}

// WithTimeFunc returns the ParserOption for specifying the time func. The
// primary use-case for this is testing. If you are looking for a way to account
// for clock-skew, WithLeeway should be used instead.
func WithTimeFunc(f func() time.Time) ParserOption {
	return func(p *Parser) {
		p.validator.timeFunc = f
	}
}

// WithIssuedAt returns the ParserOption to enable verification
// of issued-at.
func WithIssuedAt() ParserOption {
	return func(p *Parser) {
		p.validator.verifyIat = true
	}
}

// WithExpirationRequired returns the ParserOption to make exp claim required.
// By default exp claim is optional.
func WithExpirationRequired() ParserOption {
	return func(p *Parser) {
		p.validator.requireExp = true
	}
}

// WithAudience configures the validator to require the specified audience in
// the `aud` claim. Validation will fail if the audience is not listed in the
// token or the `aud` claim is missing.
//
// NOTE: While the `aud` claim is OPTIONAL in a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim,
// if an audience is expected.
func WithAudience(aud string) ParserOption {
	return func(p *Parser) {
		p.validator.expectedAud = aud
	}
}

// WithIssuer configures the validator to require the specified issuer in the
// `iss` claim. Validation will fail if a different issuer is specified in the
// token or the `iss` claim is missing.
//
// NOTE: While the `iss` claim is OPTIONAL in a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim,
// if an issuer is expected.
func WithIssuer(iss string) ParserOption {
	return func(p *Parser) {
		p.validator.expectedIss = iss
	}
}

// WithSubject configures the validator to require the specified subject in the
// `sub` claim. Validation will fail if a different subject is specified in the
// token or the `sub` claim is missing.
//
// NOTE: While the `sub` claim is OPTIONAL in a JWT, the handling of it is
// application-specific. Since this validation API is helping developers in
// writing secure application, we decided to REQUIRE the existence of the claim,
// if a subject is expected.
func WithSubject(sub string) ParserOption {
	return func(p *Parser) {
		p.validator.expectedSub = sub
	}
}

// WithPaddingAllowed will enable the codec used for decoding JWTs to allow
// padding. Note that the JWS RFC7515 states that the tokens will utilize a
// Base64url encoding with no padding. Unfortunately, some implementations of
// JWT are producing non-standard tokens, and thus require support for decoding.
func WithPaddingAllowed() ParserOption {
	return func(p *Parser) {
		p.decodePaddingAllowed = true
	}
}

// WithStrictDecoding will switch the codec used for decoding JWTs into strict
// mode. In this mode, the decoder requires that trailing padding bits are zero,
// as described in RFC 4648 section 3.5.
//
// Note: This is only supported when using [encoding/base64.Encoding], but not
// by any other decoder specified with [WithBase64Decoder].
func WithStrictDecoding() ParserOption {
	return func(p *Parser) {
		p.decodeStrict = true
	}
}

// WithJSONDecoder supports a custom JSON decoder to use in parsing the JWT.
// There are two functions that can be supplied:
//   - jsonUnmarshal is a [JSONUnmarshalFunc] that is used for the
//     un-marshalling the header and claims when no other options are specified
//   - jsonNewDecoder is a [JSONNewDecoderFunc] that is used to create an object
//     satisfying the [JSONDecoder] interface.
//
// The latter is used when the [WithJSONNumber] option is used.
//
// If any of the supplied functions is set to nil, the defaults from the Go
// standard library, [encoding/json.Unmarshal] and [encoding/json.NewDecoder]
// are used.
//
// Example using the https://github.com/bytedance/sonic library.
//
//	import (
//		"github.com/bytedance/sonic"
//	)
//
//	var parser = jwt.NewParser(jwt.WithJSONDecoder(sonic.Unmarshal, sonic.ConfigDefault.NewDecoder))
func WithJSONDecoder[T JSONDecoder](jsonUnmarshal JSONUnmarshalFunc, jsonNewDecoder JSONNewDecoderFunc[T]) ParserOption {
	return func(p *Parser) {
		p.jsonUnmarshal = jsonUnmarshal
		// This seems to be necessary, since we don't want to store the specific
		// JSONDecoder type in our parser, but need it in the function
		// interface.
		p.jsonNewDecoder = func(r io.Reader) JSONDecoder {
			return jsonNewDecoder(r)
		}
	}
}

// WithBase64Decoder supports a custom Base64 when decoding a base64 encoded
// token. Two encoding can be specified:
//   - rawURL needs to contain a [Base64Encoding] that is based on base64url
//     without padding. This is used for parsing tokens with the default
//     options.
//   - url needs to contain a [Base64Encoding] based on base64url with padding.
//     The sole use of this to decode tokens when [WithPaddingAllowed] is
//     enabled.
//
// If any of the supplied encodings are set to nil, the defaults from the Go
// standard library, [encoding/base64.RawURLEncoding] and
// [encoding/base64.URLEncoding] are used.
//
// Example using the https://github.com/segmentio/asm library.
//
//	import (
//		asmbase64 "github.com/segmentio/asm/base64"
//	)
//
//	var parser = jwt.NewParser(jwt.WithBase64Decoder(asmbase64.RawURLEncoding, asmbase64.URLEncoding))
func WithBase64Decoder[T Base64Encoding](rawURL Base64Encoding, url T) ParserOption {
	return func(p *Parser) {
		p.rawUrlBase64Encoding = rawURL
		p.urlBase64Encoding = url

		// Check, whether the library supports the Strict() function
		stricter, ok := rawURL.(Stricter[T])
		if ok {
			// We need to get rid of the type parameter T, so we need to wrap it
			// here
			p.strict = func() Base64Encoding {
				return stricter.Strict()
			}
		}
	}
}
