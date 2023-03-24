# Migration Guide (v5.0.0)

Version `v5` contains a major rework of core functionalities in the `jwt-go` library. This includes support for several
validation options as well as a re-design of the `Claims` interface. Lastly, we reworked how errors work under the hood,
which should provide a better overall developer experience.

Starting from [v5.0.0](https://github.com/golang-jwt/jwt/releases/tag/v5.0.0), the import path will be:

    "github.com/golang-jwt/jwt/v5"

For most users, changing the import path *should* suffice. However, since we intentionally changed and cleaned some of
the public API, existing programs might need to be updated. The following sections describe significant changes
and corresponding updates for existing programs.

## Parsing and Validation Options

Under the hood, a new `validator` struct takes care of validating the claims. A long awaited feature has been the option
to fine-tune the validation of tokens. This is now possible with several `ParserOption` functions that can be appended
to most `Parse` functions, such as `ParseWithClaims`. The most important options and changes are:
  * Added `WithLeeway` to support specifying the leeway that is allowed when validating time-based claims, such as `exp` or `nbf`.
  * Changed default behavior to not check the `iat` claim. Usage of this claim is OPTIONAL according to the JWT RFC. The claim itself is also purely informational according to the RFC, so a strict validation failure is not recommended. If you want to check for sensible values in these claims, please use the `WithIssuedAt` parser option.
  * Added `WithAudience`, `WithSubject` and `WithIssuer` to support checking for expected `aud`, `sub` and `iss`.

## Changes to the `Claims` interface

### Complete Restructuring

Previously, the claims interface was satisfied with an implementation of a `Valid() error` function. This had several issues:
  * The different claim types (struct claims, map claims, etc.) then contained similar (but not 100 % identical) code of how this validation was done. This lead to a lot of (almost) duplicate code and was hard to maintain
  * It was not really semantically close to what a "claim" (or a set of claims) really is; which is a list of defined key/value pairs with a certain semantic meaning.

Since all the validation functionality is now extracted into the validator, all `VerifyXXX` and `Valid` functions have been removed from the `Claims` interface. Instead, the interface now represents a list of getters to retrieve values with a specific meaning. This allows us to completely decouple the validation logic with the underlying storage representation of the claim, which could be a struct, a map or even something stored in a database.

```go
type Claims interface {
	GetExpirationTime() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() (ClaimStrings, error)
}
```

### Supported Claim Types and Removal of `StandardClaims`

The two standard claim types supported by this library, `MapClaims` and `RegisteredClaims` both implement the necessary functions of this interface. The old `StandardClaims` struct, which has already been deprecated in `v4` is now removed.

Users using custom claims, in most cases, will not experience any changes in the behavior as long as they embedded
`RegisteredClaims`. If they created a new claim type from scratch, they now need to implemented the proper getter
functions.

### Migrating Application Specific Logic of the old `Valid`

Previously, users could override the `Valid` method in a custom claim, for example to extend the validation with application-specific claims. However, this was always very dangerous, since once could easily disable the standard validation and signature checking.

In order to avoid that, while still supporting the use-case, a new `ClaimsValidator` interface has been introduced. This interface consists of the `Validate() error` function. If the validator sees, that a `Claims` struct implements this interface, the errors returned to the `Validate` function will be *appended* to the regular standard validation. It is not possible to disable the standard validation anymore (even only by accident).

Usage examples can be found in [example_test.go](./example_test.go), to build claims structs like the following.

```go
// MyCustomClaims includes all registered claims, plus Foo.
type MyCustomClaims struct {
	Foo string `json:"foo"`
	jwt.RegisteredClaims
}

// Validate can be used to execute additional application-specific claims
// validation.
func (m MyCustomClaims) Validate() error {
	if m.Foo != "bar" {
		return errors.New("must be foobar")
	}

	return nil
}
```

# Migration Guide (v4.0.0)

Starting from [v4.0.0](https://github.com/golang-jwt/jwt/releases/tag/v4.0.0), the import path will be:

    "github.com/golang-jwt/jwt/v4"

The `/v4` version will be backwards compatible with existing `v3.x.y` tags in this repo, as well as 
`github.com/dgrijalva/jwt-go`. For most users this should be a drop-in replacement, if you're having 
troubles migrating, please open an issue.

You can replace all occurrences of `github.com/dgrijalva/jwt-go` or `github.com/golang-jwt/jwt` with `github.com/golang-jwt/jwt/v5`, either manually or by using tools such as `sed` or `gofmt`.

And then you'd typically run:

```
go get github.com/golang-jwt/jwt/v4
go mod tidy
```

# Older releases (before v3.2.0)

The original migration guide for older releases can be found at https://github.com/dgrijalva/jwt-go/blob/master/MIGRATION_GUIDE.md.
