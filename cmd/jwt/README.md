# `jwt` command-line tool

This is a simple tool to sign, verify and show JSON Web Tokens from
the command line.

## Getting Started

The following will create and sign a token, then verify it and output the original claims:

```bash
echo {\"foo\":\"bar\"} | ./jwt -key ../../test/sample_key -alg RS256 -sign - | ./jwt -key ../../test/sample_key.pub -alg RS256 -verify -
```

Key files should be in PEM format. Other formats are not supported by this tool.

To simply display a token, use:

```bash
echo $JWT | ./jwt -show -
```

You can install this tool with the following command:

```bash
go install github.com/golang-jwt/jwt/v4/cmd/jwt
```

## Sign/Verify with Shared Secret

First, create a JSON document with token payload, e.g. `~/experimental/jwt/data`.

```json
{
    "email": "jsmith@foo.bar",
    "aud": "foo.bar",
    "exp": 2559489932,
    "iat": 1612805132,
    "iss": "foo.bar",
    "sub": "jsmith"
}
```

Then, create a file with shared secret key, e.g. `~/experimental/jwt/token.key`.

```
foobarbaz
```

Next, sign the token:

```bash
./jwt -key ~/experimental/jwt/token.key -alg HS512 -sign ~/experimental/jwt/data > ~/experimental/jwt/token.jwt
```

After that, review the token:

```bash
./jwt -show ~/experimental/jwt/token.jwt
```

The expected output follows:

```
Header:
{
    "alg": "HS512",
    "typ": "JWT"
}
Claims:
{
    "aud": "foo.bar",
    "email": "jsmith@foo.bar",
    "exp": 2559489932,
    "iat": 1612805132,
    "iss": "foo.bar",
    "sub": "jsmith"
}
```

Subsequently, validate the token:

```bash
./jwt -key ~/experimental/jwt/token.key -alg HS512 -verify ~/experimental/jwt/token.jwt
```

The expected output follows:

```
{
    "aud": "foo.bar",
    "email": "jsmith@foo.bar",
    "exp": 2559489932,
    "iat": 1612805132,
    "iss": "foo.bar",
    "sub": "jsmith"
}
```
