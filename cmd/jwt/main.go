// A useful example app.  You can use this to debug your tokens on the command line.
// This is also a great place to look at how you might use this library.
//
// Example usage:
// The following will create and sign a token, then verify it and output the original claims.
//
//	echo {\"foo\":\"bar\"} | bin/jwt -key test/sample_key -alg RS256 -sign - | bin/jwt -key test/sample_key.pub -verify -
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// Options
	flagAlg     = flag.String("alg", "", algHelp())
	flagKey     = flag.String("key", "", "path to key file or '-' to read from stdin")
	flagCompact = flag.Bool("compact", false, "output compact JSON")
	flagDebug   = flag.Bool("debug", false, "print out all kinds of debug data")
	flagClaims  = make(ArgList)
	flagHead    = make(ArgList)

	// Modes - exactly one of these is required
	flagSign   = flag.String("sign", "", "path to claims object to sign, '-' to read from stdin, or '+' to use only -claim args")
	flagVerify = flag.String("verify", "", "path to JWT token to verify or '-' to read from stdin")
	flagShow   = flag.String("show", "", "path to JWT file or '-' to read from stdin")
)

func main() {
	// Plug in Var flags
	flag.Var(flagClaims, "claim", "add additional claims. may be used more than once")
	flag.Var(flagHead, "header", "add additional header params. may be used more than once")

	// Usage message if you ask for -help or if you mess up inputs.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  One of the following flags is required: sign, verify\n")
		flag.PrintDefaults()
	}

	// Parse command line options
	flag.Parse()

	// Do the thing.  If something goes wrong, print error to stderr
	// and exit with a non-zero status code
	if err := start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Figure out which thing to do and then do that
func start() error {
	switch {
	case *flagSign != "":
		return signToken()
	case *flagVerify != "":
		return verifyToken()
	case *flagShow != "":
		return showToken()
	default:
		flag.Usage()
		return fmt.Errorf("none of the required flags are present.  What do you want me to do?")
	}
}

// Helper func:  Read input from specified file or stdin
func loadData(p string) ([]byte, error) {
	if p == "" {
		return nil, fmt.Errorf("no path specified")
	}

	var rdr io.Reader
	switch p {
	case "-":
		rdr = os.Stdin
	case "+":
		return []byte("{}"), nil
	default:
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		rdr = f
		defer f.Close()
	}
	return io.ReadAll(rdr)
}

// Print a json object in accordance with the prophecy (or the command line options)
func printJSON(j interface{}) error {
	var out []byte
	var err error

	if !*flagCompact {
		out, err = json.MarshalIndent(j, "", "    ")
	} else {
		out, err = json.Marshal(j)
	}

	if err == nil {
		fmt.Println(string(out))
	}

	return err
}

// Verify a token and output the claims.  This is a great example
// of how to verify and view a token.
func verifyToken() error {
	// get the token
	tokData, err := loadData(*flagVerify)
	if err != nil {
		return fmt.Errorf("couldn't read token: %w", err)
	}

	// trim possible whitespace from token
	tokData = regexp.MustCompile(`\s*$`).ReplaceAll(tokData, []byte{})
	if *flagDebug {
		fmt.Fprintf(os.Stderr, "Token len: %v bytes\n", len(tokData))
	}

	// Parse the token.  Load the key from command line option
	token, err := jwt.Parse(string(tokData), func(t *jwt.Token) (interface{}, error) {
		if isNone() {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		data, err := loadData(*flagKey)
		if err != nil {
			return nil, err
		}
		switch {
		case isEs():
			return jwt.ParseECPublicKeyFromPEM(data)
		case isRs():
			return jwt.ParseRSAPublicKeyFromPEM(data)
		case isEd():
			return jwt.ParseEdPublicKeyFromPEM(data)
		default:
			return data, nil
		}
	})

	// Print an error if we can't parse for some reason
	if err != nil {
		return fmt.Errorf("couldn't parse token: %w", err)
	}

	// Print some debug data
	if *flagDebug {
		fmt.Fprintf(os.Stderr, "Header:\n%v\n", token.Header)
		fmt.Fprintf(os.Stderr, "Claims:\n%v\n", token.Claims)
	}

	// Print the token details
	if err := printJSON(token.Claims); err != nil {
		return fmt.Errorf("failed to output claims: %w", err)
	}

	return nil
}

// Create, sign, and output a token.  This is a great, simple example of
// how to use this library to create and sign a token.
func signToken() error {
	// get the token data from command line arguments
	tokData, err := loadData(*flagSign)
	if err != nil {
		return fmt.Errorf("couldn't read token: %w", err)
	} else if *flagDebug {
		fmt.Fprintf(os.Stderr, "Token: %v bytes", len(tokData))
	}

	// parse the JSON of the claims
	var claims jwt.MapClaims
	if err := json.Unmarshal(tokData, &claims); err != nil {
		return fmt.Errorf("couldn't parse claims JSON: %w", err)
	}

	// add command line claims
	if len(flagClaims) > 0 {
		for k, v := range flagClaims {
			claims[k] = v
		}
	}

	// get the key
	var key interface{}
	if isNone() {
		key = jwt.UnsafeAllowNoneSignatureType
	} else {
		key, err = loadData(*flagKey)
		if err != nil {
			return fmt.Errorf("couldn't read key: %w", err)
		}
	}

	// get the signing alg
	alg := jwt.GetSigningMethod(*flagAlg)
	if alg == nil {
		return fmt.Errorf("couldn't find signing method: %v", *flagAlg)
	}

	// create a new token
	token := jwt.NewWithClaims(alg, claims)

	// add command line headers
	if len(flagHead) > 0 {
		for k, v := range flagHead {
			token.Header[k] = v
		}
	}

	switch {
	case isEs():
		k, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("couldn't convert key data to key")
		}
		key, err = jwt.ParseECPrivateKeyFromPEM(k)
		if err != nil {
			return err
		}
	case isRs():
		k, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("couldn't convert key data to key")
		}
		key, err = jwt.ParseRSAPrivateKeyFromPEM(k)
		if err != nil {
			return err
		}
	case isEd():
		k, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("couldn't convert key data to key")
		}
		key, err = jwt.ParseEdPrivateKeyFromPEM(k)
		if err != nil {
			return err
		}
	}

	out, err := token.SignedString(key)
	if err != nil {
		return fmt.Errorf("error signing token: %w", err)
	}
	fmt.Println(out)

	return nil
}

// showToken pretty-prints the token on the command line.
func showToken() error {
	// get the token
	tokData, err := loadData(*flagShow)
	if err != nil {
		return fmt.Errorf("couldn't read token: %w", err)
	}

	// trim possible whitespace from token
	tokData = regexp.MustCompile(`\s*$`).ReplaceAll(tokData, []byte{})
	if *flagDebug {
		fmt.Fprintf(os.Stderr, "Token len: %v bytes\n", len(tokData))
	}

	token, err := jwt.Parse(string(tokData), nil)
	if err != nil {
		return fmt.Errorf("malformed token: %w", err)
	}

	// Print the token details
	fmt.Println("Header:")
	if err := printJSON(token.Header); err != nil {
		return fmt.Errorf("failed to output header: %w", err)
	}

	fmt.Println("Claims:")
	if err := printJSON(token.Claims); err != nil {
		return fmt.Errorf("failed to output claims: %w", err)
	}

	return nil
}

func isEs() bool {
	return strings.HasPrefix(*flagAlg, "ES")
}

func isRs() bool {
	return strings.HasPrefix(*flagAlg, "RS") || strings.HasPrefix(*flagAlg, "PS")
}

func isEd() bool {
	return *flagAlg == "EdDSA"
}

func isNone() bool {
	return *flagAlg == "none"
}

func algHelp() string {
	algs := jwt.GetAlgorithms()
	sort.Strings(algs)

	var b strings.Builder
	b.WriteString("signing algorithm identifier, one of\n")
	for i, alg := range algs {
		if i > 0 {
			if i%7 == 0 {
				b.WriteString(",\n")
			} else {
				b.WriteString(", ")
			}
		}
		b.WriteString(alg)
	}
	return b.String()
}

type ArgList map[string]string

func (l ArgList) String() string {
	data, _ := json.Marshal(l)
	return string(data)
}

func (l ArgList) Set(arg string) error {
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid argument '%v'.  Must use format 'key=value'. %v", arg, parts)
	}
	l[parts[0]] = parts[1]
	return nil
}
