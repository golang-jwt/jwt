module github.com/dgrijalva/jwt-go

go 1.14

// this version suffers from CVE-2020-26160 and follows a pre-modules versioning scheme
retract v3.2.0+incompatible

// this version was a leftover from the original versioning scheme and got cached by accident
retract v1.0.2
