module auth0middleware

go 1.16

require (
	github.com/MicahParks/keyfunc v0.6.1 // TODO
	github.com/auth0/go-jwt-middleware v1.0.1
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible
)

replace github.com/MicahParks/keyfunc => ../../
