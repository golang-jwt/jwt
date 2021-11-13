package main

import (
	"context"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/keyfunc"
)

func main() {

	// Get the JWKs URL.
	//
	// This is a sample JWKs service. Visit https://jwks-service.appspot.com/ and grab a token to test this example.
	jwksURL := "https://jwks-service.appspot.com/.well-known/jwks.json"

	// Create a context that, when cancelled, ends the JWKs background refresh goroutine.
	ctx, cancel := context.WithCancel(context.Background())

	// Create the keyfunc options. Use an error handler that logs. Refresh the JWKs when a JWT signed by an unknown KID
	// is found or at the specified interval. Rate limit these refreshes. Timeout the initial JWKs refresh request after
	// 10 seconds. This timeout is also used to create the initial context.Context for keyfunc.Get.
	refreshInterval := time.Hour
	refreshRateLimit := time.Minute * 5
	refreshTimeout := time.Second * 10
	refreshUnknownKID := true
	options := keyfunc.Options{
		Ctx: ctx,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   refreshInterval,
		RefreshRateLimit:  refreshRateLimit,
		RefreshTimeout:    refreshTimeout,
		RefreshUnknownKID: &refreshUnknownKID,
	}

	// Create the JWKs from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKs from resource at the given URL.\nError: %s", err.Error())
	}

	// Get a JWT to parse.
	jwtB64 := "eyJraWQiOiJlZThkNjI2ZCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJXZWlkb25nIiwiYXVkIjoiVGFzaHVhbiIsImlzcyI6Imp3a3Mtc2VydmljZS5hcHBzcG90LmNvbSIsImlhdCI6MTYzMTM2OTk1NSwianRpIjoiNDY2M2E5MTAtZWU2MC00NzcwLTgxNjktY2I3NDdiMDljZjU0In0.LwD65d5h6U_2Xco81EClMa_1WIW4xXZl8o4b7WzY_7OgPD2tNlByxvGDzP7bKYA9Gj--1mi4Q4li4CAnKJkaHRYB17baC0H5P9lKMPuA6AnChTzLafY6yf-YadA7DmakCtIl7FNcFQQL2DXmh6gS9J6TluFoCIXj83MqETbDWpL28o3XAD_05UP8VLQzH2XzyqWKi97mOuvz-GsDp9mhBYQUgN3csNXt2v2l-bUPWe19SftNej0cxddyGu06tXUtaS6K0oe0TTbaqc3hmfEiu5G0J8U6ztTUMwXkBvaknE640NPgMQJqBaey0E4u0txYgyvMvvxfwtcOrDRYqYPBnA"

	// Parse the JWT.
	var token *jwt.Token
	if token, err = jwt.Parse(jwtB64, jwks.Keyfunc); err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	// Check if the token is valid.
	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}
	log.Println("The token is valid.")

	// End the background refresh goroutine when it's no longer needed.
	cancel()

	// This will be ineffectual because the line above this canceled the parent context.Context.
	// This method call is idempotent similar to context.CancelFunc.
	jwks.EndBackground()
}
