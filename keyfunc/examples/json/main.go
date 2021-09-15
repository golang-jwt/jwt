package main

import (
	"encoding/json"
	"log"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

func main() {

	// Get the JWKs as JSON.
	jwksJSON := json.RawMessage(`{"keys":[{"kty":"RSA","e":"AQAB","kid":"ee8d626d","n":"gRda5b0pkgTytDuLrRnNSYhvfMIyM0ASq2ZggY4dVe12JV8N7lyXilyqLKleD-2lziivvzE8O8CdIC2vUf0tBD7VuMyldnZruSEZWCuKJPdgKgy9yPpShmD2NyhbwQIAbievGMJIp_JMwz8MkdY5pzhPECGNgCEtUAmsrrctP5V8HuxaxGt9bb-DdPXkYWXW3MPMSlVpGZ5GiIeTABxqYNG2MSoYeQ9x8O3y488jbassTqxExI_4w9MBQBJR9HIXjWrrrenCcDlMY71rzkbdj3mmcn9xMq2vB5OhfHyHTihbUPLSm83aFWSuW9lE7ogMc93XnrB8evIAk6VfsYlS9Q"},{"kty":"EC","crv":"P-256","kid":"711d48d1","x":"tfXCoBU-wXemeQCkME1gMZWK0-UECCHIkedASZR0t-Q","y":"9xzYtnKQdiQJHCtGwpZWF21eP1fy5x4wC822rCilmBw"},{"kty":"EC","crv":"P-384","kid":"d52c9829","x":"tFx6ev6eLs9sNfdyndn4OgbhV6gPFVn7Ul0VD5vwuplJLbIYeFLI6T42tTaE5_Q4","y":"A0gzB8TqxPX7xMzyHH_FXkYG2iROANH_kQxBovSeus6l_QSyqYlipWpBy9BhY9dz"},{"kty":"RSA","e":"AQAB","kid":"ecac72e5","n":"nLbnTvZAUxdmuAbDDUNAfha6mw0fri3UpV2w1PxilflBuSnXJhzo532-YQITogoanMjy_sQ8kHUhZYHVRR6vLZRBBbl-hP8XWiCe4wwioy7Ey3TiIUYfW-SD6I42XbLt5o-47IR0j5YDXxnX2UU7-UgR_kITBeLDfk0rSp4B0GUhPbP5IDItS0MHHDDS3lhvJomxgEfoNrp0K0Fz_s0K33hfOqc2hD1tSkX-3oDTQVRMF4Nxax3NNw8-ahw6HNMlXlwWfXodgRMvj9pcz8xUYa3C5IlPlZkMumeNCFx1qds6K_eYcU0ss91DdbhhE8amRX1FsnBJNMRUkA5i45xkOIx15rQN230zzh0p71jvtx7wYRr5pdMlwxV0T9Ck5PCmx-GzFazA2X6DJ0Xnn1-cXkRoZHFj_8Mba1dUrNz-NWEk83uW5KT-ZEbX7nzGXtayKWmGb873a8aYPqIsp6bQ_-eRBd8TDT2g9HuPyPr5VKa1p33xKaohz4DGy3t1Qpy3UWnbPXUlh5dLWPKz-TcS9FP5gFhWVo-ZhU03Pn6P34OxHmXGWyQao18dQGqzgD4e9vY3rLhfcjVZJYNlWY2InsNwbYS-DnienPf1ws-miLeXxNKG3tFydoQzHwyOxG6Wc-HBfzL_hOvxINKQamvPasaYWl1LWznMps6elKCgKDc"},{"kty":"EC","crv":"P-521","kid":"c570888f","x":"AHNpXq0J7rikNRlwhaMYDD8LGVAVJzNJ-jEPksUIn2LB2LCdNRzfAhgbxdQcWT9ktlc9M1EhmTLccEqfnWdGL9G1","y":"AfHPUW3GYzzqbTczcYR0nYMVMFVrYsUxv4uiuSNV_XRN3Jf8zeYbbOLJv4S3bUytO7qHY8bfZxPxR9nn3BBTf5ol"}]}`)

	// Create the JWKs from the resource at the given URL.
	jwks, err := keyfunc.NewJSON(jwksJSON)
	if err != nil {
		log.Fatalf("Failed to create JWKs from JSON.\nError: %s", err.Error())
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
}
