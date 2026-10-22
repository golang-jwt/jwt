package request

import (
	"net/url"
	"testing"
)

func TestOAuth2Extractor(t *testing.T) {
	const fromHeader = "token-from-bearer-header"
	const fromArg = "token-from-access_token-arg"

	tests := []struct {
		name    string
		headers map[string]string
		query   url.Values
		want    string
		wantErr error
	}{
		{
			name:    "bearer header",
			headers: map[string]string{"Authorization": "Bearer " + fromHeader},
			want:    fromHeader,
		},
		{
			name:    "bearer header takes precedence over access_token",
			headers: map[string]string{"Authorization": "Bearer " + fromHeader},
			query:   url.Values{"access_token": {fromArg}},
			want:    fromHeader,
		},
		{
			name:  "access_token when no authorization header",
			query: url.Values{"access_token": {fromArg}},
			want:  fromArg,
		},
		{
			// Regression: a present but non-Bearer Authorization header (e.g.
			// HTTP Basic) must not shadow a valid access_token argument.
			name:    "non-bearer header falls through to access_token",
			headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNzd29yZA=="},
			query:   url.Values{"access_token": {fromArg}},
			want:    fromArg,
		},
		{
			name:    "another non-bearer scheme falls through to access_token",
			headers: map[string]string{"Authorization": "Token " + fromArg},
			query:   url.Values{"access_token": {fromArg}},
			want:    fromArg,
		},
		{
			name:    "non-bearer header and no access_token",
			headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNzd29yZA=="},
			want:    "",
			wantErr: ErrNoTokenInRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := makeExampleRequest("GET", "/", tt.headers, tt.query)
			got, err := OAuth2Extractor.ExtractToken(r)
			if got != tt.want {
				t.Errorf("token = %q, want %q", got, tt.want)
			}
			if err != tt.wantErr {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
