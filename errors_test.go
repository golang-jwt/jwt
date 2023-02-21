package jwt

import (
	"errors"
	"io"
	"testing"
)

func Test_joinErrors(t *testing.T) {
	type args struct {
		errs []error
	}
	tests := []struct {
		name        string
		args        args
		wantErrors  []error
		wantMessage string
	}{
		{
			name: "multiple errors",
			args: args{
				errs: []error{ErrTokenNotValidYet, ErrTokenExpired},
			},
			wantErrors:  []error{ErrTokenNotValidYet, ErrTokenExpired},
			wantMessage: "token is not valid yet, token is expired",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := joinErrors(tt.args.errs...)
			for _, wantErr := range tt.wantErrors {
				if !errors.Is(err, wantErr) {
					t.Errorf("joinErrors() error = %v, does not contain %v", err, wantErr)
				}
			}

			if err.Error() != tt.wantMessage {
				t.Errorf("joinErrors() error.Error() = %v, wantMessage %v", err, tt.wantMessage)
			}
		})
	}
}

func Test_newError(t *testing.T) {
	type args struct {
		message string
		err     error
		more    []error
	}
	tests := []struct {
		name        string
		args        args
		wantErrors  []error
		wantMessage string
	}{
		{
			name:        "single error",
			args:        args{message: "something is wrong", err: ErrTokenMalformed},
			wantMessage: "token is malformed: something is wrong",
			wantErrors:  []error{ErrTokenMalformed},
		},
		{
			name:        "two errors",
			args:        args{message: "something is wrong", err: ErrTokenMalformed, more: []error{io.ErrUnexpectedEOF}},
			wantMessage: "token is malformed: something is wrong: unexpected EOF",
			wantErrors:  []error{ErrTokenMalformed},
		},
		{
			name:        "two errors, no detail",
			args:        args{message: "", err: ErrTokenInvalidClaims, more: []error{ErrTokenExpired}},
			wantMessage: "token has invalid claims: token is expired",
			wantErrors:  []error{ErrTokenInvalidClaims, ErrTokenExpired},
		},
		{
			name:        "two errors, no detail and join error",
			args:        args{message: "", err: ErrTokenInvalidClaims, more: []error{joinErrors(ErrTokenExpired, ErrTokenNotValidYet)}},
			wantMessage: "token has invalid claims: token is expired, token is not valid yet",
			wantErrors:  []error{ErrTokenInvalidClaims, ErrTokenExpired, ErrTokenNotValidYet},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newError(tt.args.message, tt.args.err, tt.args.more...)
			for _, wantErr := range tt.wantErrors {
				if !errors.Is(err, wantErr) {
					t.Errorf("newError() error = %v, does not contain %v", err, wantErr)
				}
			}

			if err.Error() != tt.wantMessage {
				t.Errorf("newError() error.Error() = %v, wantMessage %v", err, tt.wantMessage)
			}
		})
	}
}
