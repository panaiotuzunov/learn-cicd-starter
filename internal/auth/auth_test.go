package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "no authorization header",
			headers:     http.Header{},
			wantKey:     "",
			wantErr:     true,
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:     "",
			wantErr:     true,
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey:     "",
			wantErr:     true,
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey super-secret-key"},
			},
			wantKey:     "super-secret-key",
			wantErr:     false,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.expectedErr.Error() {
					t.Errorf("expected error %q, got %q", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if gotKey != tt.wantKey {
					t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
				}
			}
		})
	}
}
