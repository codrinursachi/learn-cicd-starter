package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeySuccess(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey secret-token")
	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret-token" {
		t.Fatalf("expected token %q, got %q", "secret-token", got)
	}
}

func TestGetAPIKeyFailures(t *testing.T) {
	t.Run("missing header", func(t *testing.T) {
		_, err := GetAPIKey(http.Header{})
		if err != ErrNoAuthHeaderIncluded {
			t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer not-api-key")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatalf("expected error for malformed header, got nil")
		}
	})
}

func TestGetAPIKeyIgnoresExtraSegments(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey secret-token extra-data")
	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("unexpected error when extra segments are present: %v", err)
	}
	if got != "secret-token" {
		t.Fatalf("expected token %q, got %q", "secret-token", got)
	}
}
