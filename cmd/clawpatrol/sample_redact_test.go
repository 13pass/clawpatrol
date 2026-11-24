package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/plugins/credentials"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestInjectedHeaderSecrets(t *testing.T) {
	before := http.Header{"Accept": {"*/*"}, "Authorization": {"Bearer PH_placeholder_1"}}
	after := before.Clone()
	after.Set("Authorization", "Basic dXNlcjpzM2NyZXQtcGFzc3dvcmQ=")
	after.Set("X-Amz-Date", "20260909T000000Z")
	after.Set("X-Short", "abc")
	got := injectedHeaderSecrets(before, after)
	want := map[string]bool{
		"Basic dXNlcjpzM2NyZXQtcGFzc3dvcmQ=": true,
		"dXNlcjpzM2NyZXQtcGFzc3dvcmQ=":       true,
		"20260909T000000Z":                   true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %d values", got, len(want))
	}
	for _, v := range got {
		if !want[v] {
			t.Fatalf("unexpected redaction %q in %q", v, got)
		}
	}
	if s := redactCredentialSample("echo: Authorization: Basic dXNlcjpzM2NyZXQtcGFzc3dvcmQ= ok", got); strings.Contains(s, "dXNlcjpz") {
		t.Fatalf("derived credential survived redaction: %q", s)
	}
}

func TestCredentialRedactionsSkipVisibleSlots(t *testing.T) {
	sec := runtime.Secret{Bytes: []byte("api-token-value"), Extras: map[string]string{"username": "api"}}
	got := appendCredentialSecretRedactions(nil, sec, &credentials.BasicAuth{})
	if len(got) != 1 || got[0] != "api-token-value" {
		t.Errorf("redactions = %q, want only the password", got)
	}
}
