package credentials

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestBasicAuthInjectHTTPStampsAuthorization(t *testing.T) {
	plugin := &BasicAuth{Username: "agent"}
	req, err := http.NewRequest("GET", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:PH_password")))

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte("real-password")}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("agent:real-password"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestBasicAuthInjectHTTPIgnoresEmptySecret(t *testing.T) {
	plugin := &BasicAuth{Username: "agent"}
	req, err := http.NewRequest("GET", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Basic placeholder")

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Basic placeholder" {
		t.Fatalf("Authorization = %q, want original placeholder", got)
	}
}

func TestBasicAuthSecretSlots(t *testing.T) {
	slots := (&BasicAuth{Username: "agent"}).SecretSlots()
	if len(slots) != 1 {
		t.Fatalf("want 1 slot, got %d", len(slots))
	}
	if slots[0].Name != "" {
		t.Errorf("slot name = %q, want unnamed password slot", slots[0].Name)
	}
	if slots[0].Label != "Password" || slots[0].Description == "" {
		t.Errorf("slot missing label/description: %+v", slots[0])
	}
}

func TestBasicAuthWithoutUsernameAsksForIt(t *testing.T) {
	slots := (&BasicAuth{}).SecretSlots()
	if len(slots) != 2 || slots[0].Name != basicAuthUsernameSlot || !slots[0].Visible || slots[1].Name != "" {
		t.Fatalf("slots = %+v, want a visible username slot, then the unnamed password slot", slots)
	}
}

func TestBasicAuthInjectHTTPUsesTheStoredUsername(t *testing.T) {
	plugin := &BasicAuth{}
	sec := runtime.Secret{Bytes: []byte("api-token"), Extras: map[string]string{basicAuthUsernameSlot: "alice@example.org"}}
	req, err := http.NewRequest("GET", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := plugin.InjectHTTP(req.Context(), req, sec); err != nil {
		t.Fatalf("inject: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice@example.org:api-token"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestBasicAuthInjectHTTPNamesTheMissingHalf(t *testing.T) {
	for name, sec := range map[string]runtime.Secret{
		"Password": {Extras: map[string]string{basicAuthUsernameSlot: "alice@example.org"}},
		"Username": {Bytes: []byte("api-token")},
	} {
		req, err := http.NewRequest("GET", "https://example.com/api", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		err = (&BasicAuth{}).InjectHTTP(req.Context(), req, sec)
		if err == nil || !strings.Contains(err.Error(), "missing "+name) {
			t.Errorf("missing %s: err = %v, want one naming it", name, err)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("missing %s: Authorization = %q, want none", name, got)
		}
	}
}

func TestBasicAuthMissingSecretSlots(t *testing.T) {
	b := &BasicAuth{}
	if got := b.MissingSecretSlots(map[string]bool{basicAuthUsernameSlot: true}); len(got) != 1 || got[0] != "Password" {
		t.Errorf("username only: missing = %v, want [Password]", got)
	}
	if got := b.MissingSecretSlots(map[string]bool{basicAuthUsernameSlot: true, "": true}); len(got) != 0 {
		t.Errorf("both: missing = %v, want none", got)
	}
	if got := (&BasicAuth{Username: "agent"}).MissingSecretSlots(map[string]bool{"": true}); len(got) != 0 {
		t.Errorf("configured username: missing = %v, want none", got)
	}
}
