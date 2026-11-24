package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestDeviceFlowSendsIntentAndMachineAndStopsOnRejection(t *testing.T) {
	var startQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/onboard/start":
			startQuery = r.URL.Query()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "device-code",
				"user_code":   "WXYZ-4821",
				"verify_url":  "http://100.64.0.1/#/onboard/WXYZ-4821",
				"interval":    -1,
				"expires_in":  5,
			})
		case "/api/onboard/poll":
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "server_error", "detail": "rejected on the dashboard"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	setup := joinSetup{intent: "intent-123"}
	_, err := onboardViaDeviceFlow(srv.URL, false, "", "", &setup, true, srv.Client(), false)
	if err == nil || !strings.Contains(err.Error(), "rejected on the dashboard") {
		t.Fatalf("onboardViaDeviceFlow error = %v, want the rejection", err)
	}
	if got := startQuery.Get("intent"); got != "intent-123" {
		t.Errorf("start intent = %q, want intent-123", got)
	}
	if got := startQuery.Get("os"); got != runtime.GOOS {
		t.Errorf("start os = %q, want %q", got, runtime.GOOS)
	}
	if got := startQuery.Get("os_user"); got != currentOSUser() {
		t.Errorf("start os_user = %q, want %q", got, currentOSUser())
	}
	osHost, _ := os.Hostname()
	if got := startQuery.Get("os_hostname"); got != osHost {
		t.Errorf("start os_hostname = %q, want %q", got, osHost)
	}
	// Without --hostname the gateway names an intent join itself.
	if startQuery.Has("hostname") {
		t.Errorf("start hostname = %q, want none without --hostname", startQuery.Get("hostname"))
	}

	_, _ = onboardViaDeviceFlow(srv.URL, false, "", "devbox-gemma", &setup, true, srv.Client(), false)
	if got := startQuery.Get("hostname"); got != "devbox-gemma" {
		t.Errorf("start hostname = %q, want the --hostname devbox-gemma", got)
	}
}
