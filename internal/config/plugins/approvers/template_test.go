package approvers

import (
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func approveRequestWithHeaders(h http.Header) runtime.ApproveRequest {
	return runtime.ApproveRequest{
		AgentIP: "10.0.0.7",
		Profile: "service-ops",
		Request: &match.Request{Family: "http", Headers: h},
	}
}

func TestExpandMessageHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Caller-Id", "agent-ops")
	h.Add("X-Trace", "a")
	h.Add("X-Trace", "b")
	h.Set("Authorization", "Bearer placeholder")
	h.Set("X-Api-Key", "placeholder")
	req := approveRequestWithHeaders(h)

	cases := []struct {
		tmpl, want string
	}{
		{"caller={{http.headers.X-Caller-Id}}", "caller=agent-ops"},
		{"caller={{ http.headers.x-caller-id }}", "caller=agent-ops"},
		{"trace={{http.headers.X-Trace}}", "trace=a, b"},
		{"auth={{http.headers.Authorization}}", "auth=***"},
		{"key={{http.headers.X-Api-Key}}", "key=***"},
		{"missing={{http.headers.X-Absent}}", "missing={{http.headers.X-Absent}}"},
		{"empty={{http.headers.}}", "empty={{http.headers.}}"},
	}
	for _, tc := range cases {
		if got := expandMessage(tc.tmpl, req); got != tc.want {
			t.Errorf("expandMessage(%q) = %q, want %q", tc.tmpl, got, tc.want)
		}
	}
}

func TestExpandMessageHeadersWithoutRequest(t *testing.T) {
	req := runtime.ApproveRequest{Profile: "service-ops"}
	const tmpl = "caller={{http.headers.X-Caller-Id}}"
	if got := expandMessage(tmpl, req); got != tmpl {
		t.Errorf("expandMessage(%q) = %q, want it unchanged", tmpl, got)
	}
}

func TestExpandMessageProfileIsProfileName(t *testing.T) {
	req := approveRequestWithHeaders(nil)
	if got, want := expandMessage("{{profile}}", req), "service-ops"; got != want {
		t.Errorf("expandMessage({{profile}}) = %q, want %q", got, want)
	}
}
