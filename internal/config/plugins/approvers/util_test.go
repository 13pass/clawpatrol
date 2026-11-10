package approvers

import (
	"net/http"
	"testing"
)

func TestBuildPendingMasksSensitiveHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Add("X-Trace", "a")
	h.Add("X-Trace", "b")
	h.Set("Authorization", "Bearer placeholder")
	h.Set("Private-Token", "placeholder")

	got := buildPending(approveRequestWithHeaders(h)).Headers

	want := map[string]string{
		"Content-Type":  "application/json",
		"X-Trace":       "a, b",
		"Authorization": "***",
		"Private-Token": "***",
	}
	if len(got) != len(want) {
		t.Fatalf("Headers = %v, want %v", got, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("Headers[%q] = %q, want %q", name, got[name], value)
		}
	}
}

func TestBuildPendingWithoutRequestHasNoHeaders(t *testing.T) {
	req := approveRequestWithHeaders(nil)
	req.Request = nil

	if got := buildPending(req).Headers; len(got) != 0 {
		t.Fatalf("Headers = %v, want none", got)
	}
}

func TestBuildPendingFlagsBodyTheApproverCannotSee(t *testing.T) {
	req := approveRequestWithHeaders(nil)
	req.Request.Truncated = true
	req.Request.BodyNotCaptured = true

	got := buildPending(req)

	if !got.BodyTruncated || !got.BodyNotCaptured {
		t.Fatalf("BodyTruncated = %v, BodyNotCaptured = %v, want both true", got.BodyTruncated, got.BodyNotCaptured)
	}
}
