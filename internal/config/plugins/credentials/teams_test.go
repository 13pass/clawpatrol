package credentials

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const teamsTestURL = "https://default0f.70.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig=s3cret"

func TestTeamsValidateChannel(t *testing.T) {
	ok := runtime.UserChannel{Target: "my chat", Secret: teamsTestURL}
	if err := (&TeamsWorkflow{}).ValidateChannel(ok); err != nil {
		t.Fatalf("valid webhook refused: %v", err)
	}
	for name, ch := range map[string]runtime.UserChannel{
		"no label":      {Secret: teamsTestURL},
		"http":          {Target: "x", Secret: strings.Replace(teamsTestURL, "https:", "http:", 1)},
		"connector":     {Target: "x", Secret: "https://unitednations.webhook.office.com/webhookb2/a@b/IncomingWebhook/c/d"},
		"other host":    {Target: "x", Secret: "https://evil.example/workflows/abc?sig=s"},
		"suffix trick":  {Target: "x", Secret: "https://environment.api.powerplatform.com.evil.example/workflows/abc?sig=s"},
		"no signature":  {Target: "x", Secret: strings.Replace(teamsTestURL, "&sig=s3cret", "", 1)},
		"userinfo":      {Target: "x", Secret: strings.Replace(teamsTestURL, "https://", "https://u:p@", 1)},
		"not a trigger": {Target: "x", Secret: "https://default0f.70.environment.api.powerplatform.com/other?sig=s"},
	} {
		if err := (&TeamsWorkflow{}).ValidateChannel(ch); err == nil {
			t.Errorf("%s: accepted %q", name, ch.Secret)
		}
	}
}

// teamsTestServer serves a fake webhook and points the plugin at it.
func teamsTestServer(t *testing.T, status int) (*httptest.Server, string, chan map[string]any) {
	t.Helper()
	got := make(chan map[string]any, 2)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var card map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &card)
		got <- card
		rw.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	hosts, client, backoff := teamsWebhookHosts, teamsHTTPClient, teamsRetryBackoff
	tlsClient := srv.Client()
	tlsClient.CheckRedirect = teamsNoRedirect
	teamsWebhookHosts, teamsHTTPClient, teamsRetryBackoff = []string{u.Hostname()}, tlsClient, 0
	t.Cleanup(func() { teamsWebhookHosts, teamsHTTPClient, teamsRetryBackoff = hosts, client, backoff })
	return srv, srv.URL + "/workflows/abc/triggers/manual/paths/invoke?sig=s3cret", got
}

func TestTeamsNotifyPostsAnEscapedCard(t *testing.T) {
	_, hook, got := teamsTestServer(t, http.StatusAccepted)
	err := (&TeamsWorkflow{}).NotifyHITL(context.Background(), runtime.ApproveRequest{
		Method: "POST", Host: "gitlab.com", Path: "/api/v4/[click](https://evil.example)", Profile: "team-a",
	}, runtime.HITLTarget{Secret: hook, DashboardURL: "https://gw.example.test/", PendingID: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(<-got)
	s := string(raw)
	if !strings.Contains(s, `\\[click\\](https://evil.example)`) {
		t.Errorf("request path not escaped: %s", s)
	}
	if !strings.Contains(s, `"url":"https://gw.example.test/#hitl/p1"`) {
		t.Errorf("no dashboard button: %s", s)
	}
}

func TestTeamsErrorsNeverCarryTheWebhookURL(t *testing.T) {
	srv, hook, got := teamsTestServer(t, http.StatusInternalServerError)
	err := (&TeamsWorkflow{}).SendChannelText(context.Background(), nil, "", runtime.UserChannel{Target: "x", Secret: hook}, "hi")
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("err = %v, want an error without the signature", err)
	}
	if len(got) != 2 {
		t.Fatalf("posted %d times, want a retry after a 500", len(got))
	}
	srv.Close()
	err = (&TeamsWorkflow{}).SendChannelText(context.Background(), nil, "", runtime.UserChannel{Target: "x", Secret: hook}, "hi")
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("connection error = %v, want one without the signature", err)
	}
}
