package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const scopedRuleTestConfig = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "gitlab" { hosts = ["gitlab.com"] }
credential "bearer_token" "gl" { endpoint = https.gitlab }
credential "slack_tokens" "ops-slack" {}
approver "human_approver" "team-a-review" {
  channel    = "#team-a"
  credential = slack_tokens.ops-slack
}
profile "team-a" { credentials = [bearer_token.gl] }
profile "team-b" { credentials = [bearer_token.gl] }
`

func scopedRuleTestDir(t *testing.T) (string, *config.CompiledPolicy) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00-base.hcl"), []byte(scopedRuleTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cp, err := loadConfig(dir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return dir, cp
}

func notesEvent() *Event {
	return &Event{
		ID:         "0190-notes",
		Endpoint:   "gitlab",
		Family:     "http",
		Host:       "gitlab.com",
		Method:     "POST",
		Path:       "/api/v4/projects/123/issues/45/notes",
		Credential: "gl",
		Profile:    "team-a",
		ReqHeaders: map[string]string{"X-Uninfo-Caller": "agent-ops", "Authorization": "***"},
	}
}

// installRule loads the generated HCL next to the base config and
// returns the compiled gitlab endpoint.
func installRule(t *testing.T, dir string, rule *ScopedRule) *config.CompiledEndpoint {
	t.Helper()
	_, cp, err := loadConfigOverlay(dir, map[string][]byte{"50-user-alice.hcl": []byte(rule.HCL)})
	if err != nil {
		t.Fatalf("generated HCL does not load:\n%s\n%v", rule.HCL, err)
	}
	return cp.Endpoints["gitlab"]
}

func httpReq(method, path, profile string, headers map[string]string) *match.Request {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &match.Request{Family: "http", Method: method, URL: &url.URL{Path: path}, Headers: h, Credential: "gl", Profile: profile}
}

func matchedRule(ep *config.CompiledEndpoint, req *match.Request) string {
	if r := runtime.MatchRequest(ep, req); r != nil {
		return r.Name
	}
	return ""
}

func TestScopedMemberRuleIsPinnedToTheMembersProfile(t *testing.T) {
	dir, cp := scopedRuleTestDir(t)
	author := &RuleAuthor{Username: "alice"}
	rule, err := GenerateScopedRule(cp, notesEvent(), RuleRequest{Verdict: ruleVerdictDeny, Scope: ruleScopeExact}, author)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rule.RuleName, "alice-") {
		t.Errorf("rule name %q lacks the member prefix", rule.RuleName)
	}
	for _, want := range []string{"profile    = profile.team-a", "credential = bearer_token.gl", "priority   = 50"} {
		if !strings.Contains(rule.HCL, want) {
			t.Errorf("HCL lacks %q:\n%s", want, rule.HCL)
		}
	}
	ep := installRule(t, dir, rule)
	path := "/api/v4/projects/123/issues/45/notes"
	if got := matchedRule(ep, httpReq("POST", path, "team-a", nil)); got != rule.RuleName {
		t.Errorf("team-a request matched %q, want the member rule", got)
	}
	if got := matchedRule(ep, httpReq("POST", path, "team-b", nil)); got != "" {
		t.Errorf("team-b request matched %q: the rule leaked to a profile sharing the credential", got)
	}
}

func TestScopedRuleScopes(t *testing.T) {
	dir, cp := scopedRuleTestDir(t)
	cases := []struct {
		scope        string
		method, path string
		want         bool
	}{
		{ruleScopeExact, "POST", "/api/v4/projects/123/issues/45/notes", true},
		{ruleScopeExact, "GET", "/api/v4/projects/123/issues/45/notes", false},
		{ruleScopeAnyMethod, "GET", "/api/v4/projects/123/issues/45/notes", true},
		{ruleScopeAnyMethod, "POST", "/api/v4/projects/123/issues/46/notes", false},
		{ruleScopePattern, "POST", "/api/v4/projects/999/issues/1/notes", true},
		{ruleScopePattern, "POST", "/api/v4/projects/999/issues/1/notes/7", false},
		{ruleScopePattern, "GET", "/api/v4/projects/999/issues/1/notes", false},
	}
	for _, tc := range cases {
		rule, err := GenerateScopedRule(cp, notesEvent(), RuleRequest{Verdict: ruleVerdictAllow, Scope: tc.scope}, &RuleAuthor{Username: "alice"})
		if err != nil {
			t.Fatalf("%s: %v", tc.scope, err)
		}
		ep := installRule(t, dir, rule)
		if got := matchedRule(ep, httpReq(tc.method, tc.path, "team-a", nil)) != ""; got != tc.want {
			t.Errorf("%s %s %s: matched = %v, want %v\n%s", tc.scope, tc.method, tc.path, got, tc.want, rule.HCL)
		}
	}
}

func TestScopedRuleHeaderPin(t *testing.T) {
	dir, cp := scopedRuleTestDir(t)
	req := RuleRequest{Verdict: ruleVerdictAllow, Scope: ruleScopeExact, PinHeader: "x-uninfo-caller"}
	rule, err := GenerateScopedRule(cp, notesEvent(), req, &RuleAuthor{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	ep := installRule(t, dir, rule)
	path := "/api/v4/projects/123/issues/45/notes"
	if got := matchedRule(ep, httpReq("POST", path, "team-a", map[string]string{"X-Uninfo-Caller": "agent-ops"})); got != rule.RuleName {
		t.Errorf("same caller matched %q", got)
	}
	if got := matchedRule(ep, httpReq("POST", path, "team-a", map[string]string{"X-Uninfo-Caller": "agent-other"})); got != "" {
		t.Errorf("other caller matched %q", got)
	}
	// No header at all must fall through, not fire a synthesized deny.
	if r := runtime.MatchRequest(ep, httpReq("POST", path, "team-a", nil)); r != nil {
		t.Errorf("request without the header matched %q (verdict %q)", r.Name, r.Outcome.Verdict)
	}

	for _, bad := range []string{"Authorization", "X-Absent"} {
		if _, err := GenerateScopedRule(cp, notesEvent(), RuleRequest{Verdict: ruleVerdictAllow, PinHeader: bad}, nil); err == nil {
			t.Errorf("pin on header %q accepted", bad)
		}
	}
}

func TestScopedRuleApproveRoutesToTheMembersApprover(t *testing.T) {
	dir, cp := scopedRuleTestDir(t)
	cases := map[string]string{"team-a-review": "human_approver.team-a-review", "": dashboardApproverRef}
	for approver, wantRef := range cases {
		rule, err := GenerateScopedRule(cp, notesEvent(),
			RuleRequest{Verdict: ruleVerdictApprove, Approver: "ignored-for-members"},
			&RuleAuthor{Username: "alice", Approver: approver})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rule.HCL, "approve    = ["+wantRef+"]") {
			t.Errorf("approver %q: HCL\n%s\nwant approve = [%s]", approver, rule.HCL, wantRef)
		}
		ep := installRule(t, dir, rule)
		r := runtime.MatchRequest(ep, httpReq("POST", "/api/v4/projects/123/issues/45/notes", "team-a", nil))
		if r == nil || len(r.Outcome.Approve) != 1 {
			t.Fatalf("approver %q: matched %+v", approver, r)
		}
	}
}

func TestScopedRuleRefusals(t *testing.T) {
	_, cp := scopedRuleTestDir(t)
	noProfile := notesEvent()
	noProfile.Profile = ""
	hostOnly := &Event{ID: "h", Host: "example.org", Method: "GET", Path: "/", Profile: "team-a"}
	cases := []struct {
		name string
		ev   *Event
		req  RuleRequest
	}{
		{"bad verdict", notesEvent(), RuleRequest{Verdict: "maybe"}},
		{"bad scope", notesEvent(), RuleRequest{Verdict: ruleVerdictDeny, Scope: ruleScopeAnyName}},
		{"no profile", noProfile, RuleRequest{Verdict: ruleVerdictDeny}},
		{"allow unknown host", hostOnly, RuleRequest{Verdict: ruleVerdictAllow}},
		{"pattern unknown host", hostOnly, RuleRequest{Verdict: ruleVerdictDeny, Scope: ruleScopePattern}},
	}
	for _, tc := range cases {
		if _, err := GenerateScopedRule(cp, tc.ev, tc.req, &RuleAuthor{Username: "alice"}); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestPathPattern(t *testing.T) {
	cases := map[string]string{
		"/api/v4/projects/123/issues":                         `^/api/v4/projects/[^/]+/issues$`,
		"/api/v4/projects/unrcs%2Fdco/merge_requests/9":       `^/api/v4/projects/[^/]+/merge_requests/[^/]+$`,
		"/repos/x/commits/0123456789abcdef0123":               `^/repos/x/commits/[^/]+$`,
		"/v1/items/3f2b8c1e-1d2a-4b5c-9e8f-0a1b2c3d4e5f.json": `^/v1/items/3f2b8c1e-1d2a-4b5c-9e8f-0a1b2c3d4e5f\.json$`,
	}
	for in, want := range cases {
		if got, _ := pathPattern(in); got != want {
			t.Errorf("pathPattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRuleMatchesEventReplaysRecordedRequests(t *testing.T) {
	_, cp := scopedRuleTestDir(t)
	rule, err := GenerateScopedRule(cp, notesEvent(), RuleRequest{Verdict: ruleVerdictDeny, Scope: ruleScopePattern}, &RuleAuthor{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	other := notesEvent()
	other.Path = "/api/v4/projects/7/issues/8/notes"
	teamB := notesEvent()
	teamB.Profile = "team-b"
	read := notesEvent()
	read.Method = "GET"
	for name, tc := range map[string]struct {
		ev   *Event
		want bool
	}{"other ids": {other, true}, "team-b": {teamB, false}, "GET": {read, false}} {
		matched, ok := ruleMatchesEvent(rule, tc.ev)
		if !ok || matched != tc.want {
			t.Errorf("%s: matched = %v ok = %v, want %v", name, matched, ok, tc.want)
		}
	}
}
