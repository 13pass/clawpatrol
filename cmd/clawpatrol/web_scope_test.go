package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestMemberStateIsScopedToOwnProfiles(t *testing.T) {
	env := newRulesTestEnv(t, true)
	rw := serveAs(t, env.h, env.alice, http.MethodGet, "/api/state", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("member GET /api/state = %d %s", rw.Code, rw.Body.String())
	}
	var state struct {
		Integrations []IntegrationRow `json:"integrations"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, row := range state.Integrations {
		got[row.ID] = row.Manageable
	}
	// gl is shared with team-b: visible, not manageable. sentry-a is
	// team-a's alone. ops-slack belongs to no profile of alice's.
	if manage, ok := got["gl"]; !ok || manage {
		t.Errorf("gl: visible=%v manageable=%v, want visible and not manageable", ok, manage)
	}
	if manage, ok := got["sentry-a"]; !ok || !manage {
		t.Errorf("sentry-a: visible=%v manageable=%v, want both", ok, manage)
	}
	if _, ok := got["ops-slack"]; ok {
		t.Error("ops-slack visible to alice")
	}

	// bob (team-b) sees only gl.
	rw = serveAs(t, env.h, env.bob, http.MethodGet, "/api/status", "")
	var rows []IntegrationRow
	if err := json.Unmarshal(rw.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	if strings.Join(ids, ",") != "gl" {
		t.Errorf("bob's credentials = %v", ids)
	}
	if rw := serveAs(t, env.h, env.bob, http.MethodGet, "/api/status?profile=team-a", ""); strings.TrimSpace(rw.Body.String()) != "[]" {
		t.Errorf("bob asking for team-a's credentials got %s", rw.Body.String())
	}
}

func TestMemberProfilesAndRulesAreScoped(t *testing.T) {
	env := newRulesTestEnv(t, true)
	rw := serveAs(t, env.h, env.alice, http.MethodGet, "/api/profiles", "")
	var profiles []string
	if err := json.Unmarshal(rw.Body.Bytes(), &profiles); err != nil || strings.Join(profiles, ",") != "team-a" {
		t.Fatalf("alice's profiles = %s", rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"deny"}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	var summaries []RuleSummary
	rw = serveAs(t, env.h, env.bob, http.MethodGet, "/api/rules", "")
	if err := json.Unmarshal(rw.Body.Bytes(), &summaries); err != nil {
		t.Fatal(err)
	}
	for _, s := range summaries {
		if s.Profile != "team-b" {
			t.Errorf("bob sees a rule summary of profile %q", s.Profile)
		}
	}
}

func TestMemberEventStreamIsScoped(t *testing.T) {
	env := newRulesTestEnv(t, true)
	sink, err := NewSink(nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	env.w.g.sink = sink
	sink.Emit(Event{ID: "ev-a", Profile: "team-a", Host: "gitlab.com", Action: "allow"})
	sink.Emit(Event{ID: "ev-b", Profile: "team-b", Host: "gitlab.com", Action: "allow"})
	sink.Emit(Event{ID: "ev-none", Host: "gitlab.com", Action: "allow"})
	deadline := time.Now().Add(2 * time.Second)
	for {
		backlog, _, cancel := sink.RecentAndSubscribe()
		cancel()
		if len(backlog) == 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	stream := func(c *http.Cookie) string {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
		req.Host = "localhost"
		req.AddCookie(c)
		rw := httptest.NewRecorder()
		env.h.ServeHTTP(rw, req)
		return rw.Body.String()
	}
	alice := stream(env.alice)
	if !strings.Contains(alice, `"ev-a"`) || strings.Contains(alice, `"ev-b"`) || strings.Contains(alice, `"ev-none"`) {
		t.Errorf("alice's stream: %s", alice)
	}
	root := stream(env.root)
	if !strings.Contains(root, `"ev-b"`) || !strings.Contains(root, `"ev-none"`) {
		t.Errorf("root's stream: %s", root)
	}
}

func TestMemberCredentialChangesNeedExclusiveCredentials(t *testing.T) {
	env := newRulesTestEnv(t, true)
	forbidden := func(rw *httptest.ResponseRecorder) bool {
		return rw.Code == http.StatusForbidden && strings.Contains(rw.Body.String(), "only an admin can change this credential")
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/credentials/set",
		`{"id":"sentry-a","slots":{"token":"t0ken-value"}}`); forbidden(rw) || rw.Code >= http.StatusInternalServerError {
		t.Errorf("alice setting her own credential = %d %s", rw.Code, rw.Body.String())
	}
	for name, tc := range map[string]struct {
		c    *http.Cookie
		path string
		body string
	}{
		"alice sets shared gl":     {env.alice, "/api/credentials/set", `{"id":"gl","slots":{"token":"x"}}`},
		"alice clears ops-slack":   {env.alice, "/api/credentials/clear", `{"id":"ops-slack"}`},
		"bob clears sentry-a":      {env.bob, "/api/credentials/clear", `{"id":"sentry-a"}`},
		"bob starts oauth on gl":   {env.bob, "/api/oauth/start?id=gl", ""},
		"alice revokes unknown id": {env.alice, "/api/oauth/revoke", `{"id":"nope"}`},
	} {
		if rw := serveAs(t, env.h, tc.c, http.MethodPost, tc.path, tc.body); !forbidden(rw) {
			t.Errorf("%s = %d %s, want 403", name, rw.Code, rw.Body.String())
		}
	}
}

func TestMemberCannotFinishSomeoneElsesOAuthFlow(t *testing.T) {
	env := newRulesTestEnv(t, true)
	env.w.sessions = map[string]*oauthSession{
		"root-state": {id: "sentry-a", state: "root-state", owner: dashboardRootUsername, created: time.Now()},
	}
	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/oauth/exchange", `{"state":"root-state","code":"c"}`)
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "started by someone else") {
		t.Fatalf("alice finishing root's flow = %d %s", rw.Code, rw.Body.String())
	}
	if env.w.sessions["root-state"] == nil {
		t.Fatal("refused exchange consumed the session")
	}
}

func TestMemberDevicesAndJoinsAreScoped(t *testing.T) {
	env := newRulesTestEnv(t, true)
	reg := newOnboardRegistry()
	env.w.onboard, env.w.g.onboard = reg, reg
	reg.AssignProfile("10.68.0.5", "team-a")
	reg.AssignProfile("10.68.0.6", "team-b")

	for name, tc := range map[string]struct {
		path, body string
		want       int
	}{
		"delete bob's device":           {"/api/agents/delete?ip=10.68.0.6", "", http.StatusNotFound},
		"move own device to team-b":     {"/api/agents/profile?ip=10.68.0.5&profile=team-b", "", http.StatusForbidden},
		"move bob's device to team-a":   {"/api/agents/profile?ip=10.68.0.6&profile=team-a", "", http.StatusNotFound},
		"approve a join into team-b":    {"/api/onboard/approve", `{"code":"ABCD-EFGH","profile":"team-b"}`, http.StatusForbidden},
		"approve a join, no profile":    {"/api/onboard/approve", `{"code":"ABCD-EFGH"}`, http.StatusForbidden},
		"approve a join into team-a":    {"/api/onboard/approve", `{"code":"ABCD-EFGH","profile":"team-a"}`, http.StatusNotFound},
		"move own device within team-a": {"/api/agents/profile?ip=10.68.0.5&profile=team-a", "", http.StatusOK},
	} {
		if rw := serveAs(t, env.h, env.alice, http.MethodPost, tc.path, tc.body); rw.Code != tc.want {
			t.Errorf("%s = %d %s, want %d", name, rw.Code, rw.Body.String(), tc.want)
		}
	}
}

func TestMemberDecidesOnlyApprovalsOfTheirOwnRules(t *testing.T) {
	env := newRulesTestEnv(t, true)
	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"approve"}`)
	var created struct {
		RuleName string `json:"rule_name"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &created); err != nil || created.RuleName == "" {
		t.Fatalf("create approval rule: %d %s", rw.Code, rw.Body.String())
	}
	env.w.g.hitl = newHITLRegistry(nil)
	own, _ := env.w.g.hitl.Add(runtime.HITLPending{Profile: "team-a", Rule: created.RuleName, Host: "gitlab.com"})
	admins, _ := env.w.g.hitl.Add(runtime.HITLPending{Profile: "team-a", Rule: "gitlab-writes", Host: "gitlab.com"})
	bobs, _ := env.w.g.hitl.Add(runtime.HITLPending{Profile: "team-b", Rule: created.RuleName, Host: "gitlab.com"})

	rw = serveAs(t, env.h, env.alice, http.MethodGet, "/api/hitl/pending", "")
	var pending []runtime.HITLPending
	if err := json.Unmarshal(rw.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != own {
		t.Fatalf("alice's pending = %+v, want only %s", pending, own)
	}
	for _, id := range []string{admins, bobs} {
		if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/hitl/decide", `{"id":"`+id+`","allow":true}`); rw.Code != http.StatusNotFound {
			t.Errorf("alice deciding %s = %d, want 404", id, rw.Code)
		}
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/hitl/decide", `{"id":"`+own+`","allow":false}`); rw.Code == http.StatusNotFound || rw.Code == http.StatusForbidden {
		t.Errorf("alice deciding her own approval = %d %s", rw.Code, rw.Body.String())
	}
	rw = serveAs(t, env.h, env.root, http.MethodGet, "/api/hitl/pending", "")
	if !strings.Contains(rw.Body.String(), admins) || !strings.Contains(rw.Body.String(), bobs) {
		t.Errorf("root's pending list lacks some: %s", rw.Body.String())
	}
}

func TestMemberAnalyticsAreScoped(t *testing.T) {
	env := newRulesTestEnv(t, true)
	ids := func(c *http.Cookie) string {
		rw := serveAs(t, env.h, c, http.MethodGet, "/api/analytics?range=24h", "")
		var body struct {
			Events []Event `json:"events"`
		}
		if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
			t.Fatalf("analytics: %d %s", rw.Code, rw.Body.String())
		}
		seen := map[string]bool{}
		for _, ev := range body.Events {
			seen[ev.ID] = true
		}
		return strings.Join([]string{boolMark(seen["a-notes-45"]), boolMark(seen["b-notes-45"])}, "")
	}
	if got := ids(env.alice); got != "+-" {
		t.Errorf("alice's analytics (a-notes-45, b-notes-45) = %s, want +-", got)
	}
	if got := ids(env.root); got != "++" {
		t.Errorf("root's analytics = %s, want ++", got)
	}
}

func boolMark(b bool) string {
	if b {
		return "+"
	}
	return "-"
}

// TestEveryOtherOperatorRouteRefusesMembers: any operator route not
// opened to members — including routes added later — is refused by
// the role gate, before its handler runs.
func TestEveryOtherOperatorRouteRefusesMembers(t *testing.T) {
	env := newRulesTestEnv(t, true)
	reg := newOnboardRegistry()
	env.w.onboard, env.w.g.onboard = reg, reg
	for _, route := range env.w.routes() {
		// authTailnetOperator routes (device-code lookup) carry no
		// dashboard session: in WireGuard mode upstream serves them
		// without one, so no member identity ever reaches the gate.
		if !needsOperatorGate(route.Auth) || route.Auth == authTailnetOperator || env.w.isMemberRoute(route.Path) {
			continue
		}
		rw := serveAs(t, env.h, env.alice, route.Method, route.Path, "")
		if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "requires the admin role") {
			t.Errorf("member %s %s = %d %q, want the role gate's 403", route.Method, route.Path, rw.Code, rw.Body.String())
		}
	}
}

// TestMemberRoutesAreReviewed pins the routes members may call. Each
// one scopes what it does to the member's profiles (see the handler or
// its guard); adding one here is a reviewed decision.
func TestMemberRoutesAreReviewed(t *testing.T) {
	reviewed := []string{
		"/__logout",
		"/api/agents/delete", "/api/agents/profile", // guardDevice
		"/api/analytics",                                 // profile filter
		"/api/credentials/clear", "/api/credentials/set", // guardCredential
		"/api/events",                           // per-event filter
		"/api/facets",                           // static schema
		"/api/hitl/decide", "/api/hitl/pending", // decidesPending
		"/api/me", "/api/me/password",
		"/api/my/actions", "/api/my/rules", "/api/my/rules/delete", "/api/my/rules/update",
		"/api/oauth/device-poll", "/api/oauth/exchange", "/api/oauth/revoke", "/api/oauth/start", // guardCredential
		"/api/onboard/approve",                                     // guardOnboardApprove
		"/api/profiles", "/api/rules", "/api/state", "/api/status", // viewer filters
		"/api/rules/create", "/api/rules/preview",
		"/api/tailscale/connect", "/api/tailscale/disconnect", "/api/tailscale/status", // guardCredential
		"/oauth/callback", // static page
	}
	var got []string
	for path := range memberRoutes {
		got = append(got, path)
	}
	sort.Strings(got)
	sort.Strings(reviewed)
	if strings.Join(got, "\n") != strings.Join(reviewed, "\n") {
		t.Fatalf("member routes changed; review each new one, then update this list.\ngot:\n%s", strings.Join(got, "\n"))
	}
}

// TestCredentialGuardFailsClosedOnAmbiguousRequests replays requests
// that name one credential to the guard and another to the handler.
func TestCredentialGuardFailsClosedOnAmbiguousRequests(t *testing.T) {
	env := newRulesTestEnv(t, true)
	env.w.sessions = map[string]*oauthSession{
		"root-state":  {id: "gl", state: "root-state", owner: dashboardRootUsername, created: time.Now()},
		"alice-state": {id: "sentry-a", state: "alice-state", owner: "alice", created: time.Now()},
	}
	for name, tc := range map[string]struct{ path, body string }{
		"tailscale connect, query vs body":    {"/api/tailscale/connect?id=gl", `{"id":"sentry-a"}`},
		"tailscale disconnect, query vs body": {"/api/tailscale/disconnect?id=gl", `{"id":"sentry-a"}`},
		"oauth start, query vs body":          {"/api/oauth/start?id=gl", `{"id":"sentry-a"}`},
		"set, trailing data":                  {"/api/credentials/set?id=sentry-a", `{"id":"gl","slots":{}} x`},
		"clear, mixed-case keys":              {"/api/credentials/clear", `{"ID":"gl","id":"sentry-a"}`},
		"device poll, query vs body":          {"/api/oauth/device-poll?state=root-state", `{"state":"alice-state"}`},
		"exchange, unknown state":             {"/api/oauth/exchange", `{"state":"nope","code":"c"}`},
		"set, no id at all":                   {"/api/credentials/set", `{"slots":{}}`},
	} {
		if rw := serveAs(t, env.h, env.alice, http.MethodPost, tc.path, tc.body); rw.Code != http.StatusForbidden {
			t.Errorf("%s = %d %s, want 403", name, rw.Code, rw.Body.String())
		}
	}
}

func TestApproverCredentialsStayWithAdmins(t *testing.T) {
	dir := t.TempDir()
	src := scopedRuleTestConfig + `
credential "slack_tokens" "team-a-slack" {}
approver "human_approver" "team-a-chat" {
  channel    = "#team-a"
  credential = slack_tokens.team-a-slack
}
`
	src = strings.Replace(src, `profile "team-a" { credentials = [bearer_token.gl] }`,
		`profile "team-a" { credentials = [bearer_token.gl, slack_tokens.team-a-slack] }`, 1)
	if err := os.WriteFile(filepath.Join(dir, "00.hcl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cp, err := loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	v := viewer{username: "alice", profiles: map[string]bool{"team-a": true}}
	if v.managesCredential(cp, "team-a-slack") {
		t.Fatal("a member manages a credential an approver uses")
	}
}

func TestMemberCannotClaimAnotherTeamsJoin(t *testing.T) {
	env := newRulesTestEnv(t, true)
	reg := newOnboardRegistry()
	env.w.onboard, env.w.g.onboard = reg, reg
	bobs := reg.start()
	reg.mu.Lock()
	bobs.profile = "team-b"
	reg.mu.Unlock()
	noAsk := reg.start()

	for name, code := range map[string]string{"asked for team-b": bobs.userCode, "asked for nothing": noAsk.userCode} {
		rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/approve", `{"code":"`+code+`","profile":"team-a"}`)
		if rw.Code != http.StatusForbidden {
			t.Errorf("%s: alice approving into team-a = %d %s, want 403", name, rw.Code, rw.Body.String())
		}
	}
}
