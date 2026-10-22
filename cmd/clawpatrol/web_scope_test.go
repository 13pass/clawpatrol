package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
