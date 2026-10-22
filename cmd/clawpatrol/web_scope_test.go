package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
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
