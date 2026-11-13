package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAdminWritesARuleForAnEndpoint(t *testing.T) {
	env := newRulesTestEnv(t, true)
	req := `{"endpoint":"gitlab","verdict":"deny","condition":"http.method == 'DELETE'"}`
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/preview", req); rw.Code != http.StatusOK ||
		!strings.Contains(rw.Body.String(), `"hand_written":true`) {
		t.Fatalf("preview = %d %s", rw.Code, rw.Body.String())
	}
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/create", req)
	if rw.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rw.Code, rw.Body.String())
	}
	var out struct {
		RuleName string `json:"rule_name"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readCfgFile(t, env.w, dashboardConfigFile), `condition = "http.method == 'DELETE'"`) {
		t.Errorf("%s:\n%s", dashboardConfigFile, readCfgFile(t, env.w, dashboardConfigFile))
	}
	if env.w.g.cfg.Load().Policy.Rules[out.RuleName] == nil {
		t.Errorf("rule %q did not load", out.RuleName)
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/create", req); rw.Code != http.StatusConflict {
		t.Errorf("the same rule twice = %d, want 409", rw.Code)
	}
}

func TestEndpointRuleWithoutConditionMatchesEveryRequest(t *testing.T) {
	env := newRulesTestEnv(t, true)
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/create", `{"endpoint":"sentry","verdict":"deny"}`)
	if rw.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, dashboardConfigFile); strings.Contains(got, "condition") ||
		!strings.Contains(strings.Join(strings.Fields(got), " "), "endpoint = https.sentry") {
		t.Errorf("%s:\n%s", dashboardConfigFile, got)
	}
}

func TestEndpointRuleRefusals(t *testing.T) {
	env := newRulesTestEnv(t, true)
	cases := []struct {
		who  *http.Cookie
		body string
		code int
	}{
		{env.alice, `{"endpoint":"gitlab","verdict":"deny","condition":"http.method == 'DELETE'"}`, http.StatusForbidden},
		{env.root, `{"endpoint":"nope","verdict":"deny"}`, http.StatusBadRequest},
		{env.root, `{"endpoint":"gitlab","verdict":"deny","condition":"http.nope == 1"}`, http.StatusBadRequest},
		{env.root, `{"endpoint":"gitlab","verdict":"none"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		if rw := serveAs(t, env.h, c.who, http.MethodPost, "/api/rules/create", c.body); rw.Code != c.code {
			t.Errorf("%s = %d %s, want %d", c.body, rw.Code, rw.Body.String(), c.code)
		}
	}
}

func TestAdminAddsTheDefaultRulesToAnEndpoint(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if err := setNewEndpointRules(t, env.w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	rw := serveAs(t, env.h, env.root, http.MethodGet, "/api/my/rules", "")
	if !strings.Contains(rw.Body.String(), `"default_rules":["no-delete","writes"]`) {
		t.Errorf("/api/my/rules = %s, want the default rule names", rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/endpoint-defaults", `{"endpoint":"gitlab"}`); rw.Code != http.StatusForbidden {
		t.Errorf("member = %d, want 403", rw.Code)
	}
	rw = serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/endpoint-defaults", `{"endpoint":"gitlab"}`)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `"default_rules":["gitlab-no-delete","gitlab-writes"]`) {
		t.Fatalf("add defaults = %d %s", rw.Code, rw.Body.String())
	}
	rules := env.w.g.cfg.Load().Policy.Rules
	if rules["gitlab-no-delete"] == nil || rules["gitlab-writes"] == nil {
		t.Error("the default rules did not load")
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/endpoint-defaults", `{"endpoint":"gitlab"}`); rw.Code != http.StatusConflict {
		t.Errorf("a second time = %d, want 409", rw.Code)
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/endpoint-defaults", `{"endpoint":"nope"}`); rw.Code != http.StatusNotFound {
		t.Errorf("unknown endpoint = %d, want 404", rw.Code)
	}
}
