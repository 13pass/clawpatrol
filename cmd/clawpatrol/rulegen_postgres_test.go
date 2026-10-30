package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	sqlfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
)

const pgRelayHost = "20.1.170.46:5432"

func pgRelayEvent() *Event {
	return &Event{ID: "0190-pg", Mode: "relay", Host: pgRelayHost, Profile: "team-a", Action: "allow"}
}

func pgRequest(outcome, user string) RuleRequest {
	return RuleRequest{Postgres: &PostgresRuleInput{User: user, Outcome: outcome}}
}

func TestPostgresRelayRuleDeclaresEndpointCredentialAndProfiles(t *testing.T) {
	_, cp := scopedRuleTestDir(t)
	rule, err := GenerateScopedRule(cp, pgRelayEvent(), pgRequest(pgOutcomeApproveAll, "app"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`endpoint "postgres" "pg_20_1_170_46"`,
		`host    = "20.1.170.46:5432"`,
		`sslmode = "require"`,
		`credential "postgres_credential" "pg_20_1_170_46_login"`,
		`user     = "app"`,
		`endpoint  = postgres.pg_20_1_170_46`,
		`approve   = [builtin.dashboard]`,
		`profile "team-a"`,
		`profile "team-b"`,
	} {
		if !strings.Contains(rule.HCL, want) {
			t.Errorf("HCL lacks %q:\n%s", want, rule.HCL)
		}
	}
	if rule.NewCredential != "pg_20_1_170_46_login" || !rule.NewEndpoint || rule.Family != "sql" {
		t.Errorf("rule = %+v", rule)
	}
}

func TestPostgresLogOutcomeHasNoRule(t *testing.T) {
	_, cp := scopedRuleTestDir(t)
	rule, err := GenerateScopedRule(cp, pgRelayEvent(), pgRequest(pgOutcomeLog, "app"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rule.RuleName != "" || strings.Contains(rule.HCL, `rule "`) {
		t.Fatalf("log outcome wrote a rule:\n%s", rule.HCL)
	}
}

func TestPostgresApproveChangesLetsReadsThrough(t *testing.T) {
	_, cp := scopedRuleTestDir(t)
	rule, err := GenerateScopedRule(cp, pgRelayEvent(), pgRequest(pgOutcomeApproveChanges, "app"), nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := facet.NewMatcher("sql", rule.Condition)
	if err != nil {
		t.Fatalf("condition %q: %v", rule.Condition, err)
	}
	for verb, wantHeld := range map[string]bool{
		"select": false, "show": false, "begin": false, "commit": false, "set": false,
		"insert": true, "update": true, "delete": true, "drop": true, "truncate": true,
		"set role": true, "execute": true, "": true,
	} {
		got := m.Match(&match.Request{Family: "sql", Meta: &sqlfacet.Meta{Verb: verb}}).Result == match.Matched
		if got != wantHeld {
			t.Errorf("verb %q held = %v, want %v", verb, got, wantHeld)
		}
	}
}

func TestPostgresMemberRuleIsPinnedToTheirProfile(t *testing.T) {
	_, cp := scopedRuleTestDir(t)
	rule, err := GenerateScopedRule(cp, pgRelayEvent(), pgRequest(pgOutcomeDeny, ""), &RuleAuthor{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rule.ProfileAdditions) != 1 || rule.ProfileAdditions[0] != "team-a" {
		t.Errorf("profiles = %v, want [team-a]", rule.ProfileAdditions)
	}
	if !strings.HasPrefix(rule.EndpointName, "alice-") || !strings.Contains(rule.HCL, "credential = postgres_credential.alice-") {
		t.Errorf("member rule not namespaced or pinned:\n%s", rule.HCL)
	}
	if strings.Contains(rule.HCL, "user ") {
		t.Errorf("deny without a user still set one:\n%s", rule.HCL)
	}
}

func TestPostgresRelayRuleRefusals(t *testing.T) {
	_, cp := scopedRuleTestDir(t)
	refused := pgRelayEvent()
	refused.Action = "deny"
	web := &Event{ID: "web", Mode: "relay", Host: "20.1.170.46:80", Profile: "team-a", Action: "allow"}
	for name, tc := range map[string]struct {
		ev   *Event
		req  RuleRequest
		want string
	}{
		"no settings":        {pgRelayEvent(), RuleRequest{Verdict: ruleVerdictDeny}, "needs the database settings"},
		"no user":            {pgRelayEvent(), pgRequest(pgOutcomeApproveChanges, " "), "database user is required"},
		"bad outcome":        {pgRelayEvent(), pgRequest("allow", "app"), "outcome must be"},
		"refused relay":      {refused, pgRequest(pgOutcomeLog, "app"), "refused this connection"},
		"other protocol":     {web, RuleRequest{Verdict: ruleVerdictDeny}, "can't inspect this connection (port 80)"},
		"settings elsewhere": {notesEvent(), pgRequest(pgOutcomeLog, "app"), "only to a relayed Postgres"},
		"verify-full": {pgRelayEvent(), RuleRequest{Postgres: &PostgresRuleInput{
			User: "app", Outcome: pgOutcomeLog, SSLMode: "verify-full",
		}}, "use require"},
		"bad sslmode": {pgRelayEvent(), RuleRequest{Postgres: &PostgresRuleInput{
			User: "app", Outcome: pgOutcomeLog, SSLMode: "verify-ca",
		}}, "sslmode must be"},
		"bad name": {pgRelayEvent(), RuleRequest{Postgres: &PostgresRuleInput{
			Name: "2 db", User: "app", Outcome: pgOutcomeLog,
		}}, "may use only"},
		"taken name": {pgRelayEvent(), RuleRequest{Postgres: &PostgresRuleInput{
			Name: "gitlab", User: "app", Outcome: pgOutcomeLog,
		}}, "already exists"},
	} {
		if _, err := GenerateScopedRule(cp, tc.ev, tc.req, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestPostgresRelayRuleRefusedOnceTheAddressIsInspected(t *testing.T) {
	g := gatewayWithPolicy(t, `
endpoint "postgres" "appdb" { host = "20.1.170.46:5432" }
credential "postgres_credential" "appdb-login" {
  endpoint = postgres.appdb
  user     = "app"
}
profile "team-a" { credentials = [postgres_credential.appdb-login] }
profile "team-b" { credentials = [] }
`)
	_, err := GenerateScopedRule(g.Policy(), pgRelayEvent(), pgRequest(pgOutcomeLog, "app"), &RuleAuthor{Username: "alice"})
	if err == nil || !strings.Contains(err.Error(), `already inspected through endpoint "appdb"`) {
		t.Fatalf("err = %v", err)
	}
	ev := pgRelayEvent()
	ev.Profile = "team-b"
	rule, err := GenerateScopedRule(g.Policy(), ev, pgRequest(pgOutcomeLog, "app"), &RuleAuthor{Username: "bob"})
	if err != nil {
		t.Fatalf("other profile: %v", err)
	}
	if len(rule.Warnings) == 0 || !strings.Contains(rule.Warnings[0], `"appdb" already declares this address`) {
		t.Errorf("warnings = %v", rule.Warnings)
	}
}

// emitEvents records events the way the gateway does, for handlers
// that load actions by id.
func emitEvents(t *testing.T, env *rulesTestEnv, events ...Event) {
	t.Helper()
	sink, err := NewSink(env.w.g.db, len(events))
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		sink.Emit(ev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMemberCreatesPostgresEndpointAndSetsItsPassword(t *testing.T) {
	env := newRulesTestEnv(t, true)
	emitEvents(t, env, *pgRelayEvent())
	req := `{"action_id":"0190-pg","postgres":{"user":"app","outcome":"approve_changes"}}`

	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/preview", req)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `"recent_sampled":1`) {
		t.Fatalf("preview = %d %s", rw.Code, rw.Body.String())
	}
	rw = serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", req)
	if rw.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rw.Code, rw.Body.String())
	}
	var created struct {
		RuleName      string `json:"rule_name"`
		EndpointName  string `json:"endpoint_name"`
		NewCredential string `json:"new_credential"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.RuleName == "" || created.NewCredential == "" {
		t.Fatalf("create response = %s", rw.Body.String())
	}

	profiles := readCfgFile(t, env.w, "20-profiles.hcl")
	teamA := profiles[:strings.Index(profiles, `profile "team-b"`)]
	teamB := profiles[strings.Index(profiles, `profile "team-b"`):]
	if !strings.Contains(teamA, "postgres_credential."+created.NewCredential) || strings.Contains(teamB, "postgres_credential.") {
		t.Fatalf("credential not merged into team-a only:\n%s", profiles)
	}
	ep := env.w.g.Policy().Endpoints[created.EndpointName]
	if ep == nil || ep.Plugin.Type != "postgres" || len(ep.Rules) != 1 {
		t.Fatalf("endpoint %q = %+v", created.EndpointName, ep)
	}

	rw = serveAs(t, env.h, env.alice, http.MethodPost, "/api/credentials/set",
		`{"id":"`+created.NewCredential+`","slots":{"":"s3cret"}}`)
	if rw.Code != http.StatusOK {
		t.Fatalf("set password = %d %s", rw.Code, rw.Body.String())
	}
}

func TestAdminPostgresLogOutcomeCreatesNoRule(t *testing.T) {
	env := newRulesTestEnv(t, true)
	emitEvents(t, env, *pgRelayEvent())
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/create",
		`{"action_id":"0190-pg","postgres":{"user":"app","outcome":"log"}}`)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `"rule_name":""`) {
		t.Fatalf("create = %d %s", rw.Code, rw.Body.String())
	}
	got := readCfgFile(t, env.w, dashboardConfigFile)
	if !strings.Contains(got, `endpoint "postgres"`) || strings.Contains(got, `rule "`) {
		t.Fatalf("dashboard file:\n%s", got)
	}
}

func TestPostgresRuleRefusedForAnAddressTheRelayRefuses(t *testing.T) {
	env := newRulesTestEnv(t, true)
	private := *pgRelayEvent()
	private.ID, private.Host = "0190-pg-private", "10.1.2.3:5432"
	emitEvents(t, env, private)
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/preview",
		`{"action_id":"0190-pg-private","postgres":{"user":"app","outcome":"log"}}`)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("preview for a private address = %d %s", rw.Code, rw.Body.String())
	}
}
