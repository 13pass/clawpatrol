package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const rulesTestBase = `endpoint "https" "gitlab" { hosts = ["gitlab.com"] }
credential "bearer_token" "gl" { endpoint = https.gitlab }
endpoint "https" "sentry" { hosts = ["sentry.io"] }
credential "bearer_token" "sentry-a" { endpoint = https.sentry }
credential "slack_tokens" "ops-slack" {}
approver "human_approver" "team-a-review" {
  channel    = "#team-a"
  credential = slack_tokens.ops-slack
}
`

const rulesTestProfiles = `profile "team-a" {
  credentials = [bearer_token.gl, bearer_token.sentry-a]
}

profile "team-b" {
  credentials = [bearer_token.gl]
}
`

type rulesTestEnv struct {
	w                    *webMux
	h                    http.Handler
	root, alice, bob     *http.Cookie
	aliceNotes, bobNotes string
	aliceHost            string
}

func newRulesTestEnv(t *testing.T, writes bool) *rulesTestEnv {
	t.Helper()
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "gateway.d")
	if err := os.Mkdir(cfgDir, 0o750); err != nil {
		t.Fatal(err)
	}
	gatewayHCL := `gateway {
  state_dir  = "` + filepath.ToSlash(dir) + `"
  public_url = "https://gw.example.test"
  dashboard_config_writes = ` + map[bool]string{true: "true", false: "false"}[writes] + `
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
`
	for name, src := range map[string]string{"00-gateway.hcl": gatewayHCL, "10-base.hcl": rulesTestBase, "20-profiles.hcl": rulesTestProfiles} {
		if err := os.WriteFile(filepath.Join(cfgDir, name), []byte(src), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	cfg, policy, err := loadConfig(cfgDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{cfgPath: cfgDir, stateDir: dir, db: db}
	g.cfg.Store(cfg)
	g.policy.Store(policy)
	w := &webMux{g: g}

	if err := setDashboardUser(db, dashboardRootUsername, usersTestRootPassword); err != nil {
		t.Fatal(err)
	}
	for user, profile := range map[string]string{"alice": "team-a", "bob": "team-b"} {
		if err := createDashboardUser(db, user, usersTestMemberPassword, dashboardRoleMember); err != nil {
			t.Fatal(err)
		}
		if err := setDashboardUserProfiles(db, user, []string{profile}); err != nil {
			t.Fatal(err)
		}
	}
	if err := setDashboardUserApprover(db, "alice", "team-a-review"); err != nil {
		t.Fatal(err)
	}

	sink, err := NewSink(db, 16)
	if err != nil {
		t.Fatal(err)
	}
	env := &rulesTestEnv{w: w, aliceNotes: "a-notes-45", bobNotes: "b-notes-45", aliceHost: "a-host"}
	for _, ev := range []Event{
		{ID: "a-notes-12", Profile: "team-a", Endpoint: "gitlab", Family: "http", Host: "gitlab.com", Method: "POST", Path: "/api/v4/projects/123/issues/12/notes", Credential: "gl", Action: "allow"},
		{ID: env.aliceNotes, Profile: "team-a", Endpoint: "gitlab", Family: "http", Host: "gitlab.com", Method: "POST", Path: "/api/v4/projects/123/issues/45/notes", Credential: "gl", Action: "allow"},
		{ID: env.bobNotes, Profile: "team-b", Endpoint: "gitlab", Family: "http", Host: "gitlab.com", Method: "POST", Path: "/api/v4/projects/9/issues/45/notes", Credential: "gl", Action: "allow"},
		{ID: env.aliceHost, Profile: "team-a", Family: "http", Host: "example.org", Method: "GET", Path: "/", Action: "allow", Mode: "splice"},
	} {
		sink.Emit(ev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}

	env.h = w.handler()
	env.root = sessionCookieFor(t, w, dashboardRootUsername)
	env.alice = sessionCookieFor(t, w, "alice")
	env.bob = sessionCookieFor(t, w, "bob")
	return env
}

func TestMyActionsAreScopedToOwnProfiles(t *testing.T) {
	env := newRulesTestEnv(t, true)
	ids := func(c *http.Cookie) string {
		rw := serveAs(t, env.h, c, http.MethodGet, "/api/my/actions", "")
		var page struct {
			Actions []myActionRow `json:"actions"`
		}
		if err := json.Unmarshal(rw.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode %s: %v", rw.Body.String(), err)
		}
		var out []string
		for _, a := range page.Actions {
			out = append(out, a.ID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(env.alice); got != "a-host,a-notes-45,a-notes-12" {
		t.Errorf("alice sees %q", got)
	}
	if got := ids(env.bob); got != "b-notes-45" {
		t.Errorf("bob sees %q", got)
	}
	if got := ids(env.root); !strings.Contains(got, "b-notes-45") || !strings.Contains(got, "a-notes-45") {
		t.Errorf("root sees %q", got)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodGet, "/api/actions/"+env.bobNotes, ""); rw.Code != http.StatusNotFound {
		t.Errorf("alice GET bob's action = %d, want 404", rw.Code)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodGet, "/api/actions/"+env.aliceNotes, ""); rw.Code != http.StatusOK {
		t.Errorf("alice GET her action = %d, want 200", rw.Code)
	}
}

func TestMemberRulePreviewCreateAndManage(t *testing.T) {
	env := newRulesTestEnv(t, true)
	req := `{"action_id":"` + env.aliceNotes + `","verdict":"deny","scope":"pattern"}`

	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/preview", req)
	var preview struct {
		Rule          ScopedRule `json:"rule"`
		File          string     `json:"file"`
		RecentMatches int        `json:"recent_matches"`
		RecentSampled int        `json:"recent_sampled"`
		WritesEnabled bool       `json:"writes_enabled"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &preview); err != nil {
		t.Fatalf("preview: %d %s", rw.Code, rw.Body.String())
	}
	if preview.File != "50-user-alice.hcl" || !preview.WritesEnabled {
		t.Fatalf("preview file/writes = %q/%v", preview.File, preview.WritesEnabled)
	}
	// Both of alice's notes match the pattern; bob's never counts.
	if preview.RecentMatches != 2 || preview.RecentSampled != 2 {
		t.Fatalf("preview matched %d of %d, want 2 of 2", preview.RecentMatches, preview.RecentSampled)
	}

	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/preview",
		`{"action_id":"`+env.bobNotes+`","verdict":"deny"}`); rw.Code != http.StatusNotFound {
		t.Errorf("alice preview on bob's action = %d, want 404", rw.Code)
	}

	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", req); rw.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rw.Code, rw.Body.String())
	}
	ruleName := preview.Rule.RuleName
	ep := env.w.g.Policy().Endpoints["gitlab"]
	if got := matchedRule(ep, httpReq("POST", "/api/v4/projects/5/issues/6/notes", "team-a", nil)); got != ruleName {
		t.Fatalf("team-a request matched %q after create, want %q", got, ruleName)
	}
	if got := matchedRule(ep, httpReq("POST", "/api/v4/projects/5/issues/6/notes", "team-b", nil)); got != "" {
		t.Fatalf("team-b request matched %q", got)
	}

	rw = serveAs(t, env.h, env.alice, http.MethodGet, "/api/my/rules", "")
	var mine struct {
		File  string   `json:"file"`
		Rules []myRule `json:"rules"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &mine); err != nil || len(mine.Rules) != 1 || mine.Rules[0].Name != ruleName {
		t.Fatalf("my rules = %s", rw.Body.String())
	}
	if mine.Rules[0].Profile != "team-a" || mine.Rules[0].Priority != memberRulePriority {
		t.Fatalf("my rule = %+v", mine.Rules[0])
	}

	// bob cannot touch alice's rule.
	if rw := serveAs(t, env.h, env.bob, http.MethodPost, "/api/my/rules/delete", `{"name":"`+ruleName+`"}`); rw.Code != http.StatusNotFound {
		t.Errorf("bob delete of alice's rule = %d, want 404", rw.Code)
	}

	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/update", `{"name":"`+ruleName+`","disabled":true}`); rw.Code != http.StatusOK {
		t.Fatalf("disable = %d %s", rw.Code, rw.Body.String())
	}
	ep = env.w.g.Policy().Endpoints["gitlab"]
	if got := matchedRule(ep, httpReq("POST", "/api/v4/projects/5/issues/6/notes", "team-a", nil)); got != "" {
		t.Fatalf("disabled rule still matched (%q)", got)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/delete", `{"name":"`+ruleName+`"}`); rw.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, "50-user-alice.hcl"); strings.Contains(got, ruleName) {
		t.Fatalf("rule still in the file after delete:\n%s", got)
	}

	records, _ := listDashboardAudit(env.w.g.db, 0, 0)
	var audited []string
	for _, rec := range records {
		if rec.Username == "alice" && rec.Target == ruleName {
			audited = append(audited, rec.Path)
		}
	}
	if len(audited) != 3 {
		t.Errorf("alice's rule changes audited as %v, want create, update and delete", audited)
	}
	for _, rec := range records {
		if rec.Path == "/api/rules/preview" {
			t.Errorf("read-only preview audited: %+v", rec)
		}
	}
}

func TestMemberRuleOnUnknownHostClaimsOnlyTheirProfile(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceHost+`","verdict":"allow"}`); rw.Code != http.StatusBadRequest {
		t.Fatalf("allow on a passthrough host = %d, want 400", rw.Code)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceHost+`","verdict":"approve"}`); rw.Code != http.StatusOK {
		t.Fatalf("approve on a passthrough host = %d %s", rw.Code, rw.Body.String())
	}
	profiles := readCfgFile(t, env.w, "20-profiles.hcl")
	teamA := profiles[:strings.Index(profiles, `profile "team-b"`)]
	teamB := profiles[strings.Index(profiles, `profile "team-b"`):]
	if !strings.Contains(teamA, "passthrough.alice-") {
		t.Errorf("team-a did not get the generated credential:\n%s", profiles)
	}
	if strings.Contains(teamB, "passthrough.") {
		t.Errorf("team-b got the generated credential:\n%s", profiles)
	}
	policy := env.w.g.Policy()
	ep := runtime.HostEndpoint(policy, "team-a", "example.org")
	if ep == nil {
		t.Fatal("example.org has no endpoint for team-a")
	}
	if len(ep.Rules) != 1 {
		t.Fatalf("example.org endpoint rules = %+v", ep.Rules)
	}
	req := httpReq("GET", "/", "team-a", nil)
	req.Credential = ep.Rules[0].Credential
	r := runtime.MatchRequest(ep, req)
	if r == nil || len(r.Outcome.Approve) != 1 || r.Outcome.Approve[0].Name != "team-a-review" {
		t.Fatalf("team-a request to example.org matched %+v, want alice's approval rule", r)
	}
	if runtime.HostEndpoint(policy, "team-b", "example.org") != nil {
		t.Error("team-b got an endpoint for example.org")
	}
}

func TestAdminRuleGoesToTheDashboardFileUnpinned(t *testing.T) {
	env := newRulesTestEnv(t, true)
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.bobNotes+`","verdict":"allow","scope":"any_method"}`)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), dashboardConfigFile) {
		t.Fatalf("admin create = %d %s", rw.Code, rw.Body.String())
	}
	got := readCfgFile(t, env.w, dashboardConfigFile)
	if strings.Contains(got, "profile ") || !strings.Contains(got, "priority  = 100") {
		t.Fatalf("admin rule:\n%s", got)
	}
}

func TestMemberRulesRefusedWithoutWritesOrDirectory(t *testing.T) {
	env := newRulesTestEnv(t, false)
	req := `{"action_id":"` + env.aliceNotes + `","verdict":"deny"}`
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", req); rw.Code != http.StatusForbidden {
		t.Errorf("create with writes disabled = %d, want 403", rw.Code)
	}
	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/preview", req)
	if !strings.Contains(rw.Body.String(), `"writes_enabled":false`) {
		t.Errorf("preview with writes disabled: %s", rw.Body.String())
	}

	single := newUsersTestMux(t)
	v := viewer{username: "alice", profiles: map[string]bool{"team-a": true}}
	single.g.cfgPath = filepath.Join(t.TempDir(), "gateway.hcl")
	if _, _, err := single.rulesFile(v); err != errMemberRulesNeedDir {
		t.Errorf("member rules file on a single-file config: err = %v", err)
	}
}

func TestRuleCreateTwiceIsAConflict(t *testing.T) {
	env := newRulesTestEnv(t, true)
	req := `{"action_id":"` + env.aliceNotes + `","verdict":"deny"}`
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", req); rw.Code != http.StatusOK {
		t.Fatalf("first create = %d %s", rw.Code, rw.Body.String())
	}
	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", req)
	if rw.Code != http.StatusConflict || !strings.Contains(rw.Body.String(), "already exists") {
		t.Fatalf("second create = %d %s, want 409 already exists", rw.Code, rw.Body.String())
	}
}

func TestMemberLosesRuleEditsWithTheProfile(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"allow"}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/users/update", `{"username":"alice","profiles":[]}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	rw := serveAs(t, env.h, env.alice, http.MethodGet, "/api/my/rules", "")
	var mine struct {
		Rules []myRule `json:"rules"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &mine); err != nil || len(mine.Rules) != 1 || mine.Rules[0].Owned {
		t.Fatalf("my rules after losing the profile = %s", rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/update",
		`{"name":"`+mine.Rules[0].Name+`","disabled":true}`); rw.Code != http.StatusForbidden {
		t.Fatalf("edit after losing the profile = %d, want 403", rw.Code)
	}
}

func TestDeletedUsersRulesKeepApplyingWithoutAnOwner(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"deny","scope":"pattern"}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/users/delete", `{"username":"alice"}`); rw.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rw.Code, rw.Body.String())
	}
	if _, err := os.Stat(filepath.Join(env.w.g.cfgPath, "50-user-alice.hcl")); !os.IsNotExist(err) {
		t.Fatalf("alice's rules file still owned by the name (stat err %v)", err)
	}
	names, _ := filepath.Glob(filepath.Join(env.w.g.cfgPath, "50-former-user-alice-*.hcl"))
	if len(names) != 1 {
		t.Fatalf("archived files = %v", names)
	}
	// The watcher would reload; do it here to check the archived file
	// still loads and enforces.
	env.w.g.configMu.Lock()
	err := env.w.g.reloadConfigFromFileLocked(env.w.g.cfgPath)
	env.w.g.configMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ep := env.w.g.Policy().Endpoints["gitlab"]
	if r := matchedRule(ep, httpReq("POST", "/api/v4/projects/5/issues/6/notes", "team-a", nil)); !strings.HasPrefix(r, "alice-") {
		t.Fatalf("archived rule no longer applies (matched %q)", r)
	}

	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/users/create",
		`{"username":"alice","password":"`+usersTestMemberPassword+`"}`); rw.Code != http.StatusCreated {
		t.Fatalf("re-create alice = %d %s", rw.Code, rw.Body.String())
	}
	newAlice := sessionCookieFor(t, env.w, "alice")
	rw := serveAs(t, env.h, newAlice, http.MethodGet, "/api/my/rules", "")
	if !strings.Contains(rw.Body.String(), `"rules":[]`) {
		t.Fatalf("new alice inherited rules: %s", rw.Body.String())
	}

	// A leftover file under a username blocks creating that user.
	if err := os.WriteFile(filepath.Join(env.w.g.cfgPath, "50-user-carol.hcl"), []byte("\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/users/create",
		`{"username":"carol","password":"`+usersTestMemberPassword+`"}`); rw.Code != http.StatusConflict {
		t.Fatalf("create over a leftover rules file = %d, want 409", rw.Code)
	}
}

func TestRuleSummariesRespectTheProfilePin(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"deny"}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	for _, s := range env.w.collectRuleSummaries("") {
		if strings.HasPrefix(s.Name, "alice-") && s.Profile != "team-a" {
			t.Errorf("alice's team-a rule listed under profile %q", s.Profile)
		}
	}
}
