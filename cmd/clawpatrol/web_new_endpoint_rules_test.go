package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const newEndpointRulesFile = "05-defaults.hcl"

const testNewEndpointRules = `approver "human_approver" "ops" { channel = "#ops" }

defaults {
  new_endpoint_rule "no-delete" {
    condition = "http.method == 'DELETE'"
    verdict   = "deny"
    reason    = "deleting is never the agent's to perform"
  }
  new_endpoint_rule "writes" {
    # reads stay unmatched, so they are allowed
    condition = "!(http.method in ['GET', 'HEAD', 'OPTIONS'])"
    approve   = [human_approver.ops]
  }
}
`

func setNewEndpointRules(t *testing.T, w *webMux, src string) error {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.g.cfgPath, newEndpointRulesFile), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	return w.g.reloadConfigFromFileLocked(w.g.cfgPath)
}

func TestCredentialDeclareExistingEndpointAddsNoRules(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	if err := setNewEndpointRules(t, w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "gl", "endpoint": "gitlab",
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if dash := readCfgFile(t, w, dashboardConfigFile); strings.Contains(dash, "rule ") {
		t.Errorf("%s = %q, want no rule for an endpoint that already exists", dashboardConfigFile, dash)
	}
}

func TestBadNewEndpointRuleFailsTheLoad(t *testing.T) {
	cases := map[string]string{
		"unknown variable": `condition = "http.nope == 'x'"
    verdict   = "deny"`,
		"unknown approver": `condition = "http.method == 'POST'"
    approve   = [human_approver.ghost]`,
		"endpoint set": `endpoint  = https.github
    condition = "http.method == 'POST'"
    verdict   = "deny"`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := configDirTestMux(t)
			src := "defaults {\n  new_endpoint_rule \"bad\" {\n    " + body + "\n  }\n}\n"
			err := setNewEndpointRules(t, w, src)
			if err == nil || !strings.Contains(err.Error(), "defaults.new_endpoint_rule") {
				t.Fatalf("reload error = %v, want one naming defaults.new_endpoint_rule", err)
			}
			if w.g.cfg.Load().Defaults != nil {
				t.Error("the gateway swapped in the config with the bad rule")
			}
		})
	}
}

func TestNewEndpointRulesCheckedForSingleFileConfig(t *testing.T) {
	dir := t.TempDir()
	src := `gateway {
  state_dir = "` + filepath.ToSlash(dir) + `"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}
defaults {
  new_endpoint_rule "bad" {
    condition = "http.nope == 'x'"
    verdict   = "deny"
  }
}
profile "default" { credentials = [] }
`
	path := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(path, []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "defaults.new_endpoint_rule") {
		t.Fatalf("loadConfig error = %v, want one naming defaults.new_endpoint_rule", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(src, "http.nope", "http.method", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(path); err != nil {
		t.Fatalf("loadConfig with a good rule: %v", err)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), newEndpointRuleProbe) {
		t.Error("the check wrote its probe endpoint to the config")
	}
}

func TestNewEndpointRulesCheckedBeforeAWrite(t *testing.T) {
	w := configDirTestMux(t)
	bad := "defaults {\n  new_endpoint_rule \"bad\" {\n    condition = \"http.nope == 'x'\"\n    verdict = \"deny\"\n  }\n}\n"
	w.g.configMu.Lock()
	err := w.g.writeConfigFilesLocked([]configChange{{Name: newEndpointRulesFile, Content: []byte(bad)}})
	w.g.configMu.Unlock()
	var invalid *configInvalidError
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "defaults.new_endpoint_rule") {
		t.Fatalf("write error = %v, want a configInvalidError naming defaults.new_endpoint_rule", err)
	}
	if _, err := os.Stat(filepath.Join(w.g.cfgPath, newEndpointRulesFile)); !os.IsNotExist(err) {
		t.Error("a change whose defaults would not load was written")
	}
}

func TestNewEndpointRuleProbeAvoidsTakenRuleNames(t *testing.T) {
	w := configDirTestMux(t)
	src := testNewEndpointRules + `
rule "` + newEndpointRuleProbe + `-writes" {
  endpoint  = https.github
  condition = "http.method == 'DELETE'"
  verdict   = "deny"
}
`
	if err := setNewEndpointRules(t, w, src); err != nil {
		t.Fatalf("a rule named like the probe's made the config fail: %v", err)
	}
}

func TestDuplicateNewEndpointRuleLabelFailsTheLoad(t *testing.T) {
	w := configDirTestMux(t)
	src := `defaults {
  new_endpoint_rule "deny" { verdict = "deny" }
  new_endpoint_rule "deny" { verdict = "deny" }
}
`
	err := setNewEndpointRules(t, w, src)
	if err == nil || !strings.Contains(err.Error(), `new_endpoint_rule "deny" more than once`) {
		t.Fatalf("reload error = %v, want one naming the duplicated label", err)
	}
	if strings.Contains(err.Error(), "bad request") || !strings.Contains(err.Error(), newEndpointRulesFile+":3") {
		t.Errorf("reload error = %v, want the duplicate's position and no HTTP wording", err)
	}
}

func TestInvalidNewEndpointRuleLabelFailsTheLoad(t *testing.T) {
	w := configDirTestMux(t)
	for _, label := range []string{"no delete", "", "-x"} {
		src := "defaults {\n  new_endpoint_rule \"" + label + "\" { verdict = \"deny\" }\n}\n"
		if err := setNewEndpointRules(t, w, src); err == nil || !strings.Contains(err.Error(), "Invalid new_endpoint_rule name") {
			t.Errorf("label %q: reload error = %v", label, err)
		}
	}
}

func TestNewEndpointRulesCheckedOnceForASingleFileWrite(t *testing.T) {
	dir := t.TempDir()
	src := []byte("defaults {\n  new_endpoint_rule \"deny\" { verdict = \"deny\" }\n}\n")
	tmp := configSourcesSum(filepath.Join(dir, ".clawpatrol-config-1.hcl"), map[string][]byte{".clawpatrol-config-1.hcl": src}, false)
	real := configSourcesSum(filepath.Join(dir, "gateway.hcl"), map[string][]byte{"gateway.hcl": src}, false)
	if tmp != real {
		t.Error("a single file's temporary copy and the file itself have different sums")
	}
}

func TestNewEndpointRulesCheckedInReadOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	src := `gateway {
  state_dir = "` + filepath.ToSlash(t.TempDir()) + `"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}
defaults {
  new_endpoint_rule "deny" { verdict = "deny" }
}
profile "default" { credentials = [] }
`
	path := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(path, []byte(src), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skip("the directory stays writable for this user")
	}
	if _, _, err := loadConfig(path); err != nil {
		t.Fatalf("loadConfig in a read-only directory: %v", err)
	}
}

type addedHost struct {
	RuleName     string   `json:"rule_name"`
	EndpointName string   `json:"endpoint_name"`
	DefaultRules []string `json:"default_rules"`
}

// addHostAsAdmin creates a rule from env.aliceHost, a request to
// example.org that no endpoint claimed.
func addHostAsAdmin(t *testing.T, env *rulesTestEnv, fields string) (*httptest.ResponseRecorder, addedHost) {
	t.Helper()
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/create", `{"action_id":"`+env.aliceHost+`",`+fields+`}`)
	var out addedHost
	if rw.Code == http.StatusOK {
		if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return rw, out
}

func TestAdminAddsAHostWithTheDefaultRules(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if err := setNewEndpointRules(t, env.w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	rw, added := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	ep := added.EndpointName
	if added.RuleName != "" || !slices.Equal(added.DefaultRules, []string{ep + "-no-delete", ep + "-writes"}) {
		t.Fatalf("added = %+v", added)
	}
	raw := readCfgFile(t, env.w, dashboardConfigFile)
	if !regexp.MustCompile(`endpoint +=  *https\.` + ep + `\n  condition`).MatchString(raw) {
		t.Errorf("the copied rule body does not follow the endpoint line:\n%s", raw)
	}
	dash := strings.Join(strings.Fields(raw), " ")
	for _, want := range []string{
		`hosts = ["example.org"]`,
		`credential "passthrough" "` + ep + `_passthrough"`,
		`rule "` + ep + `-no-delete" { endpoint = https.` + ep + ` condition = "http.method == 'DELETE'" verdict = "deny"`,
		`rule "` + ep + `-writes" { endpoint = https.` + ep + ` # reads stay unmatched, so they are allowed`,
	} {
		if !strings.Contains(dash, want) {
			t.Errorf("%s = %q, want %q", dashboardConfigFile, dash, want)
		}
	}
	if profiles := readCfgFile(t, env.w, "20-profiles.hcl"); strings.Count(profiles, "passthrough."+ep+"_passthrough") != 2 {
		t.Errorf("both profiles should claim the endpoint:\n%s", profiles)
	}
	for _, name := range added.DefaultRules {
		if env.w.g.cfg.Load().Policy.Rules[name] == nil {
			t.Errorf("the gateway did not reload with rule %s", name)
		}
	}
}

func TestAdminHostRuleComesWithTheDefaultRules(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if err := setNewEndpointRules(t, env.w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	rw, added := addHostAsAdmin(t, env, `"verdict":"deny","scope":"exact"`)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	rules := env.w.g.cfg.Load().Policy.Rules
	for _, name := range append([]string{added.RuleName}, added.DefaultRules...) {
		if name == "" || rules[name] == nil {
			t.Errorf("rule %q did not load (added %+v)", name, added)
		}
	}
}

func TestMemberHostGetsNoDefaultRules(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if err := setNewEndpointRules(t, env.w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceHost+`","verdict":"none"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("a member adding a host without a rule = %d, want 400", rw.Code)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceHost+`","verdict":"deny"}`); rw.Code != http.StatusOK {
		t.Fatalf("member deny = %d %s", rw.Code, rw.Body.String())
	}
	for name := range env.w.g.cfg.Load().Policy.Rules {
		if strings.HasSuffix(name, "-no-delete") || strings.HasSuffix(name, "-writes") {
			t.Errorf("a member's host got the default rule %s", name)
		}
	}
}

func TestAddHostRefusesTakenDefaultRuleName(t *testing.T) {
	env := newRulesTestEnv(t, true)
	taken := testNewEndpointRules + `
rule "example_org-no-delete" {
  endpoint  = https.gitlab
  condition = "http.method == 'DELETE'"
  verdict   = "deny"
}
`
	if err := setNewEndpointRules(t, env.w, taken); err != nil {
		t.Fatal(err)
	}
	rw, _ := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`)
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), `"example_org-no-delete"`) {
		t.Fatalf("status=%d body=%s, want 400 naming the rule", rw.Code, rw.Body.String())
	}
	if _, err := os.Stat(filepath.Join(env.w.g.cfgPath, dashboardConfigFile)); !os.IsNotExist(err) {
		t.Errorf("%s written for a refused request", dashboardConfigFile)
	}
}

func TestOneLineNewEndpointRule(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if err := setNewEndpointRules(t, env.w, "defaults {\n  new_endpoint_rule \"deny\" { verdict = \"deny\" }\n}\n"); err != nil {
		t.Fatal(err)
	}
	rw, added := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if env.w.g.cfg.Load().Policy.Rules[added.EndpointName+"-deny"] == nil {
		t.Error("the rule from a one-line block did not load")
	}
}

func TestRuleCopiedFromABlockEndingInACommentHasNoBlankLine(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if err := setNewEndpointRules(t, env.w, "defaults {\n  new_endpoint_rule \"deny\" {\n    verdict = \"deny\" # why\n  }\n}\n"); err != nil {
		t.Fatal(err)
	}
	if rw, _ := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`); rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, dashboardConfigFile); strings.Contains(got, "# why\n\n") {
		t.Errorf("a blank line follows the copied comment:\n%s", got)
	}
}

func TestAddHostLeavesTheDefaultsBlockAsWritten(t *testing.T) {
	env := newRulesTestEnv(t, true)
	// In the file the host is added to, so formatting that file would
	// reach the defaults block.
	if err := os.WriteFile(filepath.Join(env.w.g.cfgPath, dashboardConfigFile), []byte(testNewEndpointRules), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := env.w.g.reloadConfigFromFileLocked(env.w.g.cfgPath); err != nil {
		t.Fatal(err)
	}
	if rw, _ := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`); rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, dashboardConfigFile); !strings.HasPrefix(got, testNewEndpointRules) {
		t.Errorf("the defaults block was rewritten:\n%s", got)
	}
}

func TestAddHostWithDuplicateLabelIsABadRequest(t *testing.T) {
	env := newRulesTestEnv(t, true)
	dup := "defaults {\n  new_endpoint_rule \"deny\" { verdict = \"deny\" }\n  new_endpoint_rule \"deny\" { verdict = \"deny\" }\n}\n"
	if err := setNewEndpointRules(t, env.w, dup); err == nil {
		t.Fatal("a duplicated label loaded")
	}
	rw, _ := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`)
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "more than once") {
		t.Fatalf("status=%d body=%s, want 400 naming the duplicated label", rw.Code, rw.Body.String())
	}
}

func TestAddHostSkipsReadOnlyProfiles(t *testing.T) {
	env := newRulesTestEnv(t, true)
	ops := "# " + readOnlyConfigMarker + "\nprofile \"ops\" { credentials = [bearer_token.gl] }\n"
	if err := os.WriteFile(filepath.Join(env.w.g.cfgPath, "25-ops.hcl"), []byte(ops), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := env.w.g.reloadConfigFromFileLocked(env.w.g.cfgPath); err != nil {
		t.Fatal(err)
	}
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/rules/preview", `{"action_id":"`+env.aliceHost+`","verdict":"none"}`)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "Profile ops is declared in 25-ops.hcl") {
		t.Fatalf("preview = %d %s, want a warning about profile ops", rw.Code, rw.Body.String())
	}
	if rw, _ := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`); rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, "25-ops.hcl"); got != ops {
		t.Errorf("25-ops.hcl changed:\n%s", got)
	}
	if !strings.Contains(readCfgFile(t, env.w, "20-profiles.hcl"), "passthrough.") {
		t.Error("the writable profiles did not get the endpoint")
	}
}

func TestMemberHostRefusedForAReadOnlyProfile(t *testing.T) {
	env := newRulesTestEnv(t, true)
	markConfigFileReadOnly(t, env.w, "20-profiles.hcl")
	if err := env.w.g.reloadConfigFromFileLocked(env.w.g.cfgPath); err != nil {
		t.Fatal(err)
	}
	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", `{"action_id":"`+env.aliceHost+`","verdict":"deny"}`)
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "declared in 20-profiles.hcl") {
		t.Fatalf("status=%d body=%s, want 400 naming the read-only file", rw.Code, rw.Body.String())
	}
}

func TestCredentialReplacesTheHostsPassthrough(t *testing.T) {
	env := newRulesTestEnv(t, true)
	_, added := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`)
	if added.EndpointName == "" {
		t.Fatal("the host was not added")
	}
	rw := credentialConfigCall(t, env.w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "ex-tok", "endpoint": added.EndpointName, "profiles": []string{"team-a"},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	profiles := readCfgFile(t, env.w, "20-profiles.hcl")
	teamA := profiles[:strings.Index(profiles, `profile "team-b"`)]
	teamB := profiles[strings.Index(profiles, `profile "team-b"`):]
	if !strings.Contains(teamA, "bearer_token.ex-tok") || strings.Contains(teamA, "passthrough.") {
		t.Errorf("team-a should list ex-tok in place of the passthrough:\n%s", profiles)
	}
	if !strings.Contains(teamB, "passthrough.") {
		t.Errorf("team-b lost the passthrough it still needs:\n%s", profiles)
	}
}

func TestCredentialSwapRefusedWhenARulePinsThePassthrough(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceHost+`","verdict":"deny"}`); rw.Code != http.StatusOK {
		t.Fatalf("member deny = %d %s", rw.Code, rw.Body.String())
	}
	var endpoint string
	for name := range env.w.g.cfg.Load().Policy.Endpoints {
		if strings.HasPrefix(name, "alice-") {
			endpoint = name
		}
	}
	before := readCfgFile(t, env.w, "20-profiles.hcl")
	rw := credentialConfigCall(t, env.w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "ex-tok", "endpoint": endpoint, "profiles": []string{"team-a"},
	})
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "would stop matching") {
		t.Fatalf("status=%d body=%s, want 400 naming the pinned rule", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, "20-profiles.hcl"); got != before {
		t.Errorf("20-profiles.hcl changed:\n%s", got)
	}
}

// hostWithCredential adds example.org from the log, then ex-tok for it
// in team-a, and returns the endpoint and its placeholder.
func hostWithCredential(t *testing.T, env *rulesTestEnv) (string, string) {
	t.Helper()
	_, added := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`)
	if added.EndpointName == "" {
		t.Fatal("the host was not added")
	}
	if rw := credentialConfigCall(t, env.w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "ex-tok", "endpoint": added.EndpointName, "profiles": []string{"team-a"},
	}); rw.Code != http.StatusOK {
		t.Fatalf("declare: status=%d body=%s", rw.Code, rw.Body.String())
	}
	return added.EndpointName, added.EndpointName + "_passthrough"
}

func teamProfiles(t *testing.T, env *rulesTestEnv) (string, string) {
	t.Helper()
	profiles := readCfgFile(t, env.w, "20-profiles.hcl")
	at := strings.Index(profiles, `profile "team-b"`)
	return profiles[:at], profiles[at:]
}

func TestRemovingTheCredentialRestoresThePlaceholder(t *testing.T) {
	env := newRulesTestEnv(t, true)
	_, placeholder := hostWithCredential(t, env)
	if rw := credentialConfigCall(t, env.w.apiCredentialRemove, map[string]any{"name": "ex-tok"}); rw.Code != http.StatusOK {
		t.Fatalf("remove: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if teamA, _ := teamProfiles(t, env); !strings.Contains(teamA, "passthrough."+placeholder) {
		t.Errorf("team-a lost the host's endpoint with its credential:\n%s", teamA)
	}
	if runtime.HostEndpoint(env.w.g.Policy(), "team-a", "example.org") == nil {
		t.Error("example.org has no endpoint for team-a any more")
	}
}

func TestMovingTheCredentialRestoresThePlaceholder(t *testing.T) {
	env := newRulesTestEnv(t, true)
	_, placeholder := hostWithCredential(t, env)
	if rw := credentialConfigCall(t, env.w.apiCredentialEdit, map[string]any{"name": "ex-tok", "endpoint": "sentry"}); rw.Code != http.StatusBadRequest {
		// team-a already binds sentry-a to sentry, so the move itself is refused.
		t.Fatalf("move onto a bound endpoint: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if rw := credentialConfigCall(t, env.w.apiCredentialEdit, map[string]any{
		"name": "ex-tok", "endpoint": "sentry", "profiles": []string{"team-b"},
	}); rw.Code != http.StatusOK {
		t.Fatalf("move: status=%d body=%s", rw.Code, rw.Body.String())
	}
	teamA, teamB := teamProfiles(t, env)
	if !strings.Contains(teamA, "passthrough."+placeholder) || strings.Contains(teamA, "ex-tok") {
		t.Errorf("team-a should be back on the placeholder:\n%s", teamA)
	}
	if !strings.Contains(teamB, "bearer_token.ex-tok") {
		t.Errorf("team-b should list ex-tok:\n%s", teamB)
	}
}

func TestEditingThePlaceholderKeepsItWhereItIs(t *testing.T) {
	env := newRulesTestEnv(t, true)
	_, added := addHostAsAdmin(t, env, `"verdict":"none","scope":"exact"`)
	placeholder := added.EndpointName + "_passthrough"
	if rw := credentialConfigCall(t, env.w.apiCredentialEdit, map[string]any{
		"name": placeholder, "profiles": []string{"team-a"},
	}); rw.Code != http.StatusOK {
		t.Fatalf("edit: status=%d body=%s", rw.Code, rw.Body.String())
	}
	teamA, teamB := teamProfiles(t, env)
	if !strings.Contains(teamA, "passthrough."+placeholder) || strings.Contains(teamB, "passthrough."+placeholder) {
		t.Errorf("want the placeholder in team-a only:\n%s%s", teamA, teamB)
	}
}

func TestHandWrittenPassthroughIsNotAPlaceholder(t *testing.T) {
	env := newRulesTestEnv(t, true)
	src := `endpoint "https" "forge" { hosts = ["forge.example"] }
credential "passthrough" "forge-open" { endpoint = https.forge }
`
	if err := os.WriteFile(filepath.Join(env.w.g.cfgPath, "15-forge.hcl"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := env.w.g.reloadConfigFromFileLocked(env.w.g.cfgPath); err != nil {
		t.Fatal(err)
	}
	if got := placeholders(env.w.g.cfg.Load(), "forge", ""); len(got) != 0 {
		t.Errorf("placeholders(forge) = %q, want none", got)
	}
}
