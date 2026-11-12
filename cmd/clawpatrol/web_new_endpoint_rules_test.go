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

// setNewEndpointRules writes a defaults block to the config directory
// and reloads, returning the reload's error.
func setNewEndpointRules(t *testing.T, w *webMux, src string) error {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.g.cfgPath, newEndpointRulesFile), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	return w.g.reloadConfigFromFileLocked(w.g.cfgPath)
}

func TestCredentialDeclareNewHostGetsDefaultRules(t *testing.T) {
	w := configDirTestMux(t)
	if err := setNewEndpointRules(t, w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "forge-tok",
		"new_endpoint": map[string]string{"name": "forge", "host": "git.example.org"},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if raw := readCfgFile(t, w, dashboardConfigFile); !regexp.MustCompile(`endpoint +=  *https\.forge\n  condition`).MatchString(raw) {
		t.Errorf("the copied rule body does not follow the endpoint line:\n%s", raw)
	}
	dash := strings.Join(strings.Fields(readCfgFile(t, w, dashboardConfigFile)), " ")
	for _, want := range []string{
		`rule "forge-no-delete" { endpoint = https.forge condition = "http.method == 'DELETE'" verdict = "deny"`,
		`rule "forge-writes" { endpoint = https.forge # reads stay unmatched, so they are allowed`,
		"approve = [human_approver.ops]",
	} {
		if !strings.Contains(dash, want) {
			t.Errorf("%s = %q, want %q", dashboardConfigFile, dash, want)
		}
	}
	rules := w.g.cfg.Load().Policy.Rules
	for _, name := range []string{"forge-no-delete", "forge-writes"} {
		if rules[name] == nil {
			t.Errorf("the gateway did not reload with rule %s", name)
		}
	}
}

func TestCredentialEditNewHostGetsDefaultRules(t *testing.T) {
	w := configDirTestMux(t)
	if err := setNewEndpointRules(t, w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	rw := credentialConfigCall(t, w.apiCredentialEdit, map[string]any{
		"name": "tok", "new_endpoint": map[string]string{"name": "forge", "host": "git.example.org"},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if w.g.cfg.Load().Policy.Rules["forge-no-delete"] == nil {
		t.Error("an endpoint added by an edit has no default rules")
	}
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

func TestCredentialDeclareRefusesTakenDefaultRuleName(t *testing.T) {
	w := configDirTestMux(t)
	taken := testNewEndpointRules + `
rule "forge-no-delete" {
  endpoint  = https.github
  condition = "http.method == 'DELETE'"
  verdict   = "deny"
}
`
	if err := setNewEndpointRules(t, w, taken); err != nil {
		t.Fatal(err)
	}
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "forge-tok",
		"new_endpoint": map[string]string{"name": "forge", "host": "git.example.org"},
	})
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), `"forge-no-delete"`) {
		t.Fatalf("status=%d body=%s, want 400 naming the rule", rw.Code, rw.Body.String())
	}
	if _, err := os.Stat(filepath.Join(w.g.cfgPath, dashboardConfigFile)); !os.IsNotExist(err) {
		t.Errorf("%s written for a refused request", dashboardConfigFile)
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

func TestCredentialOptionsListsNewEndpointRules(t *testing.T) {
	w := configDirTestMux(t)
	if err := setNewEndpointRules(t, w, testNewEndpointRules); err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	w.apiCredentialOptions(rw, httptest.NewRequest(http.MethodGet, "/api/credentials/options", nil))
	var got struct {
		NewEndpointRules []string `json:"new_endpoint_rules"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.NewEndpointRules, []string{"-no-delete", "-writes"}) {
		t.Errorf("new_endpoint_rules = %q", got.NewEndpointRules)
	}
}

func TestOneLineNewEndpointRule(t *testing.T) {
	w := configDirTestMux(t)
	if err := setNewEndpointRules(t, w, "defaults {\n  new_endpoint_rule \"deny\" { verdict = \"deny\" }\n}\n"); err != nil {
		t.Fatal(err)
	}
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "forge-tok",
		"new_endpoint": map[string]string{"name": "forge", "host": "git.example.org"},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if w.g.cfg.Load().Policy.Rules["forge-deny"] == nil {
		t.Error("the rule from a one-line block did not load")
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
	if err := setNewEndpointRules(t, w, src); err == nil || !strings.Contains(err.Error(), `new_endpoint_rule "deny" more than once`) {
		t.Fatalf("reload error = %v, want one naming the duplicated label", err)
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
