package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func credentialConfigCall(t *testing.T, handler http.HandlerFunc, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	handler(rw, httptest.NewRequest(http.MethodPost, "/api/credentials/x", strings.NewReader(string(b))))
	return rw
}

func markConfigFileReadOnly(t *testing.T, w *webMux, name string) {
	t.Helper()
	path := filepath.Join(w.g.cfgPath, name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("# "+readOnlyConfigMarker+"\n"), b...), 0o640); err != nil {
		t.Fatal(err)
	}
}

// addGitlabEndpoint declares a second endpoint, so a profile can take
// a new credential: a profile binds one fallback credential per
// endpoint, and "default" already binds tok to github.
func addGitlabEndpoint(t *testing.T, w *webMux) {
	t.Helper()
	src := `endpoint "https" "gitlab" { hosts = ["gitlab.com"] }` + "\n"
	if err := os.WriteFile(filepath.Join(w.g.cfgPath, "15-gitlab.hcl"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := w.g.reloadConfigFromFileLocked(w.g.cfgPath); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialDeclareWritesDashboardFileAndProfile(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "header_token", "name": "gh-pat", "header": "Authorization", "prefix": "token ",
		"endpoint": "gitlab", "profiles": []string{"default"},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	dash := strings.Join(strings.Fields(readCfgFile(t, w, dashboardConfigFile)), " ")
	for _, want := range []string{`credential "header_token" "gh-pat"`, `header = "Authorization"`, `prefix = "token "`, "endpoint = https.gitlab"} {
		if !strings.Contains(dash, want) {
			t.Errorf("%s = %q, want %q", dashboardConfigFile, dash, want)
		}
	}
	profiles := readCfgFile(t, w, configDirProfilesFile)
	if !strings.Contains(profiles, "[bearer_token.tok, header_token.gh-pat]") {
		t.Errorf("%s = %q, want gh-pat appended", configDirProfilesFile, profiles)
	}
	if w.g.cfg.Load().Policy.Credentials["gh-pat"] == nil {
		t.Error("the gateway did not reload with the new credential")
	}
}

func TestCredentialDeclareRejectsBadRequests(t *testing.T) {
	cases := map[string]map[string]any{
		"unknown type":     {"type": "aws", "name": "x", "endpoint": "github"},
		"taken name":       {"type": "bearer_token", "name": "tok", "endpoint": "github"},
		"bad name":         {"type": "bearer_token", "name": "1x", "endpoint": "github"},
		"missing header":   {"type": "header_token", "name": "x", "endpoint": "github"},
		"bad header":       {"type": "header_token", "name": "x", "header": "Bad Header", "endpoint": "github"},
		"no endpoint":      {"type": "bearer_token", "name": "x"},
		"new host":         {"type": "bearer_token", "name": "x", "new_endpoint": map[string]string{"name": "e", "host": "a.example"}},
		"unknown endpoint": {"type": "bearer_token", "name": "x", "endpoint": "nope"},
		"unknown profile":  {"type": "bearer_token", "name": "x", "endpoint": "github", "profiles": []string{"ghost"}},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := configDirTestMux(t)
			rw := credentialConfigCall(t, w.apiCredentialDeclare, body)
			if rw.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rw.Code, rw.Body.String())
			}
			if _, err := os.Stat(filepath.Join(w.g.cfgPath, dashboardConfigFile)); !os.IsNotExist(err) {
				t.Errorf("%s written for a refused request", dashboardConfigFile)
			}
		})
	}
}

func TestCredentialEditChangesSettingsAndProfiles(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	if rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "header_token", "name": "gh-pat", "header": "Authorization", "prefix": "token ",
		"endpoint": "gitlab", "profiles": []string{"default"},
	}); rw.Code != http.StatusOK {
		t.Fatalf("declare: status=%d body=%s", rw.Code, rw.Body.String())
	}
	rw := credentialConfigCall(t, w.apiCredentialEdit, map[string]any{
		"name": "gh-pat", "header": "PRIVATE-TOKEN", "prefix": "", "profiles": []string{},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	dash := strings.Join(strings.Fields(readCfgFile(t, w, dashboardConfigFile)), " ")
	if !strings.Contains(dash, `header = "PRIVATE-TOKEN"`) || strings.Contains(dash, "prefix") {
		t.Errorf("%s = %q, want the new header and no prefix", dashboardConfigFile, dash)
	}
	if got := readCfgFile(t, w, configDirProfilesFile); strings.Contains(got, "gh-pat") || !strings.Contains(got, "bearer_token.tok") {
		t.Errorf("%s = %q, want gh-pat dropped and tok kept", configDirProfilesFile, got)
	}
}

func TestCredentialEditProfilesOfReadOnlyCredential(t *testing.T) {
	w := configDirTestMux(t)
	markConfigFileReadOnly(t, w, "10-github.hcl")
	rw := credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "tok", "profiles": []string{}})
	if rw.Code != http.StatusOK {
		t.Fatalf("profiles only: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, w, configDirProfilesFile); strings.Contains(got, "bearer_token.tok") {
		t.Errorf("%s = %q, want tok dropped", configDirProfilesFile, got)
	}
	addGitlabEndpoint(t, w)
	rw = credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "tok", "endpoint": "gitlab", "profiles": []string{}})
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "read-only") {
		t.Fatalf("endpoint change: status=%d body=%s, want a read-only 400", rw.Code, rw.Body.String())
	}
	if _, err := os.Stat(filepath.Join(w.g.cfgPath, dashboardConfigFile)); !os.IsNotExist(err) {
		t.Errorf("%s written although the change was refused", dashboardConfigFile)
	}
}

// An unformatted file the change does not touch is not rewritten:
// hclwrite would realign it, and a read-only one would refuse.
func TestCredentialDeclareLeavesUnformattedFilesAlone(t *testing.T) {
	w := configDirTestMux(t)
	path := filepath.Join(w.g.cfgPath, "10-github.hcl")
	src := "# " + readOnlyConfigMarker + "\n" + `endpoint "https" "github" {
  hosts = ["api.github.com"]
}
credential "bearer_token" "tok" {
  endpoint   =   https.github
}
`
	if err := os.WriteFile(path, []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	addGitlabEndpoint(t, w)
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "forge-tok", "endpoint": "gitlab", "profiles": []string{"default"},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, w, "10-github.hcl"); got != src {
		t.Errorf("10-github.hcl rewritten: %q", got)
	}
}

func TestCredentialDeclareRefusesReadOnlyProfileFile(t *testing.T) {
	w := configDirTestMux(t)
	markConfigFileReadOnly(t, w, configDirProfilesFile)
	before := readCfgFile(t, w, configDirProfilesFile)
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "x", "endpoint": "github", "profiles": []string{"default"},
	})
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), configDirProfilesFile) ||
		!strings.Contains(rw.Body.String(), "add bearer_token.x to its credentials list in that file") {
		t.Fatalf("status=%d body=%s, want a 400 naming %s and the edit to make there", rw.Code, rw.Body.String(), configDirProfilesFile)
	}
	if got := readCfgFile(t, w, configDirProfilesFile); got != before {
		t.Errorf("%s changed: %q", configDirProfilesFile, got)
	}
	if _, err := os.Stat(filepath.Join(w.g.cfgPath, dashboardConfigFile)); !os.IsNotExist(err) {
		t.Errorf("%s written although the change was refused", dashboardConfigFile)
	}
}

func TestCredentialRemoveDropsBlockProfilesAndSecret(t *testing.T) {
	w := configDirTestMux(t)
	if err := setCredentialSlot(w.g.db, "tok", "", "s3cret"); err != nil {
		t.Fatal(err)
	}
	rw := credentialConfigCall(t, w.apiCredentialRemove, map[string]any{"name": "tok"})
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, w, "10-github.hcl"); strings.Contains(got, "credential") || !strings.Contains(got, `endpoint "https" "github"`) {
		t.Errorf("10-github.hcl = %q, want the endpoint without the credential", got)
	}
	if got := readCfgFile(t, w, configDirProfilesFile); !strings.Contains(got, "credentials = []") {
		t.Errorf("%s = %q, want an empty list", configDirProfilesFile, got)
	}
	if _, found, err := readCredentialSecrets(w.g.db, "tok"); err != nil || found {
		t.Errorf("secret still stored (found=%v err=%v)", found, err)
	}
	// A retry, as after a failed clear, clears what is left and succeeds.
	if err := setCredentialSlot(w.g.db, "tok", "", "left-over"); err != nil {
		t.Fatal(err)
	}
	if rw := credentialConfigCall(t, w.apiCredentialRemove, map[string]any{"name": "tok"}); rw.Code != http.StatusOK {
		t.Errorf("second remove: status=%d body=%s, want 200", rw.Code, rw.Body.String())
	}
	if _, found, err := readCredentialSecrets(w.g.db, "tok"); err != nil || found {
		t.Errorf("the retried remove left the secret (found=%v err=%v)", found, err)
	}
}

func TestCredentialConfigNeedsDashboardWrites(t *testing.T) {
	w := configDirTestMux(t)
	w.g.cfg.Load().Settings.DashboardConfigWrites = false
	rw := credentialConfigCall(t, w.apiCredentialRemove, map[string]any{"name": "tok"})
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", rw.Code, rw.Body.String())
	}
}

func TestCredentialOptionsReportsReadOnlyFiles(t *testing.T) {
	w := configDirTestMux(t)
	markConfigFileReadOnly(t, w, "10-github.hcl")
	rw := httptest.NewRecorder()
	w.apiCredentialOptions(rw, httptest.NewRequest(http.MethodGet, "/api/credentials/options", nil))
	var got struct {
		Writes      bool                             `json:"writes"`
		File        string                           `json:"file"`
		Endpoints   []credentialConfigEndpoint       `json:"endpoints"`
		Profiles    []credentialConfigProfile        `json:"profiles"`
		Credentials map[string]credentialConfigEntry `json:"credentials"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rw.Body.String())
	}
	if !got.Writes || got.File != dashboardConfigFile {
		t.Errorf("writes=%v file=%q", got.Writes, got.File)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].Family != "http" || !strings.Contains(got.Endpoints[0].Hosts, "api.github.com") {
		t.Errorf("endpoints = %+v", got.Endpoints)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].File != configDirProfilesFile || got.Profiles[0].ReadOnly ||
		len(got.Profiles[0].Credentials) != 1 || got.Profiles[0].Credentials[0] != "tok" {
		t.Errorf("profiles = %+v", got.Profiles)
	}
	tok := got.Credentials["tok"]
	if tok.File != "10-github.hcl" || !tok.ReadOnly || tok.Endpoint != "github" {
		t.Errorf("tok = %+v", tok)
	}
}

func TestConfigFileReadOnlyMarker(t *testing.T) {
	cases := map[string]bool{
		"# " + readOnlyConfigMarker + "\n":              true,
		"x = 1\n  #" + readOnlyConfigMarker + "  \n":    true,
		"// " + readOnlyConfigMarker:                    true,
		"/* " + readOnlyConfigMarker + " */\n":          true,
		"/*/\n":                                         false,
		"# see " + readOnlyConfigMarker + "\n":          false,
		`x = "` + readOnlyConfigMarker + `"` + "\n":     false,
		"# rendered by a script, never hand-edit it.\n": false,
	}
	for content, want := range cases {
		if got := configFileReadOnly([]byte(content)); got != want {
			t.Errorf("configFileReadOnly(%q) = %v, want %v", content, got, want)
		}
	}
}

// writeProfilesFile replaces the fixture's profiles file and reloads.
func writeProfilesFile(t *testing.T, w *webMux, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.g.cfgPath, configDirProfilesFile), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := w.g.reloadConfigFromFileLocked(w.g.cfgPath); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialProfilesKeepObjectEntriesCommentsAndLayout(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	writeProfilesFile(t, w, `profile "default" {
  credentials = [
    # the GitHub token
    { credential = bearer_token.tok },
  ]
}
profile "other" { credentials = [] }
`)
	rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "gl", "endpoint": "gitlab", "profiles": []string{"default", "other"},
	})
	if rw.Code != http.StatusOK {
		t.Fatalf("declare: status=%d body=%s", rw.Code, rw.Body.String())
	}
	got := readCfgFile(t, w, configDirProfilesFile)
	for _, want := range []string{"# the GitHub token", "{ credential = bearer_token.tok }", "    bearer_token.gl,\n  ]", `profile "other" { credentials = [bearer_token.gl] }`} {
		if !strings.Contains(got, want) {
			t.Errorf("after declare, %s = %q, want %q", configDirProfilesFile, got, want)
		}
	}

	opts := httptest.NewRecorder()
	w.apiCredentialOptions(opts, httptest.NewRequest(http.MethodGet, "/api/credentials/options", nil))
	if opts.Code != http.StatusOK || !strings.Contains(opts.Body.String(), `"credentials":["tok","gl"]`) {
		t.Errorf("options: status=%d body=%s, want default listing tok and gl", opts.Code, opts.Body.String())
	}

	// other then binds gl and tok (different endpoints), default only gl.
	rw = credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "tok", "profiles": []string{"other"}})
	if rw.Code != http.StatusOK {
		t.Fatalf("edit: status=%d body=%s", rw.Code, rw.Body.String())
	}
	got = readCfgFile(t, w, configDirProfilesFile)
	if strings.Contains(got, "{ credential = bearer_token.tok }") || !strings.Contains(got, "bearer_token.gl") {
		t.Errorf("after moving tok, %s = %q, want its object entry gone and gl kept", configDirProfilesFile, got)
	}
}

func TestProfileCredentialsEdits(t *testing.T) {
	cases := []struct{ src, add, remove, wantAdd, wantRemove string }{
		{"[]", "a.x", "x", "[a.x]", "[]"},
		{"[a.b, a.c]", "a.x", "b", "[a.b, a.c, a.x]", "[a.c]"},
		{"[a.b, a.c]", "a.x", "c", "[a.b, a.c, a.x]", "[a.b]"},
		{"[\n  a.b,\n  a.c,\n]", "a.x", "b", "[\n  a.b,\n  a.c,\n  a.x,\n]", "[\n  a.c,\n]"},
		{"[\n  a.b,\n  a.c\n]", "a.x", "c", "[\n  a.b,\n  a.c,\n  a.x\n]", "[\n  a.b,\n]"},
		{"[\n  a.b, # keep\n  a.c]", "a.x", "c", "[\n  a.b, # keep\n  a.c,\n  a.x]", "[\n  a.b, # keep\n  ]"},
		{"[\n  a.b, # one\n  a.c, # two\n]", "a.x", "b", "[\n  a.b, # one\n  a.c, # two\n  a.x,\n]", "[\n  a.c, # two\n]"},
		{"[\n  a.b,\n  a.c // two\n]", "a.x", "c", "[\n  a.b,\n  a.c, // two\n  a.x\n]", "[\n  a.b,\n]"},
	}
	for _, c := range cases {
		f, diags := hclwrite.ParseConfig([]byte("profile \"p\" {\n  credentials = "+c.src+"\n}\n"), "", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("%q: %s", c.src, diags.Error())
		}
		list, err := parseProfileCredentials(f.Body().Blocks()[0])
		if err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		if got := strings.TrimSpace(string(list.with(c.add))); got != c.wantAdd {
			t.Errorf("%q with %s = %q, want %q", c.src, c.add, got, c.wantAdd)
		}
		if got := strings.TrimSpace(string(list.without(c.remove))); got != c.wantRemove {
			t.Errorf("%q without %s = %q, want %q", c.src, c.remove, got, c.wantRemove)
		}
	}
}

func TestCredentialEditWithoutProfilesKeepsThem(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	if rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "header_token", "name": "gh-pat", "header": "Authorization", "endpoint": "gitlab", "profiles": []string{"default"},
	}); rw.Code != http.StatusOK {
		t.Fatalf("declare: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if rw := credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "gh-pat", "header": "PRIVATE-TOKEN"}); rw.Code != http.StatusOK {
		t.Fatalf("edit: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, w, configDirProfilesFile); !strings.Contains(got, "header_token.gh-pat") {
		t.Errorf("%s = %q, want gh-pat still listed", configDirProfilesFile, got)
	}
}

func TestCredentialDeclareClearsStaleSecret(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	if err := setCredentialSlot(w.g.db, "gl", "", "old-token"); err != nil {
		t.Fatal(err)
	}
	if rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "bearer_token", "name": "gl", "endpoint": "gitlab",
	}); rw.Code != http.StatusOK {
		t.Fatalf("declare: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if _, found, err := readCredentialSecrets(w.g.db, "gl"); err != nil || found {
		t.Errorf("a secret from before the declaration survived (found=%v err=%v)", found, err)
	}
}

func TestCredentialEditSettingsClearsVerification(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	if rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "header_token", "name": "gh-pat", "header": "Authorization", "endpoint": "gitlab",
	}); rw.Code != http.StatusOK {
		t.Fatalf("declare: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if err := setCredentialVerification(w.g.db, "gh-pat", "ok", ""); err != nil {
		t.Fatal(err)
	}
	if rw := credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "gh-pat", "profiles": []string{}}); rw.Code != http.StatusOK {
		t.Fatalf("profiles-only edit: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if _, found := getCredentialVerification(w.g.db, "gh-pat"); !found {
		t.Error("a profiles-only edit cleared the verification result")
	}
	if rw := credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "gh-pat", "header": "PRIVATE-TOKEN"}); rw.Code != http.StatusOK {
		t.Fatalf("header edit: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if _, found := getCredentialVerification(w.g.db, "gh-pat"); found {
		t.Error("the verification of the old header survived the edit")
	}
}

func TestCredentialProfilesSkipUnreadableList(t *testing.T) {
	dir := t.TempDir()
	src := `profile "odd" { credentials = some_list }
profile "ok" { credentials = [bearer_token.tok] }
`
	if err := os.WriteFile(filepath.Join(dir, "20-profiles.hcl"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	tree, err := loadConfigTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.setCredentialProfiles("bearer_token", "tok", nil, nil); err != nil {
		t.Fatalf("removing from every profile: %v", err)
	}
	if got := string(tree.changes("", "")[0].Content); !strings.Contains(got, "credentials = some_list") || strings.Contains(got, "bearer_token.tok") {
		t.Errorf("profiles = %q, want odd untouched and tok gone from ok", got)
	}
	if _, err := tree.setCredentialProfiles("bearer_token", "tok", []string{"odd"}, nil); err == nil || !strings.Contains(err.Error(), `profile "odd"`) {
		t.Errorf("adding to the unreadable list: err = %v, want it refused", err)
	}
}

func TestCredentialEditEndpointClearsSecretHeaderKeepsIt(t *testing.T) {
	w := configDirTestMux(t)
	addGitlabEndpoint(t, w)
	if rw := credentialConfigCall(t, w.apiCredentialDeclare, map[string]any{
		"type": "header_token", "name": "gh-pat", "header": "Authorization", "endpoint": "gitlab",
	}); rw.Code != http.StatusOK {
		t.Fatalf("declare: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if err := setCredentialSlot(w.g.db, "gh-pat", "", "gitlab-token"); err != nil {
		t.Fatal(err)
	}
	rw := credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "gh-pat", "header": "PRIVATE-TOKEN", "endpoint": "gitlab"})
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `"secret_cleared":false`) {
		t.Fatalf("header edit: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if _, found, _ := readCredentialSecrets(w.g.db, "gh-pat"); !found {
		t.Error("a header edit on the same endpoint dropped the secret")
	}
	forge := `endpoint "https" "forge" { hosts = ["forge.example"] }` + "\n"
	if err := os.WriteFile(filepath.Join(w.g.cfgPath, "16-forge.hcl"), []byte(forge), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := w.g.reloadConfigFromFileLocked(w.g.cfgPath); err != nil {
		t.Fatal(err)
	}
	rw = credentialConfigCall(t, w.apiCredentialEdit, map[string]any{"name": "gh-pat", "endpoint": "forge"})
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `"secret_cleared":true`) {
		t.Fatalf("endpoint edit: status=%d body=%s", rw.Code, rw.Body.String())
	}
	if _, found, _ := readCredentialSecrets(w.g.db, "gh-pat"); found {
		t.Error("the GitLab token survived the move to forge.example")
	}
}
