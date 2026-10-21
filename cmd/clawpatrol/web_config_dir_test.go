package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

const configDirProfilesFile = "20-profiles.hcl"

func configDirTestMux(t *testing.T) *webMux {
	t.Helper()
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "gateway.d")
	if err := os.Mkdir(cfgDir, 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"00-gateway.hcl": `gateway {
  state_dir = "` + filepath.ToSlash(dir) + `"
  dashboard_config_writes = true
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}
`,
		"10-github.hcl": `endpoint "https" "github" {
  hosts = ["api.github.com"]
}
credential "bearer_token" "tok" { endpoint = https.github }
`,
		configDirProfilesFile: `profile "default" { credentials = [bearer_token.tok] }
`,
	}
	for name, src := range files {
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
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{cfgPath: cfgDir, stateDir: dir, db: db}
	g.cfg.Store(cfg)
	g.policy.Store(policy)
	return &webMux{g: g}
}

func readCfgFile(t *testing.T, w *webMux, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.g.cfgPath, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestConfigFilesListsDirectoryInLoadOrder(t *testing.T) {
	w := configDirTestMux(t)
	rw := httptest.NewRecorder()
	w.apiConfigFiles(rw, httptest.NewRequest(http.MethodGet, "/api/config/files", nil))
	var got struct {
		Directory bool             `json:"directory"`
		Files     []configFileInfo `json:"files"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rw.Body.String())
	}
	if !got.Directory || len(got.Files) != 3 {
		t.Fatalf("files = %+v", got)
	}
	if got.Files[1].Name != "10-github.hcl" ||
		got.Files[1].Revision != revisionForBytes([]byte(readCfgFile(t, w, "10-github.hcl"))) {
		t.Fatalf("second file = %+v", got.Files[1])
	}
}

func TestConfigReadInDirectoryMode(t *testing.T) {
	w := configDirTestMux(t)
	cases := []struct {
		query string
		want  int
	}{
		{"", http.StatusBadRequest},
		{"?file=10-github.hcl", http.StatusOK},
		{"?file=../gateway.hcl", http.StatusBadRequest},
		{"?file=.hidden.hcl", http.StatusBadRequest},
		{"?file=99-missing.hcl", http.StatusNotFound},
	}
	for _, tc := range cases {
		rw := httptest.NewRecorder()
		w.apiConfig(rw, httptest.NewRequest(http.MethodGet, "/api/config"+tc.query, nil))
		if rw.Code != tc.want {
			t.Errorf("GET /api/config%s = %d, want %d (%s)", tc.query, rw.Code, tc.want, rw.Body.String())
		}
	}
	rw := httptest.NewRecorder()
	w.apiConfig(rw, httptest.NewRequest(http.MethodGet, "/api/config?file=10-github.hcl", nil))
	if !strings.Contains(rw.Body.String(), `endpoint "https" "github"`) {
		t.Fatalf("body = %s", rw.Body.String())
	}
}

func TestConfigApplyDirectoryDefaultsToDashboardFile(t *testing.T) {
	w := configDirTestMux(t)
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"base_revision": revisionForBytes(nil),
		"append_hcl":    "rule \"deny-writes\" {\n  endpoint = https.github\n  verdict  = \"deny\"\n}",
	}))
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), `"file":"`+dashboardConfigFile+`"`) {
		t.Fatalf("response does not name the target file: %s", rw.Body.String())
	}
	if got := readCfgFile(t, w, dashboardConfigFile); !strings.Contains(got, `rule "deny-writes"`) {
		t.Fatalf("%s = %q", dashboardConfigFile, got)
	}
	st, err := os.Stat(filepath.Join(w.g.cfgPath, dashboardConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("new file mode = %v, want 0640 (directory mode without exec bits)", st.Mode().Perm())
	}
	reloaded := false
	for _, rule := range w.g.Policy().Endpoints["github"].Rules {
		reloaded = reloaded || rule.Name == "deny-writes"
	}
	if !reloaded {
		t.Fatal("policy did not reload the appended rule")
	}
}

func TestConfigApplyDirectoryMergesProfileInItsOwnFile(t *testing.T) {
	w := configDirTestMux(t)
	before, err := os.ReadFile(filepath.Join(w.g.cfgPath, "10-github.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"file":          "10-github.hcl",
		"base_revision": revisionForBytes(before),
		"append_hcl": `endpoint "https" "gitlab" { hosts = ["gitlab.com"] }
credential "bearer_token" "gl" { endpoint = https.gitlab }
profile "default" { credentials = [bearer_token.gl] }`,
	}))
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	target := readCfgFile(t, w, "10-github.hcl")
	if !strings.Contains(target, `endpoint "https" "gitlab"`) || strings.Contains(target, "profile") {
		t.Fatalf("10-github.hcl = %q, want the endpoint and no profile block", target)
	}
	profiles := readCfgFile(t, w, configDirProfilesFile)
	if !strings.Contains(profiles, "bearer_token.tok") || !strings.Contains(profiles, "bearer_token.gl") {
		t.Fatalf("%s = %q, want both credentials", configDirProfilesFile, profiles)
	}
	if _, err := os.Stat(filepath.Join(w.g.cfgPath, dashboardConfigFile)); !os.IsNotExist(err) {
		t.Errorf("%s created although the request named a file", dashboardConfigFile)
	}
}

func TestConfigApplyDirectoryInvalidLeavesFilesUntouched(t *testing.T) {
	w := configDirTestMux(t)
	before, err := configFingerprint(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"append_hcl": `rule "bad" {
  endpoint = https.missing
  verdict  = "deny"
}
profile "default" { credentials = [bearer_token.tok] }`,
	}))
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "missing") {
		t.Fatalf("status=%d body=%s, want the undeclared endpoint reported", rw.Code, rw.Body.String())
	}
	after, err := configFingerprint(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("config changed on a rejected apply:\nbefore %s\nafter  %s", before, after)
	}
	entries, err := os.ReadDir(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".clawpatrol-config-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestConfigApplyDirectoryRevisionIsPerFile(t *testing.T) {
	w := configDirTestMux(t)
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"file":          "10-github.hcl",
		"base_revision": revisionForBytes([]byte("stale")),
		"append_hcl":    "rule \"x\" {\n  endpoint = https.github\n  verdict  = \"deny\"\n}",
	}))
	if rw.Code != http.StatusConflict || !strings.Contains(rw.Body.String(), `"file":"10-github.hcl"`) {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}

	// Another file changing does not invalidate this file's revision.
	if err := os.WriteFile(filepath.Join(w.g.cfgPath, "30-other.hcl"), []byte("\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	rw = httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"file":          "10-github.hcl",
		"base_revision": revisionForBytes([]byte(readCfgFile(t, w, "10-github.hcl"))),
		"append_hcl":    "rule \"x\" {\n  endpoint = https.github\n  verdict  = \"deny\"\n}",
	}))
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
}

func TestConfigApplySingleFileRejectsOtherFileNames(t *testing.T) {
	w := configApplyTestMux(t, true)
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"file":       "other.hcl",
		"append_hcl": "rule \"x\" {\n  endpoint = https.github\n  verdict  = \"deny\"\n}",
	}))
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
}

func TestConfigFingerprintSeesInPlaceEditsInDirectory(t *testing.T) {
	w := configDirTestMux(t)
	path := filepath.Join(w.g.cfgPath, configDirProfilesFile)
	before, err := configFingerprint(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("# edited in place\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := configFingerprint(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("fingerprint unchanged after an in-place edit")
	}
}
