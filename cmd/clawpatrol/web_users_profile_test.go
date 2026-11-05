package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

const teamProfilesHCL = `endpoint "https" "gitlab" {
  hosts = ["gitlab.com"]
}
endpoint "https" "sentry" {
  hosts = ["sentry.io"]
}
credential "header_token" "gitlab-pat" {
  header   = "PRIVATE-TOKEN"
  endpoint = https.gitlab
}
credential "header_token" "gitlab-pat-sean" {
  header   = "PRIVATE-TOKEN"
  endpoint = https.gitlab
}
credential "header_token" "gitlab-pat-gemma" {
  header   = "PRIVATE-TOKEN"
  endpoint = https.gitlab
}
credential "bearer_token" "sentry-token" { endpoint = https.sentry }
profile "vincenth" {
  credentials = [header_token.gitlab-pat, bearer_token.sentry-token]
}
profile "sean" {
  credentials = [header_token.gitlab-pat-sean, bearer_token.sentry-token]
}
profile "gemma" {
  credentials = [header_token.gitlab-pat-gemma, bearer_token.sentry-token]
}
`

func teamProfilesMux(t *testing.T, writes bool) *webMux {
	t.Helper()
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "gateway.d")
	if err := os.Mkdir(cfgDir, 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"00-gateway.hcl": `gateway {
  state_dir = "` + filepath.ToSlash(dir) + `"
  dashboard_config_writes = ` + map[bool]string{true: "true", false: "false"}[writes] + `
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}
`,
		"10-team.hcl": teamProfilesHCL,
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

func postUsersCreate(w *webMux, body string) *httptest.ResponseRecorder {
	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users/create", strings.NewReader(body))
	w.apiUsersCreate(rw, r)
	return rw
}

func profileCredentialNames(t *testing.T, w *webMux, profile string) []string {
	t.Helper()
	p := w.g.Policy().Profiles[profile]
	if p == nil {
		t.Fatalf("profile %q is not declared", profile)
	}
	var names []string
	for _, ent := range p.Credentials {
		names = append(names, ent.Symbol.Type+"."+ent.Symbol.Name)
	}
	return names
}

func TestCreateUserWithProfileClonesPrivateAndSharesShared(t *testing.T) {
	w := teamProfilesMux(t, true)
	rw := postUsersCreate(w, `{"username":"frank","password":"frank-passphrase-1234","new_profile":{"name":"frank","template":"sean"}}`)
	if rw.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", rw.Code, rw.Body.String())
	}
	if got := strings.Join(profileCredentialNames(t, w, "frank"), ","); got != "header_token.gitlab-pat-frank,bearer_token.sentry-token" {
		t.Fatalf("frank credentials = %s", got)
	}
	written := readCfgFile(t, w, dashboardConfigFile)
	if !strings.Contains(written, `credential "header_token" "gitlab-pat-frank"`) || !strings.Contains(written, `"PRIVATE-TOKEN"`) {
		t.Fatalf("cloned credential missing:\n%s", written)
	}
	if readCfgFile(t, w, "10-team.hcl") != teamProfilesHCL {
		t.Fatal("the template's file changed")
	}
	profiles, err := listDashboardUserProfiles(w.g.db, "frank")
	if err != nil || strings.Join(profiles, ",") != "frank" {
		t.Fatalf("frank's profiles = %v, %v", profiles, err)
	}
}

func TestCreateUserProfileFromUnsuffixedCredential(t *testing.T) {
	w := teamProfilesMux(t, true)
	rw := postUsersCreate(w, `{"username":"ana","password":"ana-passphrase-12345","new_profile":{"name":"ana","template":"vincenth"}}`)
	if rw.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", rw.Code, rw.Body.String())
	}
	if got := strings.Join(profileCredentialNames(t, w, "ana"), ","); got != "header_token.gitlab-pat-ana,bearer_token.sentry-token" {
		t.Fatalf("ana credentials = %s", got)
	}
}

func TestCreateUserProfileRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		writes     bool
		want       int
	}{
		{"profile exists", `{"username":"newbie","password":"newbie-passphrase-1","new_profile":{"name":"sean","template":"gemma"}}`, true, http.StatusConflict},
		{"unknown template", `{"username":"newbie","password":"newbie-passphrase-1","new_profile":{"name":"newbie","template":"nobody"}}`, true, http.StatusBadRequest},
		{"bad name", `{"username":"newbie","password":"newbie-passphrase-1","new_profile":{"name":"New Bie","template":"sean"}}`, true, http.StatusBadRequest},
		{"writes disabled", `{"username":"newbie","password":"newbie-passphrase-1","new_profile":{"name":"newbie","template":"sean"}}`, false, http.StatusBadRequest},
		{"user exists", `{"username":"root","password":"newbie-passphrase-1","new_profile":{"name":"newbie","template":"sean"}}`, true, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := teamProfilesMux(t, tc.writes)
			if err := createDashboardUser(w.g.db, "root", usersTestRootPassword, dashboardRoleAdmin); err != nil && !strings.Contains(err.Error(), "exists") {
				t.Fatal(err)
			}
			if rw := postUsersCreate(w, tc.body); rw.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rw.Code, tc.want, rw.Body.String())
			}
			if _, err := os.Stat(filepath.Join(w.g.cfgPath, dashboardConfigFile)); err == nil {
				t.Fatal("a refused request wrote the config")
			}
			if _, exists, _ := lookupDashboardUserRole(w.g.db, "newbie"); exists {
				t.Fatal("a refused request created the user")
			}
		})
	}
}

func TestProfileWithInlineCredentialsIsNotCopied(t *testing.T) {
	src := `profile "p" {
  credentials = [{ credential = header_token.a, placeholder = "x" }]
}
profile "q" {
  credentials = [header_token.a]
}
`
	f, diags := hclwrite.ParseConfig([]byte(src), "p.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	blocks := configBlocks(f.Body().Blocks())
	if !profileHasInlineCredentials(blocks.find("profile", "p")) {
		t.Fatal("inline entry not detected")
	}
	if profileHasInlineCredentials(blocks.find("profile", "q")) {
		t.Fatal("bare references reported as inline")
	}
}

func TestCloneCredentialName(t *testing.T) {
	for _, tc := range [][4]string{
		{"gitlab-pat-sean", "sean", "frank", "gitlab-pat-frank"},
		{"gitlab-pat", "vincenth", "frank", "gitlab-pat-frank"},
		{"sean-token", "sean", "frank", "sean-token-frank"},
	} {
		if got := cloneCredentialName(tc[0], tc[1], tc[2]); got != tc[3] {
			t.Errorf("cloneCredentialName(%q, %q, %q) = %q, want %q", tc[0], tc[1], tc[2], got, tc[3])
		}
	}
}

func TestCreateUserProfileFromOneLineCredential(t *testing.T) {
	w := teamProfilesMux(t, true)
	extra := `credential "bearer_token" "sentry-gemma" { endpoint = https.sentry }
profile "oneline" {
  credentials = [bearer_token.sentry-gemma]
}
`
	writeTeamFile(t, w, "20-oneline.hcl", extra)
	rw := postUsersCreate(w, `{"username":"ana","password":"ana-passphrase-12345","new_profile":{"name":"ana","template":"oneline"}}`)
	if rw.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", rw.Code, rw.Body.String())
	}
	if got := strings.Join(profileCredentialNames(t, w, "ana"), ","); got != "bearer_token.sentry-gemma-ana" {
		t.Fatalf("ana credentials = %s", got)
	}
}

func TestCreateUserProfileCloneNamesCollide(t *testing.T) {
	w := teamProfilesMux(t, true)
	writeTeamFile(t, w, "20-twins.hcl", `credential "bearer_token" "token" { endpoint = https.sentry }
credential "bearer_token" "token-twin" { endpoint = https.gitlab }
profile "twin" {
  credentials = [bearer_token.token, bearer_token.token-twin]
}
`)
	rw := postUsersCreate(w, `{"username":"ana","password":"ana-passphrase-12345","new_profile":{"name":"ana","template":"twin"}}`)
	if rw.Code != http.StatusConflict || !strings.Contains(rw.Body.String(), "token-ana") {
		t.Fatalf("status = %d (%s)", rw.Code, rw.Body.String())
	}
	if _, exists, _ := lookupDashboardUserRole(w.g.db, "ana"); exists {
		t.Fatal("a refused request created the user")
	}
}

func TestCreateUserProfileDropsLeftoversUnderTheName(t *testing.T) {
	w := teamProfilesMux(t, true)
	if err := setCredentialSlot(w.g.db, "gitlab-pat-frank", "", "old-frank-token"); err != nil {
		t.Fatal(err)
	}
	if err := createDashboardUser(w.g.db, "olduser", "olduser-passphrase-1", dashboardRoleMember); err != nil {
		t.Fatal(err)
	}
	if err := setDashboardUserProfiles(w.g.db, "olduser", []string{"frank", "gemma"}); err != nil {
		t.Fatal(err)
	}
	rw := postUsersCreate(w, `{"username":"frank","password":"frank-passphrase-1234","new_profile":{"name":"frank","template":"sean"}}`)
	if rw.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", rw.Code, rw.Body.String())
	}
	if _, found, err := readCredentialSecrets(w.g.db, "gitlab-pat-frank"); err != nil || found {
		t.Fatalf("old secret still stored: found=%v err=%v", found, err)
	}
	if got, _ := listDashboardUserProfiles(w.g.db, "olduser"); strings.Join(got, ",") != "gemma" {
		t.Fatalf("olduser's profiles = %v, want only gemma", got)
	}
}

func TestCreateUserProfileWriteFailureRemovesUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only directory")
	}
	w := teamProfilesMux(t, true)
	if err := os.Chmod(w.g.cfgPath, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(w.g.cfgPath, 0o750) })
	rw := postUsersCreate(w, `{"username":"frank","password":"frank-passphrase-1234","new_profile":{"name":"frank","template":"sean"}}`)
	if rw.Code == http.StatusCreated {
		t.Fatal("the write into a read-only directory succeeded")
	}
	if _, exists, _ := lookupDashboardUserRole(w.g.db, "frank"); exists {
		t.Fatal("the user stayed although the profile was not declared")
	}
}

// writeTeamFile adds a config file and reloads, as an operator edit
// picked up by the file watcher would.
func writeTeamFile(t *testing.T, w *webMux, name, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.g.cfgPath, name), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, policy, err := loadConfig(w.g.cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	w.g.cfg.Store(cfg)
	w.g.policy.Store(policy)
}
