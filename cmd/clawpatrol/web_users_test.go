package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

const (
	usersTestRootPassword   = "root-passphrase-1234"
	usersTestMemberPassword = "member-passphrase-1234"
)

func newUsersTestMux(t *testing.T) *webMux {
	t.Helper()
	w := newDashboardTestMux(t, nil, usersTestRootPassword)
	if err := createDashboardUser(w.g.db, "alice", usersTestMemberPassword, dashboardRoleMember); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	return w
}

func sessionCookieFor(t *testing.T, w *webMux, username string) *http.Cookie {
	t.Helper()
	token, err := createDashboardSession(w.g.db, username, w.dashboardSessionTTL())
	if err != nil {
		t.Fatalf("createDashboardSession(%s): %v", username, err)
	}
	return &http.Cookie{Name: cpSessionCookieName, Value: token}
}

func serveAs(t *testing.T, h http.Handler, c *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	// Gated reads must name a Host the gateway answers for.
	r.Host = "localhost"
	if c != nil {
		r.AddCookie(c)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	return rw
}

func postLogin(t *testing.T, w *webMux, form string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/__login?next=/", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)
	return rw
}

func sessionUserFromResponse(t *testing.T, w *webMux, rw *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rw.Result().Cookies() {
		if c.Name == cpSessionCookieName && c.Value != "" {
			user, ok, err := lookupDashboardSession(w.g.db, c.Value)
			if err != nil || !ok {
				t.Fatalf("session for cookie: ok=%v err=%v", ok, err)
			}
			return user
		}
	}
	return ""
}

func TestDashboardRootIsAdminAndNewUsersAreMembers(t *testing.T) {
	w := newUsersTestMux(t)
	if role, _, _ := lookupDashboardUserRole(w.g.db, dashboardRootUsername); role != dashboardRoleAdmin {
		t.Fatalf("root role = %q, want admin", role)
	}
	if role, _, _ := lookupDashboardUserRole(w.g.db, "alice"); role != dashboardRoleMember {
		t.Fatalf("alice role = %q, want member", role)
	}
	// A password reset must not touch the role.
	if err := setDashboardUser(w.g.db, "alice", "another-passphrase-1234"); err != nil {
		t.Fatal(err)
	}
	if role, _, _ := lookupDashboardUserRole(w.g.db, "alice"); role != dashboardRoleMember {
		t.Fatalf("alice role after password reset = %q, want member", role)
	}
}

func TestDashboardLoginWithUsername(t *testing.T) {
	w := newUsersTestMux(t)

	rw := postLogin(t, w, "username=alice&password="+usersTestMemberPassword)
	if rw.Code != http.StatusFound {
		t.Fatalf("member login status = %d, want 302 (body: %s)", rw.Code, rw.Body.String())
	}
	if got := sessionUserFromResponse(t, w, rw); got != "alice" {
		t.Fatalf("session user = %q, want alice", got)
	}

	rw = postLogin(t, w, "password="+usersTestRootPassword)
	if got := sessionUserFromResponse(t, w, rw); got != dashboardRootUsername {
		t.Fatalf("password-only login session user = %q, want root", got)
	}
}

func TestDashboardLoginUnknownUserLooksLikeWrongPassword(t *testing.T) {
	w := newUsersTestMux(t)
	unknown := postLogin(t, w, "username=mallory&password="+usersTestMemberPassword)
	wrong := postLogin(t, w, "username=alice&password=not-alices-password")
	for name, rw := range map[string]*httptest.ResponseRecorder{"unknown user": unknown, "wrong password": wrong} {
		if rw.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", name, rw.Code)
		}
		if !strings.Contains(rw.Body.String(), "wrong username or password") {
			t.Fatalf("%s: body lacks the shared error message", name)
		}
		if got := sessionUserFromResponse(t, w, rw); got != "" {
			t.Fatalf("%s: a session was minted for %q", name, got)
		}
	}
}

func TestRoleGateDeniesMembersOperatorRoutes(t *testing.T) {
	w := newUsersTestMux(t)
	h := w.handler()
	member := sessionCookieFor(t, w, "alice")

	refusedByRoleGate := func(rw *httptest.ResponseRecorder) bool {
		return rw.Code == http.StatusForbidden && strings.Contains(rw.Body.String(), "requires the admin role")
	}
	for _, path := range []string{"/api/plugins", "/api/users", "/api/audit", "/api/config"} {
		if rw := serveAs(t, h, member, http.MethodGet, path, ""); !refusedByRoleGate(rw) {
			t.Errorf("member GET %s = %d %q, want the role gate's 403", path, rw.Code, rw.Body.String())
		}
	}
	// Actions are open to members, scoped by the handler: one outside
	// their profiles is a 404, never a 403 that would confirm it exists.
	if rw := serveAs(t, h, member, http.MethodGet, "/api/actions/123", ""); rw.Code != http.StatusNotFound {
		t.Errorf("member GET /api/actions/123 = %d, want 404", rw.Code)
	}
	if rw := serveAs(t, h, member, http.MethodPost, "/api/actions/rule-preview", `{"action_id":"123"}`); !refusedByRoleGate(rw) {
		t.Errorf("member POST /api/actions/rule-preview = %d, want the role gate's 403", rw.Code)
	}
	if rw := serveAs(t, h, member, http.MethodPost, "/api/plugins/approve", `{"name":"x"}`); !refusedByRoleGate(rw) {
		t.Errorf("member POST /api/plugins/approve = %d %q, want the role gate's 403", rw.Code, rw.Body.String())
	}

	rw := serveAs(t, h, member, http.MethodGet, "/api/me", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("member GET /api/me = %d, want 200", rw.Code)
	}
	var me map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me["username"] != "alice" || me["role"] != string(dashboardRoleMember) {
		t.Fatalf("/api/me = %v, want alice/member", me)
	}

	if rw := serveAs(t, h, member, http.MethodGet, "/", ""); rw.Code == http.StatusForbidden {
		t.Fatalf("member GET / = 403, want the dashboard shell to load")
	}
}

func TestRoleChangeAppliesToLiveSession(t *testing.T) {
	w := newUsersTestMux(t)
	h := w.handler()
	member := sessionCookieFor(t, w, "alice")
	if rw := serveAs(t, h, member, http.MethodGet, "/api/users", ""); rw.Code != http.StatusForbidden {
		t.Fatalf("before promotion: %d, want 403", rw.Code)
	}
	if err := setDashboardUserRole(w.g.db, "alice", dashboardRoleAdmin); err != nil {
		t.Fatal(err)
	}
	if rw := serveAs(t, h, member, http.MethodGet, "/api/users", ""); rw.Code != http.StatusOK {
		t.Fatalf("after promotion: %d, want 200", rw.Code)
	}
}

func TestDeletedUserSessionIsRejected(t *testing.T) {
	w := newUsersTestMux(t)
	h := w.handler()
	member := sessionCookieFor(t, w, "alice")
	root := sessionCookieFor(t, w, dashboardRootUsername)
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/delete", `{"username":"alice"}`); rw.Code != http.StatusOK {
		t.Fatalf("delete alice = %d (%s)", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, h, member, http.MethodGet, "/api/me", ""); rw.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user GET /api/me = %d, want 401", rw.Code)
	}
}

func TestUserAdminInvariants(t *testing.T) {
	w := newUsersTestMux(t)
	h := w.handler()
	root := sessionCookieFor(t, w, dashboardRootUsername)

	cases := []struct {
		name, path, body string
		want             int
	}{
		{"create member", "/api/users/create", `{"username":"bob","password":"bob-passphrase-1234"}`, http.StatusCreated},
		{"reset member password", "/api/users/update", `{"username":"bob","password":"bob-new-passphrase-1234"}`, http.StatusOK},
		{"reset root password", "/api/users/update", `{"username":"root","password":"taken-over-passphrase"}`, http.StatusForbidden},
		{"duplicate", "/api/users/create", `{"username":"alice","password":"alice-passphrase-1234"}`, http.StatusConflict},
		{"bad username", "/api/users/create", `{"username":"Bob Smith","password":"bob-passphrase-1234"}`, http.StatusBadRequest},
		{"bad role", "/api/users/create", `{"username":"carol","password":"carol-passphrase-1234","role":"owner"}`, http.StatusBadRequest},
		{"short password", "/api/users/create", `{"username":"carol","password":"short"}`, http.StatusBadRequest},
		{"demote root", "/api/users/update", `{"username":"root","role":"member"}`, http.StatusBadRequest},
		{"unknown user", "/api/users/update", `{"username":"nobody","role":"admin"}`, http.StatusNotFound},
		{"promote alice", "/api/users/update", `{"username":"alice","role":"admin"}`, http.StatusOK},
		{"reset admin password", "/api/users/update", `{"username":"alice","password":"taken-over-passphrase"}`, http.StatusForbidden},
		{"refused reset keeps role", "/api/users/update", `{"username":"alice","role":"member","password":"taken-over-passphrase"}`, http.StatusForbidden},
		{"delete root", "/api/users/delete", `{"username":"root"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		if rw := serveAs(t, h, root, http.MethodPost, tc.path, tc.body); rw.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, rw.Code, tc.want, rw.Body.String())
		}
	}

	if role, _, _ := lookupDashboardUserRole(w.g.db, "alice"); role != dashboardRoleAdmin {
		t.Errorf("alice role = %q after a refused demote+reset, want admin", role)
	}
	if ok, _, _ := checkDashboardPassword(w.g.db, dashboardRootUsername, usersTestRootPassword); !ok {
		t.Error("root password changed by another admin")
	}

	alice := sessionCookieFor(t, w, "alice")
	if rw := serveAs(t, h, alice, http.MethodPost, "/api/users/update", `{"username":"alice","role":"member"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("self demotion = %d, want 400", rw.Code)
	}
	if rw := serveAs(t, h, alice, http.MethodPost, "/api/users/delete", `{"username":"alice"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("self deletion = %d, want 400", rw.Code)
	}
}

func TestMePasswordRotatesSessions(t *testing.T) {
	w := newUsersTestMux(t)
	h := w.handler()
	member := sessionCookieFor(t, w, "alice")
	other := sessionCookieFor(t, w, "alice")

	if rw := serveAs(t, h, member, http.MethodPost, "/api/me/password",
		`{"current":"wrong-passphrase-0000","new":"brand-new-passphrase-1234"}`); rw.Code != http.StatusForbidden {
		t.Fatalf("wrong current password = %d, want 403", rw.Code)
	}
	rw := serveAs(t, h, member, http.MethodPost, "/api/me/password",
		`{"current":"`+usersTestMemberPassword+`","new":"brand-new-passphrase-1234"}`)
	if rw.Code != http.StatusOK {
		t.Fatalf("change password = %d (%s)", rw.Code, rw.Body.String())
	}
	if got := sessionUserFromResponse(t, w, rw); got != "alice" {
		t.Fatalf("re-minted session user = %q, want alice", got)
	}
	if rw := serveAs(t, h, other, http.MethodGet, "/api/me", ""); rw.Code != http.StatusUnauthorized {
		t.Fatalf("old session after rotation = %d, want 401", rw.Code)
	}
	if ok, _, _ := checkDashboardPassword(w.g.db, "alice", "brand-new-passphrase-1234"); !ok {
		t.Fatal("new password not stored")
	}
}

func TestAuditRecordsStateChangesAndLogins(t *testing.T) {
	w := newUsersTestMux(t)
	h := w.handler()
	root := sessionCookieFor(t, w, dashboardRootUsername)
	member := sessionCookieFor(t, w, "alice")

	serveAs(t, h, root, http.MethodGet, "/api/users", "")
	serveAs(t, h, root, http.MethodPost, "/api/users/create", `{"username":"bob","password":"bob-passphrase-1234"}`)
	serveAs(t, h, member, http.MethodPost, "/api/plugins/approve", `{"name":"x"}`)
	postLogin(t, w, "username=mallory&password=guess-guess-guess")

	records, err := listDashboardAudit(w.g.db, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		user, path, target string
		status             int
	}
	got := map[key]bool{}
	for _, rec := range records {
		if rec.Method == http.MethodGet {
			t.Errorf("GET recorded: %+v", rec)
		}
		got[key{rec.Username, rec.Path, rec.Target, rec.Status}] = true
	}
	for _, want := range []key{
		{dashboardRootUsername, "/api/users/create", "bob", http.StatusCreated},
		{"mallory", "/__login", "login", http.StatusUnauthorized},
	} {
		if !got[want] {
			t.Errorf("missing audit record %+v; have %+v", want, records)
		}
	}
	if !got[key{"alice", "/api/plugins/approve", auditTargetRoleRefused, http.StatusForbidden}] {
		t.Errorf("member request refused by the role gate was not audited; have %+v", records)
	}

	if rw := serveAs(t, h, member, http.MethodGet, "/api/audit", ""); rw.Code != http.StatusForbidden {
		t.Errorf("member GET /api/audit = %d, want 403", rw.Code)
	}
	rw := serveAs(t, h, root, http.MethodGet, "/api/audit?limit=1", "")
	var page struct {
		Records []dashboardAuditRecord `json:"records"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &page); err != nil || len(page.Records) != 1 {
		t.Fatalf("GET /api/audit?limit=1 = %d records (err %v)", len(page.Records), err)
	}
}

func TestUnknownStoredRoleIsTreatedAsMember(t *testing.T) {
	w := newUsersTestMux(t)
	if _, err := w.g.db.Exec(`UPDATE dashboard_users SET role = 'Admin' WHERE username = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if role, _, _ := lookupDashboardUserRole(w.g.db, "alice"); role != dashboardRoleMember {
		t.Fatalf("stored role 'Admin' read as %q, want member", role)
	}
	rw := serveAs(t, w.handler(), sessionCookieFor(t, w, "alice"), http.MethodGet, "/api/users", "")
	if rw.Code != http.StatusForbidden {
		t.Fatalf("GET /api/users with an unknown stored role = %d, want 403", rw.Code)
	}
}

func TestPrincipalRoleFailsClosed(t *testing.T) {
	cases := map[dashboardRole]dashboardRole{
		"":                  dashboardRoleAdmin,
		dashboardRoleAdmin:  dashboardRoleAdmin,
		dashboardRoleMember: dashboardRoleMember,
		"owner":             dashboardRoleMember,
	}
	for in, want := range cases {
		if got := principalRole(principal{Owner: "x", Role: in}); got != want {
			t.Errorf("principalRole(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMemberPasswordResetNeverRecreatesDeletedUser(t *testing.T) {
	w := newUsersTestMux(t)
	if err := deleteDashboardUser(w.g.db, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := setDashboardMemberPassword(w.g.db, "alice", "revived-passphrase-1234"); !errors.Is(err, errDashboardUserNotFound) {
		t.Fatalf("reset of a deleted user: err = %v, want errDashboardUserNotFound", err)
	}
	if _, exists, _ := lookupDashboardUserRole(w.g.db, "alice"); exists {
		t.Fatal("password reset re-created a deleted user")
	}
}

func TestSessionLookupCarriesRole(t *testing.T) {
	w := newUsersTestMux(t)
	c := sessionCookieFor(t, w, "alice")
	user, role, ok, err := lookupDashboardSessionUser(w.g.db, c.Value)
	if err != nil || !ok || user != "alice" || role != dashboardRoleMember {
		t.Fatalf("lookupDashboardSessionUser = %q %q %v %v", user, role, ok, err)
	}
	// A session whose user row is gone (deleted without revocation)
	// carries no role, and the gate treats it as no session.
	if _, err := w.g.db.Exec(`DELETE FROM dashboard_users WHERE username = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if _, role, ok, _ := lookupDashboardSessionUser(w.g.db, c.Value); !ok || role != "" {
		t.Fatalf("orphaned session: role = %q ok = %v, want empty role", role, ok)
	}
	if rw := serveAs(t, w.handler(), c, http.MethodGet, "/api/me", ""); rw.Code != http.StatusUnauthorized {
		t.Fatalf("orphaned session GET /api/me = %d, want 401", rw.Code)
	}
}

func TestPruneDashboardAudit(t *testing.T) {
	w := newUsersTestMux(t)
	now := time.Now()
	for _, age := range []time.Duration{48 * time.Hour, time.Hour} {
		if err := recordDashboardAudit(w.g.db, dashboardAuditRecord{
			TsNs: now.Add(-age).UnixNano(), Username: "root", AuthKind: "dashboard_password",
			Method: http.MethodPost, Path: "/api/users/create", Status: http.StatusCreated,
		}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := pruneDashboardAudit(w.g.db, now.Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruneDashboardAudit = %d, %v; want 1 record pruned", n, err)
	}
	if records, _ := listDashboardAudit(w.g.db, 0, 0); len(records) != 1 {
		t.Fatalf("%d records left, want 1", len(records))
	}
}

const usersPolicyHCL = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "gitlab" { hosts = ["gitlab.com"] }
credential "bearer_token" "gl" { endpoint = https.gitlab }
credential "slack_tokens" "ops-slack" {}
profile "team-a" { credentials = [bearer_token.gl] }
profile "team-b" { credentials = [bearer_token.gl] }
approver "human_approver" "team-a-review" {
  channel    = "#team-a"
  credential = slack_tokens.ops-slack
}
approver "llm_approver" "judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = bearer_token.gl
}
`

func withUsersPolicy(t *testing.T, w *webMux) {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(usersPolicyHCL), "users.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	w.g.cfg.Store(gw)
	w.g.policy.Store(cp)
}

func TestUserProfileAndApproverAssignment(t *testing.T) {
	w := newUsersTestMux(t)
	withUsersPolicy(t, w)
	h := w.handler()
	root := sessionCookieFor(t, w, dashboardRootUsername)

	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"assign", `{"username":"alice","profiles":["team-a"],"approver":"team-a-review"}`, http.StatusOK},
		{"undeclared profile", `{"username":"alice","profiles":["team-z"]}`, http.StatusBadRequest},
		{"llm approver", `{"username":"alice","approver":"judge"}`, http.StatusBadRequest},
		{"unknown user", `{"username":"nobody","profiles":["team-a"]}`, http.StatusNotFound},
	} {
		if rw := serveAs(t, h, root, http.MethodPost, "/api/users/update", tc.body); rw.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, rw.Code, tc.want, rw.Body.String())
		}
	}

	rw := serveAs(t, h, root, http.MethodGet, "/api/users", "")
	var list struct {
		Users          []dashboardUser `json:"users"`
		Profiles       []string        `json:"profiles"`
		HumanApprovers []string        `json:"human_approvers"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if strings.Join(list.Profiles, ",") != "team-a,team-b" || strings.Join(list.HumanApprovers, ",") != "team-a-review" {
		t.Fatalf("declared lists = %v / %v", list.Profiles, list.HumanApprovers)
	}
	for _, u := range list.Users {
		if u.Username == "alice" && (strings.Join(u.Profiles, ",") != "team-a" || u.Approver != "team-a-review") {
			t.Fatalf("alice = %+v", u)
		}
	}

	member := sessionCookieFor(t, w, "alice")
	rw = serveAs(t, h, member, http.MethodGet, "/api/me", "")
	var me struct {
		Profiles []string `json:"profiles"`
		Approver string   `json:"approver"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if strings.Join(me.Profiles, ",") != "team-a" || me.Approver != "team-a-review" {
		t.Fatalf("/api/me = %+v", me)
	}

	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/delete", `{"username":"alice"}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	if profiles, _ := listDashboardUserProfiles(w.g.db, "alice"); len(profiles) != 0 {
		t.Fatalf("profiles of a deleted user survive: %v", profiles)
	}
}
