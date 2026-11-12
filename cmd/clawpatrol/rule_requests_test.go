package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// approveRequest checks rw is a member's change waiting for review and
// has root approve it.
func approveRequest(t *testing.T, env *rulesTestEnv, rw *httptest.ResponseRecorder) int64 {
	t.Helper()
	id := pendingRequestID(t, rw)
	if rw := decideRequest(t, env, id, "approve", ""); rw.Code != http.StatusOK {
		t.Fatalf("approve request %d = %d %s", id, rw.Code, rw.Body.String())
	}
	return id
}

func pendingRequestID(t *testing.T, rw *httptest.ResponseRecorder) int64 {
	t.Helper()
	var out struct {
		Pending   bool  `json:"pending"`
		RequestID int64 `json:"request_id"`
	}
	if rw.Code != http.StatusAccepted || json.Unmarshal(rw.Body.Bytes(), &out) != nil || !out.Pending || out.RequestID == 0 {
		t.Fatalf("want a pending request (202), got %d %s", rw.Code, rw.Body.String())
	}
	return out.RequestID
}

func decideRequest(t *testing.T, env *rulesTestEnv, id int64, decision, extra string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAs(t, env.h, env.root, http.MethodPost, "/api/rule-requests/decide",
		fmt.Sprintf(`{"id":%d,"decision":%q%s}`, id, decision, extra))
}

func ruleRequestsFor(t *testing.T, env *rulesTestEnv, c *http.Cookie) []ruleChangeRequest {
	t.Helper()
	rw := serveAs(t, env.h, c, http.MethodGet, "/api/rule-requests", "")
	var out struct {
		Requests []ruleChangeRequest `json:"requests"`
	}
	if rw.Code != http.StatusOK || json.Unmarshal(rw.Body.Bytes(), &out) != nil {
		t.Fatalf("GET /api/rule-requests = %d %s", rw.Code, rw.Body.String())
	}
	return out.Requests
}

const aliceNotesPath = "/api/v4/projects/5/issues/6/notes"

func TestLooseningRuleWaitsForAnAdmin(t *testing.T) {
	env := newRulesTestEnv(t, true)
	create := `{"action_id":"` + env.aliceNotes + `","verdict":"allow","scope":"pattern","reason":"the review bot posts notes"}`
	rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/preview", create)
	if !strings.Contains(rw.Body.String(), `"needs_review":true`) {
		t.Fatalf("preview of a pre-approval: %s", rw.Body.String())
	}
	id := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", create))

	if _, err := os.Stat(filepath.Join(env.w.g.cfgPath, "50-user-alice.hcl")); !os.IsNotExist(err) {
		t.Fatalf("a pending request wrote alice's rules file (stat err %v)", err)
	}
	ep := env.w.g.Policy().Endpoints["gitlab"]
	if got := matchedRule(ep, httpReq("POST", aliceNotesPath, "team-a", nil)); got != "" {
		t.Fatalf("a pending rule already applies (%q)", got)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create", create); rw.Code != http.StatusConflict {
		t.Fatalf("asking twice = %d %s, want 409", rw.Code, rw.Body.String())
	}

	mine := ruleRequestsFor(t, env, env.alice)
	if len(mine) != 1 || mine[0].ID != id || mine[0].Reason != "the review bot posts notes" ||
		!strings.Contains(mine[0].Summary, "pre-approve POST") {
		t.Fatalf("alice's requests = %+v", mine)
	}
	if got := ruleRequestsFor(t, env, env.bob); len(got) != 0 {
		t.Fatalf("bob sees alice's requests: %+v", got)
	}
	if got := ruleRequestsFor(t, env, env.root); len(got) != 1 {
		t.Fatalf("root's requests = %+v", got)
	}
	env.w.bustStateCache()
	if rw := serveAs(t, env.h, env.root, http.MethodGet, "/api/state", ""); !strings.Contains(rw.Body.String(), `"rule_requests_pending":1`) {
		t.Fatalf("root's state lacks the pending count: %s", rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rule-requests/decide",
		fmt.Sprintf(`{"id":%d,"decision":"approve"}`, id)); rw.Code != http.StatusForbidden {
		t.Fatalf("alice deciding her own request = %d, want 403", rw.Code)
	}

	if rw := decideRequest(t, env, id, "approve", ""); rw.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rw.Code, rw.Body.String())
	}
	ep = env.w.g.Policy().Endpoints["gitlab"]
	if got := matchedRule(ep, httpReq("POST", aliceNotesPath, "team-a", nil)); !strings.HasPrefix(got, "alice-allow") {
		t.Fatalf("approved rule does not apply (matched %q)", got)
	}
	if got := ruleRequestsFor(t, env, env.alice); got[0].Status != ruleRequestApproved || got[0].DecidedBy != dashboardRootUsername {
		t.Fatalf("request after approval = %+v", got[0])
	}
	if rw := decideRequest(t, env, id, "reject", ""); rw.Code != http.StatusConflict {
		t.Fatalf("deciding twice = %d, want 409", rw.Code)
	}
}

func TestTighteningChangesApplyAtOnce(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"deny"}`); rw.Code != http.StatusOK {
		t.Fatalf("deny = %d %s", rw.Code, rw.Body.String())
	}
	var allowName string
	approveRequest(t, env, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"a-notes-12","verdict":"allow"}`))
	for _, r := range ruleRequestsFor(t, env, env.alice) {
		allowName = r.RuleName
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/update",
		`{"name":"`+allowName+`","disabled":true}`); rw.Code != http.StatusOK {
		t.Fatalf("disabling a pre-approval = %d %s, want 200", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/update",
		`{"name":"`+allowName+`","disabled":false}`); rw.Code != http.StatusAccepted {
		t.Fatalf("re-enabling a pre-approval = %d %s, want 202", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/delete",
		`{"name":"`+allowName+`"}`); rw.Code != http.StatusOK {
		t.Fatalf("deleting a pre-approval = %d %s, want 200", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, "50-user-alice.hcl"); strings.Contains(got, allowName) {
		t.Fatalf("pre-approval still in the file:\n%s", got)
	}
}

func TestAdminEditsARequestedRule(t *testing.T) {
	env := newRulesTestEnv(t, true)
	id := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"allow"}`))
	asked := ruleRequestsFor(t, env, env.root)[0].HCL

	broken, _ := json.Marshal(asked + "\nrule {")
	if rw := decideRequest(t, env, id, "approve", `,"hcl":`+string(broken)); rw.Code != http.StatusBadRequest {
		t.Fatalf("approving broken HCL = %d %s, want 400", rw.Code, rw.Body.String())
	}
	if got := ruleRequestsFor(t, env, env.root)[0]; got.Status != ruleRequestPending {
		t.Fatalf("a failed approval closed the request: %+v", got)
	}

	edited := strings.Replace(asked, "Pre-approved from the dashboard by alice", "Pre-approved by root for the review bot", 1)
	if edited == asked {
		t.Fatalf("requested rule has no reason to edit:\n%s", asked)
	}
	body, _ := json.Marshal(edited)
	if rw := decideRequest(t, env, id, "approve", `,"note":"narrowed the reason","hcl":`+string(body)); rw.Code != http.StatusOK {
		t.Fatalf("approve edited = %d %s", rw.Code, rw.Body.String())
	}
	if got := readCfgFile(t, env.w, "50-user-alice.hcl"); !strings.Contains(got, "Pre-approved by root for the review bot") {
		t.Fatalf("edited rule not written:\n%s", got)
	}
	got := ruleRequestsFor(t, env, env.alice)[0]
	if !got.Edited || got.HCL != edited || got.DecisionNote != "narrowed the reason" {
		t.Fatalf("request after an edited approval = %+v", got)
	}
}

func TestRejectWithdrawAndStaleRequests(t *testing.T) {
	env := newRulesTestEnv(t, true)
	rejected := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"allow"}`))
	if rw := decideRequest(t, env, rejected, "reject", `,"note":"use the bot's own token"`); rw.Code != http.StatusOK {
		t.Fatalf("reject = %d %s", rw.Code, rw.Body.String())
	}
	if _, err := os.Stat(filepath.Join(env.w.g.cfgPath, "50-user-alice.hcl")); !os.IsNotExist(err) {
		t.Fatal("a rejected request wrote alice's rules file")
	}

	withdrawn := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"approve"}`))
	body := fmt.Sprintf(`{"id":%d}`, withdrawn)
	if rw := serveAs(t, env.h, env.bob, http.MethodPost, "/api/rule-requests/withdraw", body); rw.Code != http.StatusNotFound {
		t.Fatalf("bob withdrawing alice's request = %d, want 404", rw.Code)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rule-requests/withdraw", body); rw.Code != http.StatusOK {
		t.Fatalf("withdraw = %d %s", rw.Code, rw.Body.String())
	}
	if rw := decideRequest(t, env, withdrawn, "approve", ""); rw.Code != http.StatusConflict {
		t.Fatalf("approving a withdrawn request = %d, want 409", rw.Code)
	}

	stale := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"a-notes-12","verdict":"allow"}`))
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/users/update", `{"username":"alice","profiles":[]}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	if rw := decideRequest(t, env, stale, "approve", ""); rw.Code != http.StatusConflict || !strings.Contains(rw.Body.String(), "no longer owns") {
		t.Fatalf("approving for a lost profile = %d %s, want 409", rw.Code, rw.Body.String())
	}
}

func TestRuleRequestsReachAdminsAndTheRequester(t *testing.T) {
	env := newRulesTestEnv(t, true)
	signal := &fakeSignal{}
	srv := httptest.NewServer(signal)
	t.Cleanup(srv.Close)
	if err := os.WriteFile(filepath.Join(env.w.g.cfgPath, "30-signal.hcl"), []byte(`credential "signal_cli" "ops" {}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	env.w.g.configMu.Lock()
	err := env.w.g.reloadConfigFromFileLocked(env.w.g.cfgPath)
	env.w.g.configMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	env.w.g.secrets = staticSecrets{"ops": {Extras: map[string]string{"api_url": srv.URL, "number": "+15550000000"}}}
	now := time.Now()
	for user, number := range map[string]string{dashboardRootUsername: "+15550000001", "alice": "+15550000002"} {
		if err := saveUnverifiedUserChannel(env.w.g.db, user, userChannel{Kind: "signal_cli", Target: number}, "h", now); err != nil {
			t.Fatal(err)
		}
		if err := markUserChannelVerified(env.w.g.db, user, now); err != nil {
			t.Fatal(err)
		}
	}

	id := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"allow","reason":"the review bot posts notes"}`))
	env.w.notifications.Wait()
	to, msg := signal.last(t)
	if to != "+15550000001" || !strings.Contains(msg, "alice asks to pre-approve POST") ||
		!strings.Contains(msg, "the review bot posts notes") || !strings.Contains(msg, "https://gw.example.test/#/rules") {
		t.Fatalf("admin message to %s: %q", to, msg)
	}

	if rw := decideRequest(t, env, id, "reject", `,"note":"use the bot's own token"`); rw.Code != http.StatusOK {
		t.Fatalf("reject = %d %s", rw.Code, rw.Body.String())
	}
	env.w.notifications.Wait()
	to, msg = signal.last(t)
	if to != "+15550000002" || !strings.Contains(msg, "root rejected your request") || !strings.Contains(msg, "use the bot's own token") {
		t.Fatalf("member message to %s: %q", to, msg)
	}
}

func TestDeletingAUserRetiresTheirRequests(t *testing.T) {
	env := newRulesTestEnv(t, true)
	id := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"allow"}`))
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/users/delete", `{"username":"alice"}`); rw.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rw.Code, rw.Body.String())
	}
	got, err := getRuleRequest(env.w.g.db, id)
	if err != nil || got.Status != ruleRequestWithdrawn || !strings.HasPrefix(got.Username, "alice (deleted ") {
		t.Fatalf("request after the user's deletion = %+v, %v", got, err)
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/users/create",
		`{"username":"alice","password":"`+usersTestMemberPassword+`"}`); rw.Code != http.StatusCreated {
		t.Fatalf("re-create alice = %d %s", rw.Code, rw.Body.String())
	}
	if mine := ruleRequestsFor(t, env, sessionCookieFor(t, env.w, "alice")); len(mine) != 0 {
		t.Fatalf("the new alice sees the old one's requests: %+v", mine)
	}
}

func TestEmptiedEditIsRefused(t *testing.T) {
	env := newRulesTestEnv(t, true)
	id := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"allow"}`))
	if rw := decideRequest(t, env, id, "approve", `,"hcl":"  "`); rw.Code != http.StatusBadRequest {
		t.Fatalf("approving an emptied rule = %d %s, want 400", rw.Code, rw.Body.String())
	}
	if _, err := os.Stat(filepath.Join(env.w.g.cfgPath, "50-user-alice.hcl")); !os.IsNotExist(err) {
		t.Fatal("an emptied edit applied the rule asked for")
	}
}

func TestDeletingADisabledDenyNeedsNoReview(t *testing.T) {
	env := newRulesTestEnv(t, true)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceNotes+`","verdict":"deny"}`); rw.Code != http.StatusOK {
		t.Fatal(rw.Body.String())
	}
	var mine struct {
		Rules []myRule `json:"rules"`
	}
	_ = json.Unmarshal(serveAs(t, env.h, env.alice, http.MethodGet, "/api/my/rules", "").Body.Bytes(), &mine)
	if len(mine.Rules) != 1 || strings.Join(mine.Rules[0].NeedsReview, ",") != "disable,delete" {
		t.Fatalf("a live deny's review needs = %+v", mine.Rules)
	}
	name := mine.Rules[0].Name
	approveRequest(t, env, serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/update", `{"name":"`+name+`","disabled":true}`))
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/my/rules/delete", `{"name":"`+name+`"}`); rw.Code != http.StatusOK {
		t.Fatalf("deleting a disabled deny = %d %s, want 200", rw.Code, rw.Body.String())
	}
}

func TestApprovalRefusesAHostThatGainedAnEndpoint(t *testing.T) {
	env := newRulesTestEnv(t, true)
	id := pendingRequestID(t, serveAs(t, env.h, env.alice, http.MethodPost, "/api/rules/create",
		`{"action_id":"`+env.aliceHost+`","verdict":"approve"}`))
	files := map[string]string{
		"40-example.hcl": `endpoint "https" "example" { hosts = ["example.org"] }
credential "bearer_token" "ex" { endpoint = https.example }
`,
		"20-profiles.hcl": strings.Replace(rulesTestProfiles, "bearer_token.sentry-a]", "bearer_token.sentry-a, bearer_token.ex]", 1),
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(env.w.g.cfgPath, name), []byte(src), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	env.w.g.configMu.Lock()
	err := env.w.g.reloadConfigFromFileLocked(env.w.g.cfgPath)
	env.w.g.configMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if rw := decideRequest(t, env, id, "approve", ""); rw.Code != http.StatusConflict || !strings.Contains(rw.Body.String(), `now has endpoint "example"`) {
		t.Fatalf("approving a stale host rule = %d %s, want 409", rw.Code, rw.Body.String())
	}
}

func TestRuleCreateSummaryNamesScopeAndHandWrittenCondition(t *testing.T) {
	ev := &Event{Endpoint: "gitlab", Method: "POST", Path: "/api/v4/projects"}
	cases := []struct {
		req  RuleRequest
		rule *ScopedRule
		want string
	}{
		{RuleRequest{Verdict: ruleVerdictDeny, Scope: ruleScopeAnyPath}, &ScopedRule{}, "block POST on gitlab, any path"},
		{RuleRequest{Verdict: ruleVerdictAllow, Scope: ruleScopeAnyPath, Condition: "true"}, &ScopedRule{HandWritten: true},
			"pre-approve requests on gitlab matching a condition written by hand"},
		// An unedited condition is the generated rule.
		{RuleRequest{Verdict: ruleVerdictAllow, Scope: ruleScopeAnyPath, Condition: "http.method == 'POST'"}, &ScopedRule{},
			"pre-approve POST on gitlab, any path"},
	}
	for _, tc := range cases {
		if got := ruleCreateSummary(tc.req, tc.rule, ev); got != tc.want {
			t.Errorf("summary = %q, want %q", got, tc.want)
		}
	}
}
