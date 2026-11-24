package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func createJoinIntent(t *testing.T, env *rulesTestEnv, who *http.Cookie, body string) string {
	t.Helper()
	rw := serveAs(t, env.h, who, http.MethodPost, "/api/onboard/intent", body)
	if rw.Code != http.StatusOK {
		t.Fatalf("create intent %s = %d %s", body, rw.Code, rw.Body.String())
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil || resp.ID == "" {
		t.Fatalf("create intent response %s: %v", rw.Body.String(), err)
	}
	return resp.ID
}

// startIntentJoin plays `clawpatrol join --intent`'s /api/onboard/start.
func startIntentJoin(env *rulesTestEnv, query url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/start?"+query.Encode(), nil)
	req.Host = "localhost"
	rw := httptest.NewRecorder()
	env.h.ServeHTTP(rw, req)
	return rw
}

func intentJoinQuery(intent, hostname, osUser string) url.Values {
	return url.Values{"intent": {intent}, "hostname": {hostname}, "os_user": {osUser}, "os": {"linux"}}
}

func userCodeOf(t *testing.T, rw *httptest.ResponseRecorder) string {
	t.Helper()
	if rw.Code != http.StatusOK {
		t.Fatalf("start = %d %s", rw.Code, rw.Body.String())
	}
	var start struct {
		UserCode   string `json:"user_code"`
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &start); err != nil || start.UserCode == "" {
		t.Fatalf("start response %s: %v", rw.Body.String(), err)
	}
	return start.UserCode
}

func intentStatusAs(t *testing.T, env *rulesTestEnv, who *http.Cookie, id string) (int, joinIntentStatus) {
	t.Helper()
	rw := serveAs(t, env.h, who, http.MethodGet, "/api/onboard/intent/status?id="+url.QueryEscape(id), "")
	var st joinIntentStatus
	if rw.Code == http.StatusOK {
		if err := json.Unmarshal(rw.Body.Bytes(), &st); err != nil {
			t.Fatalf("status response %s: %v", rw.Body.String(), err)
		}
	}
	return rw.Code, st
}

func newIntentTestEnv(t *testing.T) *rulesTestEnv {
	t.Helper()
	env := newRulesTestEnv(t, true)
	reg := newOnboardRegistry()
	env.w.onboard, env.w.g.onboard = reg, reg
	return env
}

func TestJoinIntentNamesDeviceAfterMachineAndAccountAndKeepsItsProfile(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	if _, st := intentStatusAs(t, env, env.alice, id); st.State != joinIntentWaiting {
		t.Fatalf("fresh intent state = %q, want waiting", st.State)
	}

	q := intentJoinQuery(id, "hz-2025-fsn", "gemma")
	q.Set("profile", "team-b")
	code := userCodeOf(t, startIntentJoin(env, q))

	_, st := intentStatusAs(t, env, env.alice, id)
	if st.State != joinIntentPending || st.Device == nil {
		t.Fatalf("status after start = %+v, want pending with a device", st)
	}
	want := joinIntentDevice{Name: "hz-2025-fsn-gemma", OSHostname: "hz-2025-fsn", OSUser: "gemma", OS: "linux", UserCode: code}
	if *st.Device != want {
		t.Errorf("device = %+v, want %+v", *st.Device, want)
	}
	if st.Profile != "team-a" {
		t.Errorf("profile = %q, want the intent's team-a, not the CLI's team-b", st.Profile)
	}
	if st.Replaces != nil {
		t.Errorf("replaces = %+v on an empty gateway", st.Replaces)
	}
}

func TestJoinIntentOperatorNameWins(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.root, `{"profile":"team-a","device_name":"ci-runner"}`)
	userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "gemma")))
	if _, st := intentStatusAs(t, env, env.root, id); st.Device == nil || st.Device.Name != "ci-runner" {
		t.Fatalf("device = %+v, want ci-runner", st.Device)
	}
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/onboard/intent", `{"profile":"team-a","device_name":"bad name"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("invalid device name = %d, want 400", rw.Code)
	}
}

func TestJoinIntentSecondStartCancelsBothJoins(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	first := startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice"))
	userCodeOf(t, first)
	var firstStart struct {
		DeviceCode string `json:"device_code"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &firstStart)

	if rw := startIntentJoin(env, intentJoinQuery(id, "elsewhere", "mallory")); rw.Code != http.StatusConflict {
		t.Fatalf("second start = %d %s, want 409", rw.Code, rw.Body.String())
	}
	if _, st := intentStatusAs(t, env, env.alice, id); st.State != joinIntentConflict {
		t.Errorf("state = %q, want conflict", st.State)
	}
	poll := httptest.NewRequest(http.MethodPost, "/api/onboard/poll?device_code="+url.QueryEscape(firstStart.DeviceCode), nil)
	poll.Host = "localhost"
	rw := httptest.NewRecorder()
	env.h.ServeHTTP(rw, poll)
	if !strings.Contains(rw.Body.String(), "server_error") {
		t.Errorf("first device's poll = %s, want server_error", rw.Body.String())
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/approve", `{"code":"`+userCodeOf(t, first)+`","profile":"team-a"}`); rw.Code != http.StatusConflict {
		t.Errorf("approving the cancelled join = %d %s, want 409", rw.Code, rw.Body.String())
	}
}

func TestJoinIntentRefusedStartsLeaveNoSession(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	wm := intentJoinQuery(id, "hz-2025-fsn", "alice")
	wm.Set("whole_machine", "1")
	for name, tc := range map[string]struct {
		q    url.Values
		want int
	}{
		"whole machine":  {wm, http.StatusBadRequest},
		"unknown intent": {intentJoinQuery("nope", "hz-2025-fsn", "alice"), http.StatusNotFound},
		"unusable host":  {intentJoinQuery(id, "Vincent's Mac", "alice"), http.StatusBadRequest},
	} {
		if rw := startIntentJoin(env, tc.q); rw.Code != tc.want {
			t.Errorf("%s: start = %d %s, want %d", name, rw.Code, rw.Body.String(), tc.want)
		}
	}
	env.w.onboard.mu.Lock()
	left := len(env.w.onboard.byDevice)
	env.w.onboard.mu.Unlock()
	if left != 0 {
		t.Errorf("%d sessions left behind by refused starts", left)
	}
	if _, st := intentStatusAs(t, env, env.alice, id); st.State != joinIntentWaiting {
		t.Errorf("state = %q, want the intent still waiting", st.State)
	}
}

func TestJoinIntentApprovalConfirmsReplacementAndKeepsProfile(t *testing.T) {
	env := newIntentTestEnv(t)
	reg := env.w.onboard
	reg.AssignProfile("10.68.0.7", "team-a")
	reg.SetHostname("10.68.0.7", "hz-2025-fsn-alice")
	reg.AssignProfile("10.68.0.8", "team-b")
	reg.SetHostname("10.68.0.8", "hz-2025-fsn-bob")

	id := createJoinIntent(t, env, env.root, `{"profile":"team-a"}`)
	code := userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))
	_, st := intentStatusAs(t, env, env.root, id)
	if st.Replaces == nil || st.Replaces.Name != "hz-2025-fsn-alice" {
		t.Fatalf("replaces = %+v, want hz-2025-fsn-alice", st.Replaces)
	}
	if len(st.OnMachine) != 1 || st.OnMachine[0] != (deviceRef{Name: "hz-2025-fsn-bob", Profile: "team-b"}) {
		t.Errorf("on_machine = %+v, want only bob's device", st.OnMachine)
	}
	if len(st.Warnings) != 0 {
		t.Errorf("warnings = %v, want none for the account's own device", st.Warnings)
	}

	for _, step := range []struct {
		name, body string
		want       int
	}{
		{"other profile", `{"code":"` + code + `","profile":"team-b","replace":true}`, http.StatusForbidden},
		{"replace unconfirmed", `{"code":"` + code + `","profile":"team-a"}`, http.StatusConflict},
		{"replace confirmed", `{"code":"` + code + `","profile":"team-a","replace":true}`, http.StatusOK},
	} {
		if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/onboard/approve", step.body); rw.Code != step.want {
			t.Errorf("%s: approve = %d %s, want %d", step.name, rw.Code, rw.Body.String(), step.want)
		}
	}
}

func TestJoinIntentWarnsWhenProfileHasAnotherAccountOnTheMachine(t *testing.T) {
	env := newIntentTestEnv(t)
	env.w.onboard.AssignProfile("10.68.0.7", "team-a")
	env.w.onboard.SetHostname("10.68.0.7", "hz-2025-fsn-alice")

	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "gemma")))
	_, st := intentStatusAs(t, env, env.alice, id)
	if st.Replaces != nil {
		t.Errorf("replaces = %+v, want a new device", st.Replaces)
	}
	if len(st.Warnings) != 1 || !strings.Contains(st.Warnings[0], "hz-2025-fsn-alice") {
		t.Errorf("warnings = %v, want one about hz-2025-fsn-alice", st.Warnings)
	}
}

func TestJoinIntentIsScopedToItsCreator(t *testing.T) {
	env := newIntentTestEnv(t)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/intent", `{"profile":"team-b"}`); rw.Code != http.StatusForbidden {
		t.Errorf("alice creating an intent for team-b = %d, want 403", rw.Code)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/intent", `{"profile":"nope"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("unknown profile = %d, want 400", rw.Code)
	}
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	if code, _ := intentStatusAs(t, env, env.bob, id); code != http.StatusNotFound {
		t.Errorf("bob reading alice's intent = %d, want 404", code)
	}
	if rw := serveAs(t, env.h, env.bob, http.MethodPost, "/api/onboard/intent/reject", `{"id":"`+id+`"}`); rw.Code != http.StatusNotFound {
		t.Errorf("bob rejecting alice's intent = %d, want 404", rw.Code)
	}
	if code, _ := intentStatusAs(t, env, env.root, id); code != http.StatusOK {
		t.Errorf("admin reading alice's intent = %d, want 200", code)
	}
}

func TestJoinIntentRejectStopsTheWaitingJoin(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	code := userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/intent/reject", `{"id":"`+id+`"}`); rw.Code != http.StatusOK {
		t.Fatalf("reject = %d %s", rw.Code, rw.Body.String())
	}
	_, st := intentStatusAs(t, env, env.alice, id)
	if st.State != joinIntentRejected || st.Error == "" {
		t.Errorf("status = %+v, want rejected with an error for the CLI", st)
	}
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/approve", `{"code":"`+code+`","profile":"team-a"}`); rw.Code != http.StatusConflict {
		t.Errorf("approve after reject = %d %s, want 409", rw.Code, rw.Body.String())
	}
	if rw := startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")); rw.Code != http.StatusConflict {
		t.Errorf("start after reject = %d, want 409", rw.Code)
	}
}

func TestJoinIntentUsedAfterApprovalKeepsTheApprovedJoin(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.root, `{"profile":"team-a"}`)
	code := userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/onboard/approve", `{"code":"`+code+`","profile":"team-a"}`); rw.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rw.Code, rw.Body.String())
	}
	if rw := startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")); rw.Code != http.StatusConflict {
		t.Fatalf("start after approval = %d, want 409", rw.Code)
	}
	if _, st := intentStatusAs(t, env, env.root, id); st.State == joinIntentConflict {
		t.Errorf("state = conflict, want the approved join to stand")
	}
}
