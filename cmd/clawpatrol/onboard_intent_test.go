package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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

// intentJoinQuery plays an agent following the prompt on machine as
// account: --hostname <machine>-<account>.
func intentJoinQuery(intent, machine, account string) url.Values {
	return url.Values{"intent": {intent}, "hostname": {machine + "-" + account}}
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

// joinedDevice registers a device as a join would.
func joinedDevice(reg *onboardRegistry, ip, name, profile string) {
	reg.AssignProfile(ip, profile)
	reg.SetHostname(ip, name)
}

func newIntentTestEnv(t *testing.T) *rulesTestEnv {
	t.Helper()
	env := newRulesTestEnv(t, true)
	reg := newOnboardRegistry()
	env.w.onboard, env.w.g.onboard = reg, reg
	return env
}

func TestJoinIntentNamesTheDeviceInLowercaseAndKeepsItsProfile(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	if _, st := intentStatusAs(t, env, env.alice, id); st.State != joinIntentWaiting {
		t.Fatalf("fresh intent state = %q, want waiting", st.State)
	}

	q := intentJoinQuery(id, "HZ-2025-fsn", "Gemma")
	q.Set("profile", "team-b")
	code := userCodeOf(t, startIntentJoin(env, q))

	_, st := intentStatusAs(t, env, env.alice, id)
	if st.State != joinIntentPending || st.Device == nil {
		t.Fatalf("status after start = %+v, want pending with a device", st)
	}
	want := joinIntentDevice{Name: "hz-2025-fsn-gemma", UserCode: code}
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
		"no name":        {url.Values{"intent": {id}}, http.StatusBadRequest},
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
	joinedDevice(env.w.onboard, "10.68.0.7", "hz-2025-fsn-alice", "team-a")
	joinedDevice(env.w.onboard, "10.68.0.8", "hz-2025-fsn-bob", "team-b")

	id := createJoinIntent(t, env, env.root, `{"profile":"team-a"}`)
	code := userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))
	_, st := intentStatusAs(t, env, env.root, id)
	if st.Replaces == nil || st.Replaces.Name != "hz-2025-fsn-alice" {
		t.Fatalf("replaces = %+v, want hz-2025-fsn-alice", st.Replaces)
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

func TestJoinIntentReportsAFailedSetup(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.root, `{"profile":"team-a"}`)
	code := userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))
	s := env.w.onboard.byUserCode(code)
	env.w.onboard.mu.Lock()
	s.approved, s.err = true, "mint: boom"
	env.w.onboard.mu.Unlock()
	if _, st := intentStatusAs(t, env, env.root, id); st.State != joinIntentFailed || st.Error != "mint: boom" {
		t.Errorf("status = %+v, want failed with the mint error", st)
	}
}

func TestJoinIntentApprovingTwiceReportsAlready(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.root, `{"profile":"team-a"}`)
	code := userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))
	body := `{"code":"` + code + `","profile":"team-a"}`
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/onboard/approve", body); rw.Code != http.StatusOK {
		t.Fatalf("first approve = %d %s", rw.Code, rw.Body.String())
	}
	// The first approval's claim registers the device under the same name.
	joinedDevice(env.w.onboard, "10.68.0.7", "hz-2025-fsn-alice", "team-a")
	rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/onboard/approve", body)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `"already":true`) {
		t.Errorf("second approve = %d %s, want already", rw.Code, rw.Body.String())
	}
}

func TestJoinIntentWithoutProfilesOnAProfilelessGateway(t *testing.T) {
	env := newIntentTestEnv(t)
	env.w.g.cfg.Load().Policy = nil
	if rw := serveAs(t, env.h, env.root, http.MethodPost, "/api/onboard/intent", `{}`); rw.Code != http.StatusOK {
		t.Errorf("create without profiles = %d %s, want 200", rw.Code, rw.Body.String())
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

func TestJoinIntentClaimKeepsTheIntentName(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.root, `{"profile":"team-a"}`)
	s := env.w.onboard.byUserCode(userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "HZ-2025-fsn", "gemma"))))
	env.w.onboard.mu.Lock()
	s.owner = "root"
	deviceCode := s.deviceCode
	env.w.onboard.mu.Unlock()

	const ip = "10.68.0.9"
	if _, ok := env.w.onboard.ClaimIP(deviceCode, ip, "HZ-2025-fsn-gemma"); !ok {
		t.Fatal("claim refused")
	}
	env.w.onboard.mu.Lock()
	got := env.w.onboard.hostnameByIP[ip]
	env.w.onboard.mu.Unlock()
	if got != "hz-2025-fsn-gemma" {
		t.Errorf("claimed name = %q, want the intent's hz-2025-fsn-gemma", got)
	}
}

func TestJoinIntentLivesWhileTheWindowPolls(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	in := env.w.onboard.intentByID(id)
	setSeen := func(ago time.Duration) {
		env.w.onboard.mu.Lock()
		in.seen = time.Now().Add(-ago)
		env.w.onboard.mu.Unlock()
	}

	// Older than a device-flow session, but polled recently.
	setSeen(joinIntentIdle / 2)
	env.w.onboard.mu.Lock()
	in.created = time.Now().Add(-2 * onboardSessionTTL)
	env.w.onboard.mu.Unlock()
	if _, st := intentStatusAs(t, env, env.alice, id); st.State != joinIntentWaiting {
		t.Fatalf("polled intent state = %q, want waiting", st.State)
	}
	setSeen(joinIntentIdle / 2)
	userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))

	lapsed := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	in = env.w.onboard.intentByID(lapsed)
	setSeen(joinIntentIdle + time.Second)
	if _, st := intentStatusAs(t, env, env.alice, lapsed); st.State != joinIntentExpired {
		t.Errorf("unpolled intent state = %q, want expired", st.State)
	}
	if _, st := intentStatusAs(t, env, env.alice, lapsed); st.State != joinIntentExpired {
		t.Errorf("a poll revived a lapsed intent: state = %q", st.State)
	}
	if rw := startIntentJoin(env, intentJoinQuery(lapsed, "hz-2025-fsn", "alice")); rw.Code != http.StatusNotFound {
		t.Errorf("start with a lapsed intent = %d, want 404", rw.Code)
	}
}

func TestJoinIntentPollTellsTheClientItsName(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.root, `{"profile":"team-a"}`)
	s := env.w.onboard.byUserCode(userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "gemma"))))
	env.w.onboard.mu.Lock()
	s.approved, s.owner, s.authKey = true, "root", "wireguard-config"
	deviceCode := s.deviceCode
	env.w.onboard.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/poll?device_code="+url.QueryEscape(deviceCode), nil)
	req.Host = "localhost"
	rw := httptest.NewRecorder()
	env.h.ServeHTTP(rw, req)
	var resp map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("poll = %d %s: %v", rw.Code, rw.Body.String(), err)
	}
	if resp["device_name"] != "hz-2025-fsn-gemma" {
		t.Errorf("poll device_name = %v, want hz-2025-fsn-gemma (response %s)", resp["device_name"], rw.Body.String())
	}
}

func TestJoinIntentSecondStartStillConflictsAfterTheWindowWentQuiet(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	userCodeOf(t, startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")))
	in := env.w.onboard.intentByID(id)
	env.w.onboard.mu.Lock()
	in.seen = time.Now().Add(-joinIntentIdle - time.Second)
	env.w.onboard.mu.Unlock()

	if rw := startIntentJoin(env, intentJoinQuery(id, "other-box", "mallory")); rw.Code != http.StatusConflict {
		t.Errorf("second start = %d %s, want 409", rw.Code, rw.Body.String())
	}
	if _, st := intentStatusAs(t, env, env.alice, id); st.State != joinIntentConflict {
		t.Errorf("state = %q, want conflict", st.State)
	}
}

func TestJoinIntentLapsesAfterAnHourEvenWhilePolled(t *testing.T) {
	env := newIntentTestEnv(t)
	id := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	in := env.w.onboard.intentByID(id)
	env.w.onboard.mu.Lock()
	in.created = time.Now().Add(-joinIntentMaxAge - time.Second)
	env.w.onboard.mu.Unlock()
	if _, st := intentStatusAs(t, env, env.alice, id); st.State != joinIntentExpired {
		t.Errorf("state = %q, want expired past joinIntentMaxAge", st.State)
	}
	if rw := startIntentJoin(env, intentJoinQuery(id, "hz-2025-fsn", "alice")); rw.Code != http.StatusNotFound {
		t.Errorf("start = %d, want 404", rw.Code)
	}
}

func TestJoinIntentRejectIfUnusedSparesAStartedJoin(t *testing.T) {
	env := newIntentTestEnv(t)
	unused := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/intent/reject", `{"id":"`+unused+`","if_unused":true}`); rw.Code != http.StatusOK {
		t.Errorf("reject unused = %d %s, want 200", rw.Code, rw.Body.String())
	}

	used := createJoinIntent(t, env, env.alice, `{"profile":"team-a"}`)
	userCodeOf(t, startIntentJoin(env, intentJoinQuery(used, "hz-2025-fsn", "alice")))
	if rw := serveAs(t, env.h, env.alice, http.MethodPost, "/api/onboard/intent/reject", `{"id":"`+used+`","if_unused":true}`); rw.Code != http.StatusConflict {
		t.Errorf("reject if unused after a start = %d %s, want 409", rw.Code, rw.Body.String())
	}
	if _, st := intentStatusAs(t, env, env.alice, used); st.State != joinIntentPending {
		t.Errorf("state = %q, want the started join still pending", st.State)
	}
}
