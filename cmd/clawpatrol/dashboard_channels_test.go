package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type fakeSignal struct {
	mu   sync.Mutex
	sent []struct {
		Recipients []string `json:"recipients"`
		Message    string   `json:"message"`
	}
}

func (f *fakeSignal) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	var m struct {
		Recipients []string `json:"recipients"`
		Message    string   `json:"message"`
	}
	_ = json.NewDecoder(r.Body).Decode(&m)
	f.mu.Lock()
	f.sent = append(f.sent, m)
	f.mu.Unlock()
	rw.WriteHeader(http.StatusCreated)
	_, _ = rw.Write([]byte(`{"timestamp":"1"}`))
}

func (f *fakeSignal) last(t *testing.T) (string, string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		t.Fatal("nothing sent")
	}
	m := f.sent[len(f.sent)-1]
	return strings.Join(m.Recipients, ","), m.Message
}

type staticSecrets map[string]runtime.Secret

func (s staticSecrets) Get(name string) (runtime.Secret, error) { return s[name], nil }

type channelTestEnv struct {
	w      *webMux
	h      http.Handler
	signal *fakeSignal
	alice  *http.Cookie
	root   *http.Cookie
}

func newChannelTestEnv(t *testing.T) *channelTestEnv {
	t.Helper()
	dir := t.TempDir()
	signal := &fakeSignal{}
	srv := httptest.NewServer(signal)
	t.Cleanup(srv.Close)
	cfgPath := filepath.Join(dir, "gateway.hcl")
	src := `gateway {
  state_dir  = "` + filepath.ToSlash(dir) + `"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
credential "signal_cli" "ops" {}
profile "team-a" { credentials = [] }
`
	if err := os.WriteFile(cfgPath, []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, policy, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{cfgPath: cfgPath, stateDir: dir, db: db,
		secrets: staticSecrets{"ops": {Extras: map[string]string{"api_url": srv.URL, "number": "+15550000000"}}}}
	g.cfg.Store(cfg)
	g.policy.Store(policy)
	w := &webMux{g: g}
	if err := setDashboardUser(db, dashboardRootUsername, usersTestRootPassword); err != nil {
		t.Fatal(err)
	}
	if err := createDashboardUser(db, "alice", usersTestMemberPassword, dashboardRoleMember); err != nil {
		t.Fatal(err)
	}
	return &channelTestEnv{w: w, h: w.handler(), signal: signal,
		alice: sessionCookieFor(t, w, "alice"), root: sessionCookieFor(t, w, dashboardRootUsername)}
}

var sentCode = regexp.MustCompile(`code is (\d{6})`)

func (e *channelTestEnv) code(t *testing.T) string {
	t.Helper()
	_, msg := e.signal.last(t)
	m := sentCode.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("no code in %q", msg)
	}
	return m[1]
}

func (e *channelTestEnv) myChannel(t *testing.T, c *http.Cookie) map[string]any {
	t.Helper()
	rw := serveAs(t, e.h, c, http.MethodGet, "/api/my/channel", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("GET /api/my/channel = %d: %s", rw.Code, rw.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func wantStatus(t *testing.T, rw *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rw.Code != want {
		t.Fatalf("status = %d, want %d: %s", rw.Code, want, rw.Body.String())
	}
}

func TestMemberSetsAndVerifiesTheirChannel(t *testing.T) {
	e := newChannelTestEnv(t)
	if kinds := e.myChannel(t, e.alice)["kinds"]; len(kinds.([]any)) != 1 || kinds.([]any)[0] != "signal_cli" {
		t.Fatalf("kinds = %v, want [signal_cli]", kinds)
	}
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/set", `{"kind":"signal_cli","target":"+41790000001"}`), http.StatusOK)
	if to, _ := e.signal.last(t); to != "+41790000001" {
		t.Fatalf("code sent to %q", to)
	}
	ch := e.myChannel(t, e.alice)["channel"].(map[string]any)
	if ch["verified"] != false || ch["target"] != "+41790000001" {
		t.Fatalf("channel before verify = %v", ch)
	}
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/test", `{}`), http.StatusBadRequest)
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/verify", `{"code":"`+e.code(t)+`"}`), http.StatusOK)
	if ch := e.myChannel(t, e.alice)["channel"].(map[string]any); ch["verified"] != true {
		t.Fatalf("channel after verify = %v", ch)
	}
	// The test message shares the code's send throttle.
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/test", `{}`), http.StatusTooManyRequests)
}

func TestChannelRejectsBadTargetsAndUnknownKinds(t *testing.T) {
	e := newChannelTestEnv(t)
	for _, body := range []string{
		`{"kind":"signal_cli","target":"0790000001"}`,
		`{"kind":"signal_cli","target":"+41790000001","secret":"x"}`,
		`{"kind":"slack_tokens","target":"#ops"}`,
	} {
		wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/set", body), http.StatusBadRequest)
	}
	if len(e.signal.sent) != 0 {
		t.Fatalf("sent %d messages for rejected channels", len(e.signal.sent))
	}
}

func TestChannelCodeAttemptsAreLimited(t *testing.T) {
	e := newChannelTestEnv(t)
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/set", `{"kind":"signal_cli","target":"group.YWJjZGVmZ2hpams="}`), http.StatusOK)
	code := e.code(t)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < channelCodeMaxAttempts; i++ {
		wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/verify", `{"code":"`+wrong+`"}`), http.StatusForbidden)
	}
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/verify", `{"code":"`+code+`"}`), http.StatusTooManyRequests)
}

func TestChannelSecretNeverReachesTheBrowser(t *testing.T) {
	e := newChannelTestEnv(t)
	if err := saveUnverifiedUserChannel(e.w.g.db, "alice", userChannel{Kind: "teams_workflow", Target: "Teams", Secret: "https://hook.example/sig=s3cret"}, "h", timeNowForTest()); err != nil {
		t.Fatal(err)
	}
	for _, rw := range []*httptest.ResponseRecorder{
		serveAs(t, e.h, e.alice, http.MethodGet, "/api/my/channel", ""),
		serveAs(t, e.h, e.root, http.MethodGet, "/api/users", ""),
	} {
		wantStatus(t, rw, http.StatusOK)
		if strings.Contains(rw.Body.String(), "s3cret") {
			t.Fatalf("secret leaked: %s", rw.Body.String())
		}
	}
}

func TestOnlyAnAdminClearsAnotherUsersChannel(t *testing.T) {
	e := newChannelTestEnv(t)
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/set", `{"kind":"signal_cli","target":"+41790000001"}`), http.StatusOK)
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/users/channel/clear", `{"username":"alice"}`), http.StatusForbidden)
	wantStatus(t, serveAs(t, e.h, e.root, http.MethodPost, "/api/users/channel/clear", `{"username":"alice"}`), http.StatusOK)
	if ch := e.myChannel(t, e.alice)["channel"]; ch != nil {
		t.Fatalf("channel after admin clear = %v", ch)
	}
}

func TestDeletingAUserDropsTheirChannel(t *testing.T) {
	e := newChannelTestEnv(t)
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/set", `{"kind":"signal_cli","target":"+41790000001"}`), http.StatusOK)
	if err := deleteDashboardUser(e.w.g.db, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupUserChannel(e.w.g.db, "alice"); err != errNoUserChannel {
		t.Fatalf("lookup after delete: %v", err)
	}
}

func timeNowForTest() time.Time { return time.Now() }

func TestParallelGuessesShareTheAttemptCap(t *testing.T) {
	e := newChannelTestEnv(t)
	wantStatus(t, serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/set", `{"kind":"signal_cli","target":"+41790000001"}`), http.StatusOK)
	wrong := "000000"
	if e.code(t) == wrong {
		wrong = "111111"
	}
	const guesses = 20
	codes := make(chan int, guesses)
	var wg sync.WaitGroup
	for i := 0; i < guesses; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- serveAs(t, e.h, e.alice, http.MethodPost, "/api/my/channel/verify", `{"code":"`+wrong+`"}`).Code
		}()
	}
	wg.Wait()
	close(codes)
	tried := 0
	for c := range codes {
		if c == http.StatusForbidden {
			tried++
		}
	}
	if tried != channelCodeMaxAttempts {
		t.Fatalf("%d guesses were checked, want %d", tried, channelCodeMaxAttempts)
	}
}
