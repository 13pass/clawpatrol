package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	oidcTestClientID = "dashboard-client"
	oidcTestKeyID    = "k1"
	oidcTestCode     = "good-code"
	oidcTestAccess   = "access-token"
)

// fakeOIDC is a minimal OpenID provider. Tests change its fields to
// make it answer wrongly in one way at a time.
type fakeOIDC struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	sub  string
	user string
	// nonce is what the next ID token carries; "" echoes the sign-in's.
	nonce    string
	lastSeen string
	audience string
	issuer   string
	expires  time.Duration
	signKey  *rsa.PrivateKey
	groups   []string
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{key: key, sub: "4242", user: "alice-gl", audience: oidcTestClientID, expires: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(rw).Encode(map[string]string{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
			"userinfo_endpoint":      f.srv.URL + "/userinfo",
			"jwks_uri":               f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(rw http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(rw).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &f.key.PublicKey, KeyID: oidcTestKeyID, Algorithm: string(jose.RS256), Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != oidcTestCode || r.PostForm.Get("code_verifier") == "" {
			http.Error(rw, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"access_token": oidcTestAccess, "token_type": "Bearer", "expires_in": 3600,
			"id_token": f.idToken(t),
		})
	})
	mux.HandleFunc("/userinfo", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+oidcTestAccess {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(rw).Encode(map[string]any{"sub": f.sub, "groups": f.groups})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) idToken(t *testing.T) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	signKey := f.key
	if f.signKey != nil {
		signKey = f.signKey
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256,
		Key: jose.JSONWebKey{Key: signKey, KeyID: oidcTestKeyID}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	issuer := f.srv.URL
	if f.issuer != "" {
		issuer = f.issuer
	}
	nonce := f.lastSeen
	if f.nonce != "" {
		nonce = f.nonce
	}
	now := time.Now()
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: issuer, Subject: f.sub, Audience: jwt.Audience{f.audience},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(f.expires)),
	}).Claims(map[string]any{"nonce": nonce, "preferred_username": f.user}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newOIDCTestMux(t *testing.T, f *fakeOIDC, allowedGroups string) *webMux {
	t.Helper()
	w := newUsersTestMux(t)
	src := `gateway {
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
  dashboard_oidc {
    issuer         = "` + f.srv.URL + `"
    client_id      = "` + oidcTestClientID + `"
    client_secret  = "s3cret"
    ` + allowedGroups + `
  }
}
`
	gw, diags := config.LoadBytes([]byte(src), "oidc.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	w.g.cfg.Store(gw)
	w.g.oidcState = &oidcState{client: f.srv.Client()}
	return w
}

// oidcSignIn runs the browser's side of a sign-in and returns the
// callback's response.
func oidcSignIn(t *testing.T, w *webMux, f *fakeOIDC, tamper func(state *string, cookie *http.Cookie)) *httptest.ResponseRecorder {
	t.Helper()
	h := w.handler()
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, oidcStartPath+"?next=/%23/rules", nil))
	if rw.Code != http.StatusFound {
		t.Fatalf("start = %d %s", rw.Code, rw.Body.String())
	}
	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), f.srv.URL+"/authorize") {
		t.Fatalf("start redirected to %q", rw.Header().Get("Location"))
	}
	q := loc.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		t.Fatalf("authorize request lacks PKCE or nonce: %s", loc)
	}
	f.mu.Lock()
	f.lastSeen = q.Get("nonce")
	f.mu.Unlock()
	var cookie *http.Cookie
	for _, c := range rw.Result().Cookies() {
		if c.Name == oidcStateCookie {
			cookie = c
		}
	}
	state := q.Get("state")
	if cookie == nil || cookie.Value != state {
		t.Fatalf("state cookie %v does not match state %q", cookie, state)
	}
	if tamper != nil {
		tamper(&state, cookie)
	}
	req := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code="+oidcTestCode+"&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rw = httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	return rw
}

func signedInAs(t *testing.T, w *webMux, rw *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rw.Result().Cookies() {
		if c.Name == cpSessionCookieName && c.Value != "" {
			su, ok, err := lookupDashboardSessionUser(w.g.db, c.Value)
			if err != nil || !ok {
				t.Fatalf("session: %v %v", ok, err)
			}
			if su.Method != sessionMethodOIDC {
				t.Errorf("session method = %q, want oidc", su.Method)
			}
			return su.Username
		}
	}
	return ""
}

func TestOIDCSignInBindsTheLinkedUserBySubject(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	if err := setDashboardUserOIDCUsername(w.g.db, "alice", "Alice-GL"); err != nil {
		t.Fatal(err)
	}
	rw := oidcSignIn(t, w, f, nil)
	if rw.Code != http.StatusFound || rw.Header().Get("Location") != "/#/rules" {
		t.Fatalf("callback = %d → %q %s", rw.Code, rw.Header().Get("Location"), rw.Body.String())
	}
	if got := signedInAs(t, w, rw); got != "alice" {
		t.Fatalf("signed in as %q, want alice", got)
	}

	// Renamed on the provider: the bound subject still decides.
	f.user = "alice-renamed"
	if got := signedInAs(t, w, oidcSignIn(t, w, f, nil)); got != "alice" {
		t.Fatalf("after a provider rename signed in as %q", got)
	}
	// Someone else now holds the old username: they get nothing.
	f.sub, f.user = "9999", "alice-gl"
	rw = oidcSignIn(t, w, f, nil)
	if rw.Code != http.StatusForbidden || signedInAs(t, w, rw) != "" {
		t.Fatalf("recycled username signed in: %d", rw.Code)
	}
}

func TestOIDCUnlinkedAccountIsRefused(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	rw := oidcSignIn(t, w, f, nil)
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "ask an admin to link it") {
		t.Fatalf("unlinked sign-in = %d %s", rw.Code, rw.Body.String())
	}
	records, _ := listDashboardAudit(w.g.db, 0, 0)
	if len(records) == 0 || records[0].Username != "@alice-gl" || records[0].Status != http.StatusForbidden {
		t.Fatalf("refused sign-in not audited: %+v", records)
	}
}

func TestOIDCSignInRejectsForgedOrMisboundResponses(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		provider func(f *fakeOIDC)
		tamper   func(state *string, cookie *http.Cookie)
		want     int
	}{
		"no state cookie":       {tamper: func(_ *string, c *http.Cookie) { c.Value = "" }, want: http.StatusBadRequest},
		"cookie of another run": {tamper: func(_ *string, c *http.Cookie) { c.Value = "forged" }, want: http.StatusBadRequest},
		"wrong nonce":           {provider: func(f *fakeOIDC) { f.nonce = "replayed" }, want: http.StatusUnauthorized},
		"wrong audience":        {provider: func(f *fakeOIDC) { f.audience = "another-app" }, want: http.StatusUnauthorized},
		"wrong issuer":          {provider: func(f *fakeOIDC) { f.issuer = "https://evil.example" }, want: http.StatusUnauthorized},
		"expired":               {provider: func(f *fakeOIDC) { f.expires = -time.Hour }, want: http.StatusUnauthorized},
		"signed by another key": {provider: func(f *fakeOIDC) { f.signKey = other }, want: http.StatusUnauthorized},
	}
	for name, tc := range cases {
		f := newFakeOIDC(t)
		w := newOIDCTestMux(t, f, "")
		if err := setDashboardUserOIDCUsername(w.g.db, "alice", "alice-gl"); err != nil {
			t.Fatal(err)
		}
		if tc.provider != nil {
			tc.provider(f)
		}
		rw := oidcSignIn(t, w, f, tc.tamper)
		if rw.Code != tc.want || signedInAs(t, w, rw) != "" {
			t.Errorf("%s: callback = %d, want %d and no session", name, rw.Code, tc.want)
		}
	}
}

func TestOIDCAllowedGroups(t *testing.T) {
	for name, tc := range map[string]struct {
		groups []string
		want   int
	}{
		"subgroup of an allowed group": {[]string{"unrcs/dco/team-a"}, http.StatusFound},
		"the allowed group itself":     {[]string{"UNRCS/dco"}, http.StatusFound},
		"a look-alike group":           {[]string{"unrcs/dcox"}, http.StatusForbidden},
		"no groups":                    {nil, http.StatusForbidden},
	} {
		f := newFakeOIDC(t)
		f.groups = tc.groups
		w := newOIDCTestMux(t, f, `allowed_groups = ["unrcs/dco"]`)
		if err := setDashboardUserOIDCUsername(w.g.db, "alice", "alice-gl"); err != nil {
			t.Fatal(err)
		}
		if rw := oidcSignIn(t, w, f, nil); rw.Code != tc.want {
			t.Errorf("%s: callback = %d, want %d", name, rw.Code, tc.want)
		}
	}
}

func TestPasswordlessLinkedUser(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	h := w.handler()
	root := sessionCookieFor(t, w, dashboardRootUsername)
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/create", `{"username":"carol","oidc_username":"@carol-gl"}`); rw.Code != http.StatusCreated {
		t.Fatalf("create passwordless = %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/create", `{"username":"dave","oidc_username":"CAROL-GL"}`); rw.Code != http.StatusConflict {
		t.Errorf("second link to the same account = %d, want 409", rw.Code)
	}
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/create", `{"username":"erin"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("no password and no link = %d, want 400", rw.Code)
	}
	if rw := postLogin(t, w, "username=carol&password="); rw.Code != http.StatusUnauthorized {
		t.Errorf("password login of a passwordless user = %d, want 401", rw.Code)
	}
	f.sub, f.user = "77", "carol-gl"
	rw := oidcSignIn(t, w, f, nil)
	if got := signedInAs(t, w, rw); got != "carol" {
		t.Fatalf("carol's sign-in = %d as %q", rw.Code, got)
	}
	carol := sessionCookieFor(t, w, "carol")
	if rw := serveAs(t, h, carol, http.MethodPost, "/api/me/password", `{"current":"","new":"brand-new-passphrase-1"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("passwordless user setting a password = %d, want 400", rw.Code)
	}

	// Relinking to another account unbinds the subject and ends sessions.
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/update", `{"username":"carol","oidc_username":"carol-new"}`); rw.Code != http.StatusOK {
		t.Fatalf("relink = %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, h, carol, http.MethodGet, "/api/me", ""); rw.Code != http.StatusUnauthorized {
		t.Errorf("carol's session after relinking = %d, want 401", rw.Code)
	}
	if rw := oidcSignIn(t, w, f, nil); rw.Code != http.StatusForbidden {
		t.Errorf("old account after relinking = %d, want 403", rw.Code)
	}
}

func TestLoginPageOffersOIDCOnlyWhenConfigured(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, httptest.NewRequest(http.MethodGet, "/__login?next=/", nil))
	if !strings.Contains(rw.Body.String(), "Sign in with SSO") || !strings.Contains(rw.Body.String(), oidcStartPath+"?next=") {
		t.Fatalf("login page lacks the sign-in button:\n%s", rw.Body.String())
	}
	plain := newUsersTestMux(t)
	rw = httptest.NewRecorder()
	plain.apiDashboardLogin(rw, httptest.NewRequest(http.MethodGet, "/__login?next=/", nil))
	if strings.Contains(rw.Body.String(), oidcStartPath) {
		t.Fatal("login page offers OIDC without a dashboard_oidc block")
	}
}

func TestDashboardOIDCConfigValidation(t *testing.T) {
	const publicURL = `public_url = "https://gw.example.test"`
	for name, tc := range map[string]struct {
		publicURL string
		block     []string
		ok        bool
	}{
		"gitlab default":  {publicURL, []string{`client_id = "x"`}, true},
		"loopback issuer": {publicURL, []string{`issuer = "http://127.0.0.1:9000"`, `client_id = "x"`}, true},
		"http issuer":     {publicURL, []string{`issuer = "http://gitlab.example"`, `client_id = "x"`}, false},
		"no client id":    {publicURL, []string{`client_id = ""`}, false},
		"no public url":   {"", []string{`client_id = "x"`}, false},
	} {
		src := "gateway {\n  " + tc.publicURL + "\n  wireguard {\n    subnet_cidr = \"10.55.0.0/24\"\n    endpoint = \"127.0.0.1:51820\"\n  }\n" +
			"  dashboard_oidc {\n    " + strings.Join(tc.block, "\n    ") + "\n  }\n}\n"
		_, diags := config.LoadBytes([]byte(src), "v.hcl")
		if diags.HasErrors() == tc.ok {
			t.Errorf("%s: errors = %v", name, diags)
		}
		if !tc.ok && !strings.Contains(diags.Error(), "dashboard_oidc") {
			t.Errorf("%s: rejected for another reason: %v", name, diags)
		}
	}
}
