package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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
	oidcTestHost     = "gw.example.test"
)

// fakeOIDC is a minimal OpenID provider. Tests change its fields to
// make it answer wrongly in one way at a time.
type fakeOIDC struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	mu  sync.Mutex
	sub string
	// idClaims and userinfoClaims are the extra claims each source
	// carries (username, email, groups, …).
	idClaims       map[string]any
	userinfoClaims map[string]any
	// nonce is what the next ID token carries; "" echoes the sign-in's.
	nonce    string
	lastSeen string
	audience string
	issuer   string
	// slash makes the provider's own issuer end in "/".
	slash   bool
	expires time.Duration
	signKey *rsa.PrivateKey
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{
		key: key, sub: "4242", audience: oidcTestClientID, expires: time.Hour,
		idClaims:       map[string]any{"preferred_username": "alice-gl"},
		userinfoClaims: map[string]any{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(rw).Encode(map[string]string{
			"issuer":                 f.ownIssuer(),
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
		out := map[string]any{"sub": f.sub}
		for k, v := range f.userinfoClaims {
			out[k] = v
		}
		_ = json.NewEncoder(rw).Encode(out)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) ownIssuer() string {
	if f.slash {
		return f.srv.URL + "/"
	}
	return f.srv.URL
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
	issuer := f.ownIssuer()
	if f.issuer != "" {
		issuer = f.issuer
	}
	nonce := f.lastSeen
	if f.nonce != "" {
		nonce = f.nonce
	}
	extra := map[string]any{"nonce": nonce}
	for k, v := range f.idClaims {
		extra[k] = v
	}
	now := time.Now()
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: issuer, Subject: f.sub, Audience: jwt.Audience{f.audience},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(f.expires)),
	}).Claims(extra).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// oidcTestProvider is one dashboard_oidc block of a test gateway.
type oidcTestProvider struct {
	name  string
	f     *fakeOIDC
	extra string // further attributes, one per line
}

func newOIDCTestMuxWith(t *testing.T, providers ...oidcTestProvider) *webMux {
	t.Helper()
	w := newUsersTestMux(t)
	src := "gateway {\n  public_url = \"https://" + oidcTestHost + "\"\n  wireguard { subnet_cidr = \"10.55.0.0/24\" }\n"
	for _, p := range providers {
		src += "  dashboard_oidc \"" + p.name + "\" {\n    issuer = \"" + p.f.ownIssuer() + "\"\n    client_id = \"" + oidcTestClientID +
			"\"\n    client_secret = \"s3cret\"\n    " + p.extra + "\n  }\n"
	}
	src += "}\n"
	gw, diags := config.LoadBytes([]byte(src), "oidc.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v\n%s", diags, src)
	}
	w.g.cfg.Store(gw)
	// Every fake serves under its own test certificate; one client
	// trusting them all stands in for the system roots.
	client := providers[0].f.srv.Client()
	for _, p := range providers[1:] {
		pool := client.Transport.(*http.Transport).TLSClientConfig.RootCAs
		pool.AddCert(p.f.srv.Certificate())
	}
	w.g.oidcState = &oidcState{client: client}
	return w
}

// newOIDCTestMux is a gateway with one provider, "gitlab", whose extra
// attributes are given.
func newOIDCTestMux(t *testing.T, f *fakeOIDC, extra string) *webMux {
	t.Helper()
	return newOIDCTestMuxWith(t, oidcTestProvider{"gitlab", f, extra})
}

func linkAt(t *testing.T, w *webMux, username, provider, account string) {
	t.Helper()
	if _, err := setDashboardUserOIDC(w.g.db, username, provider, account); err != nil {
		t.Fatal(err)
	}
}

// oidcSignIn runs the browser's side of a sign-in at provider and
// returns the callback's response.
func oidcSignIn(t *testing.T, w *webMux, f *fakeOIDC, provider string, tamper func(state *string, cookie *http.Cookie)) *httptest.ResponseRecorder {
	t.Helper()
	h := w.handler()
	rw := httptest.NewRecorder()
	start := httptest.NewRequest(http.MethodGet, oidcStartPath(provider)+"?next=/%23/rules", nil)
	start.Host = oidcTestHost
	h.ServeHTTP(rw, start)
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
	if want := "https://" + oidcTestHost + oidcCallbackPath(provider); q.Get("redirect_uri") != want {
		t.Fatalf("redirect_uri = %q, want %q", q.Get("redirect_uri"), want)
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
	if cookie == nil || cookie.Path != oidcStartPath(provider) {
		t.Fatalf("sign-in cookie = %+v, want one on %s", cookie, oidcStartPath(provider))
	}
	if pending, ok := w.g.oidc().openPending(cookie.Value); !ok || pending.State != state || pending.Provider != provider {
		t.Fatalf("sign-in cookie does not carry state %q for %s", state, provider)
	}
	if tamper != nil {
		tamper(&state, cookie)
	}
	req := httptest.NewRequest(http.MethodGet, oidcCallbackPath(provider)+"?code="+oidcTestCode+"&state="+url.QueryEscape(state), nil)
	req.Host = oidcTestHost
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
	linkAt(t, w, "alice", "gitlab", "Alice-GL")
	rw := oidcSignIn(t, w, f, "gitlab", nil)
	if rw.Code != http.StatusFound || rw.Header().Get("Location") != "/#/rules" {
		t.Fatalf("callback = %d → %q %s", rw.Code, rw.Header().Get("Location"), rw.Body.String())
	}
	if got := signedInAs(t, w, rw); got != "alice" {
		t.Fatalf("signed in as %q, want alice", got)
	}

	// Renamed on the provider: the bound subject still decides.
	f.idClaims["preferred_username"] = "alice-renamed"
	if got := signedInAs(t, w, oidcSignIn(t, w, f, "gitlab", nil)); got != "alice" {
		t.Fatalf("after a provider rename signed in as %q", got)
	}
	// Someone else now holds the old username: they get nothing.
	f.sub, f.idClaims["preferred_username"] = "9999", "alice-gl"
	rw = oidcSignIn(t, w, f, "gitlab", nil)
	if rw.Code != http.StatusForbidden || signedInAs(t, w, rw) != "" {
		t.Fatalf("recycled username signed in: %d", rw.Code)
	}
}

func TestOIDCUnlinkedAccountIsRefused(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	rw := oidcSignIn(t, w, f, "gitlab", nil)
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "ask an admin to link it") {
		t.Fatalf("unlinked sign-in = %d %s", rw.Code, rw.Body.String())
	}
	records, _ := listDashboardAudit(w.g.db, 0, 0)
	if len(records) == 0 || records[0].Username != "@alice-gl" || records[0].Status != http.StatusForbidden ||
		records[0].AuthKind != auditKindOIDC || records[0].Target != "login oidc gitlab" {
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
		"no state cookie":        {tamper: func(_ *string, c *http.Cookie) { c.Value = "" }, want: http.StatusBadRequest},
		"cookie of another run":  {tamper: func(_ *string, c *http.Cookie) { c.Value = "forged" }, want: http.StatusBadRequest},
		"state not the cookie's": {tamper: func(s *string, _ *http.Cookie) { *s = "another-state" }, want: http.StatusBadRequest},
		"tampered cookie": {tamper: func(_ *string, c *http.Cookie) {
			body, sig, _ := strings.Cut(c.Value, ".")
			payload, _ := base64.RawURLEncoding.DecodeString(body)
			payload = []byte(strings.Replace(string(payload), `"x":"/#/rules"`, `"x":"/evil"`, 1))
			c.Value = base64.RawURLEncoding.EncodeToString(payload) + "." + sig
		}, want: http.StatusBadRequest},
		"wrong nonce":           {provider: func(f *fakeOIDC) { f.nonce = "replayed" }, want: http.StatusUnauthorized},
		"wrong audience":        {provider: func(f *fakeOIDC) { f.audience = "another-app" }, want: http.StatusUnauthorized},
		"wrong issuer":          {provider: func(f *fakeOIDC) { f.issuer = "https://evil.example" }, want: http.StatusUnauthorized},
		"expired":               {provider: func(f *fakeOIDC) { f.expires = -time.Hour }, want: http.StatusUnauthorized},
		"signed by another key": {provider: func(f *fakeOIDC) { f.signKey = other }, want: http.StatusUnauthorized},
	}
	for name, tc := range cases {
		f := newFakeOIDC(t)
		w := newOIDCTestMux(t, f, "")
		linkAt(t, w, "alice", "gitlab", "alice-gl")
		if tc.provider != nil {
			tc.provider(f)
		}
		rw := oidcSignIn(t, w, f, "gitlab", tc.tamper)
		if rw.Code != tc.want || signedInAs(t, w, rw) != "" {
			t.Errorf("%s: callback = %d, want %d and no session", name, rw.Code, tc.want)
		}
	}
}

func TestOIDCGitLabStyleGroups(t *testing.T) {
	const gitlabStyle = `allowed_groups = ["unrcs/dco"]
    groups_source = "userinfo"
    group_match = "subgroups"`
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
		f.userinfoClaims["groups"] = tc.groups
		w := newOIDCTestMux(t, f, gitlabStyle)
		linkAt(t, w, "alice", "gitlab", "alice-gl")
		if rw := oidcSignIn(t, w, f, "gitlab", nil); rw.Code != tc.want {
			t.Errorf("%s: callback = %d, want %d", name, rw.Code, tc.want)
		}
	}
}

func TestOIDCEntraStyleGroupsAndEmailUsernames(t *testing.T) {
	const groupID = "6f1b2c3d-0000-4000-8000-0123456789ab"
	for name, tc := range map[string]struct {
		groups []any
		want   int
	}{
		"in the group":               {[]any{"aaaaaaaa-0000-4000-8000-000000000000", groupID}, http.StatusFound},
		"not in it":                  {[]any{"aaaaaaaa-0000-4000-8000-000000000000"}, http.StatusForbidden},
		"prefix is not enough":       {[]any{groupID + "/sub"}, http.StatusForbidden},
		"groups only somewhere else": {nil, http.StatusForbidden},
	} {
		f := newFakeOIDC(t)
		f.idClaims = map[string]any{"preferred_username": "Alice.Doe@un.org"}
		if tc.groups != nil {
			f.idClaims["groups"] = tc.groups
		}
		// Groups in userinfo must not count: this provider reads the token.
		f.userinfoClaims["groups"] = []string{groupID}
		w := newOIDCTestMuxWith(t, oidcTestProvider{"entra", f, `allowed_groups = ["` + groupID + `"]`})
		linkAt(t, w, "alice", "entra", "alice.doe@un.org")
		if rw := oidcSignIn(t, w, f, "entra", nil); rw.Code != tc.want {
			t.Errorf("%s: callback = %d, want %d", name, rw.Code, tc.want)
		}
	}
}

func TestOIDCUsernameClaimFromUserinfo(t *testing.T) {
	// A Google-like provider: no username in the token, the email in
	// userinfo.
	f := newFakeOIDC(t)
	f.idClaims = map[string]any{}
	f.userinfoClaims["email"] = "alice@example.org"
	w := newOIDCTestMuxWith(t, oidcTestProvider{"google", f, `username_claim = "email"
    scopes = ["openid", "email"]`})
	linkAt(t, w, "alice", "google", "alice@example.org")
	rw := oidcSignIn(t, w, f, "google", nil)
	if got := signedInAs(t, w, rw); got != "alice" {
		t.Fatalf("sign-in by userinfo email = %d as %q", rw.Code, got)
	}
}

func TestOIDCSeveralProvidersSideBySide(t *testing.T) {
	gl, entra := newFakeOIDC(t), newFakeOIDC(t)
	// The same subject value at both: the issuer keeps them apart.
	gl.sub, entra.sub = "42", "42"
	gl.idClaims = map[string]any{"preferred_username": "alice-gl"}
	entra.idClaims = map[string]any{"preferred_username": "alice@un.org"}
	w := newOIDCTestMuxWith(t,
		oidcTestProvider{"gitlab", gl, `display_name = "GitLab"`},
		oidcTestProvider{"entra", entra, `display_name = "Entra ID"`},
	)
	linkAt(t, w, "alice", "gitlab", "alice-gl")
	linkAt(t, w, "alice", "entra", "alice@un.org")

	for provider, f := range map[string]*fakeOIDC{"gitlab": gl, "entra": entra} {
		if got := signedInAs(t, w, oidcSignIn(t, w, f, provider, nil)); got != "alice" {
			t.Fatalf("sign-in at %s = %q, want alice", provider, got)
		}
	}
	// A sign-in started at one provider does not complete at the other.
	h := w.handler()
	start := httptest.NewRequest(http.MethodGet, oidcStartPath("gitlab"), nil)
	start.Host = oidcTestHost
	srw := httptest.NewRecorder()
	h.ServeHTTP(srw, start)
	var glCookie *http.Cookie
	for _, c := range srw.Result().Cookies() {
		if c.Name == oidcStateCookie {
			glCookie = c
		}
	}
	state := mustQuery(t, srw.Header().Get("Location"), "state")
	cross := httptest.NewRequest(http.MethodGet, oidcCallbackPath("entra")+"?code="+oidcTestCode+"&state="+state, nil)
	cross.Host = oidcTestHost
	cross.AddCookie(glCookie)
	crw := httptest.NewRecorder()
	h.ServeHTTP(crw, cross)
	if crw.Code != http.StatusBadRequest {
		t.Errorf("gitlab sign-in completed at entra's callback: %d", crw.Code)
	}

	// The login page offers both.
	lrw := httptest.NewRecorder()
	w.apiDashboardLogin(lrw, httptest.NewRequest(http.MethodGet, "/__login?next=/", nil))
	for _, want := range []string{"Sign in with GitLab", "Sign in with Entra ID", oidcStartPath("gitlab") + "?next=", oidcStartPath("entra") + "?next="} {
		if !strings.Contains(lrw.Body.String(), want) {
			t.Errorf("login page lacks %q", want)
		}
	}
	// An unknown provider is a 404.
	urw := httptest.NewRecorder()
	unknown := httptest.NewRequest(http.MethodGet, oidcStartPath("okta"), nil)
	unknown.Host = oidcTestHost
	h.ServeHTTP(urw, unknown)
	if urw.Code != http.StatusNotFound {
		t.Errorf("unknown provider = %d, want 404", urw.Code)
	}
}

func mustQuery(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func TestPasswordlessLinkedUser(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	h := w.handler()
	root := sessionCookieFor(t, w, dashboardRootUsername)
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/create", `{"username":"carol","oidc":{"gitlab":"@carol-gl"}}`); rw.Code != http.StatusCreated {
		t.Fatalf("create passwordless = %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/create", `{"username":"dave","oidc":{"gitlab":"CAROL-GL"}}`); rw.Code != http.StatusConflict {
		t.Errorf("second link to the same account = %d, want 409", rw.Code)
	}
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/create", `{"username":"erin"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("no password and no link = %d, want 400", rw.Code)
	}
	if rw := postLogin(t, w, "username=carol&password="); rw.Code != http.StatusUnauthorized {
		t.Errorf("password login of a passwordless user = %d, want 401", rw.Code)
	}
	f.sub, f.idClaims["preferred_username"] = "77", "carol-gl"
	rw := oidcSignIn(t, w, f, "gitlab", nil)
	if got := signedInAs(t, w, rw); got != "carol" {
		t.Fatalf("carol's sign-in = %d as %q", rw.Code, got)
	}
	carol := sessionCookieFor(t, w, "carol")
	if rw := serveAs(t, h, carol, http.MethodPost, "/api/me/password", `{"current":"","new":"brand-new-passphrase-1"}`); rw.Code != http.StatusBadRequest {
		t.Errorf("passwordless user setting a password = %d, want 400", rw.Code)
	}

	// Saving the same link (any case) changes nothing and keeps sessions.
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/update", `{"username":"carol","oidc":{"gitlab":"Carol-GL"}}`); rw.Code != http.StatusOK {
		t.Fatalf("unchanged link = %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, h, carol, http.MethodGet, "/api/me", ""); rw.Code != http.StatusOK {
		t.Errorf("carol's session after an unchanged link = %d, want 200", rw.Code)
	}
	// Relinking to another account unbinds the subject and ends sessions.
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/update", `{"username":"carol","oidc":{"gitlab":"carol-new"}}`); rw.Code != http.StatusOK {
		t.Fatalf("relink = %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveAs(t, h, carol, http.MethodGet, "/api/me", ""); rw.Code != http.StatusUnauthorized {
		t.Errorf("carol's session after relinking = %d, want 401", rw.Code)
	}
	if rw := oidcSignIn(t, w, f, "gitlab", nil); rw.Code != http.StatusForbidden {
		t.Errorf("old account after relinking = %d, want 403", rw.Code)
	}
}

func TestOIDCAccountLinkingRules(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	h := w.handler()
	if err := createDashboardUser(w.g.db, "ada", "ada-passphrase-1234", dashboardRoleAdmin); err != nil {
		t.Fatal(err)
	}
	ada := sessionCookieFor(t, w, "ada")
	root := sessionCookieFor(t, w, dashboardRootUsername)

	// One admin cannot link another admin, or root, to an account.
	for target, caller := range map[string]*http.Cookie{dashboardRootUsername: ada, "ada": root} {
		if rw := serveAs(t, h, caller, http.MethodPost, "/api/users/update", `{"username":"`+target+`","oidc":{"gitlab":"takeover"}}`); rw.Code != http.StatusForbidden {
			t.Errorf("linking admin %s = %d, want 403", target, rw.Code)
		}
	}
	// An admin may link their own account, and stays signed in.
	rw := serveAs(t, h, ada, http.MethodPost, "/api/users/update", `{"username":"ada","oidc":{"gitlab":"ada-gl"}}`)
	if rw.Code != http.StatusOK {
		t.Fatalf("self link = %d %s", rw.Code, rw.Body.String())
	}
	if got := sessionUserFromResponse(t, w, rw); got != "ada" {
		t.Errorf("self link did not re-mint the caller's session (got %q)", got)
	}

	// A refused link leaves no partial change behind.
	if rw := serveAs(t, h, root, http.MethodPost, "/api/users/update", `{"username":"alice","role":"admin","oidc":{"gitlab":"ADA-GL"}}`); rw.Code != http.StatusConflict {
		t.Fatalf("link to a taken account = %d, want 409", rw.Code)
	}
	if role, _, _ := lookupDashboardUserRole(w.g.db, "alice"); role != dashboardRoleMember {
		t.Errorf("refused request promoted alice to %q", role)
	}

	// The database itself refuses a second link to one account.
	if _, err := w.g.db.Exec(`INSERT INTO dashboard_user_oidc (provider, username, account) VALUES ('gitlab', 'alice', 'Ada-GL')`); !isUniqueViolation(err) {
		t.Errorf("duplicate link at the database = %v, want a UNIQUE violation", err)
	}
}

func TestOIDCLinkNeedsTheProviderConfigured(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	h := w.handler()
	root := sessionCookieFor(t, w, dashboardRootUsername)
	for path, body := range map[string]string{
		"/api/users/create": `{"username":"bob","oidc":{"okta":"bob"}}`,
		"/api/users/update": `{"username":"alice","oidc":{"okta":"alice"}}`,
	} {
		if rw := serveAs(t, h, root, http.MethodPost, path, body); rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "no sign-in provider") {
			t.Errorf("%s with an unknown provider = %d %s", path, rw.Code, rw.Body.String())
		}
	}
}

func TestOIDCStartMovesToPublicURLHost(t *testing.T) {
	f := newFakeOIDC(t)
	w := newOIDCTestMux(t, f, "")
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, oidcStartPath("gitlab")+"?next=/x", nil)
	req.Host = "100.64.0.1:8080"
	w.handler().ServeHTTP(rw, req)
	if want := "https://" + oidcTestHost + oidcStartPath("gitlab") + "?next=%2Fx"; rw.Code != http.StatusFound || rw.Header().Get("Location") != want {
		t.Fatalf("start on another host = %d → %q, want %q", rw.Code, rw.Header().Get("Location"), want)
	}
	for _, c := range rw.Result().Cookies() {
		if c.Name == oidcStateCookie {
			t.Fatal("sign-in cookie set on the wrong host")
		}
	}
}

func TestOIDCIssuerWithTrailingSlash(t *testing.T) {
	f := newFakeOIDC(t)
	f.slash = true
	w := newOIDCTestMux(t, f, "")
	linkAt(t, w, "alice", "gitlab", "alice-gl")
	if got := signedInAs(t, w, oidcSignIn(t, w, f, "gitlab", nil)); got != "alice" {
		t.Fatalf("sign-in with a trailing-slash issuer signed in as %q", got)
	}
}

func TestLoginPageOffersOIDCOnlyWhenConfigured(t *testing.T) {
	plain := newUsersTestMux(t)
	rw := httptest.NewRecorder()
	plain.apiDashboardLogin(rw, httptest.NewRequest(http.MethodGet, "/__login?next=/", nil))
	if strings.Contains(rw.Body.String(), oidcPathPrefix) {
		t.Fatal("login page offers OIDC without a dashboard_oidc block")
	}
}

func TestDashboardOIDCConfigValidation(t *testing.T) {
	const publicURL = `public_url = "https://gw.example.test"`
	block := func(name string, attrs ...string) string {
		return "  dashboard_oidc \"" + name + "\" {\n    " + strings.Join(attrs, "\n    ") + "\n  }\n"
	}
	for name, tc := range map[string]struct {
		publicURL string
		blocks    string
		ok        bool
	}{
		"gitlab default":    {publicURL, block("gitlab", `client_id = "x"`), true},
		"two providers":     {publicURL, block("gitlab", `client_id = "x"`) + block("entra", `issuer = "https://login.microsoftonline.com/t/v2.0"`, `client_id = "y"`), true},
		"loopback issuer":   {publicURL, block("dev", `issuer = "http://127.0.0.1:9000"`, `client_id = "x"`), true},
		"duplicate name":    {publicURL, block("gitlab", `client_id = "x"`) + block("gitlab", `client_id = "y"`), false},
		"bad name":          {publicURL, block("Git Lab", `client_id = "x"`), false},
		"http issuer":       {publicURL, block("gl", `issuer = "http://gitlab.example"`, `client_id = "x"`), false},
		"no client id":      {publicURL, block("gl", `client_id = ""`), false},
		"no openid scope":   {publicURL, block("gl", `client_id = "x"`, `scopes = ["profile"]`), false},
		"bad groups_source": {publicURL, block("gl", `client_id = "x"`, `groups_source = "header"`), false},
		"bad group_match":   {publicURL, block("gl", `client_id = "x"`, `group_match = "prefix"`), false},
		"no public url":     {"", block("gl", `client_id = "x"`), false},
	} {
		src := "gateway {\n  " + tc.publicURL + "\n  wireguard {\n    subnet_cidr = \"10.55.0.0/24\"\n    endpoint = \"127.0.0.1:51820\"\n  }\n" + tc.blocks + "}\n"
		_, diags := config.LoadBytes([]byte(src), "v.hcl")
		if diags.HasErrors() == tc.ok {
			t.Errorf("%s: errors = %v", name, diags)
		}
		if !tc.ok && !strings.Contains(diags.Error(), "dashboard_oidc") {
			t.Errorf("%s: rejected for another reason: %v", name, diags)
		}
	}
}

func TestOIDCProviderDefaults(t *testing.T) {
	gitlab := &config.DashboardOIDCBlock{Name: "gitlab"}
	entra := &config.DashboardOIDCBlock{Name: "entra", Issuer: "https://login.microsoftonline.com/t/v2.0"}
	if gitlab.GroupsSourceOrDefault() != config.OIDCGroupsFromUserinfo || gitlab.GroupMatchOrDefault() != config.OIDCGroupMatchSubtree || gitlab.Label() != "Sign in with GitLab" {
		t.Errorf("gitlab.com defaults: %s %s %q", gitlab.GroupsSourceOrDefault(), gitlab.GroupMatchOrDefault(), gitlab.Label())
	}
	if entra.GroupsSourceOrDefault() != config.OIDCGroupsFromIDToken || entra.GroupMatchOrDefault() != config.OIDCGroupMatchExact || entra.Label() != "Sign in with entra" {
		t.Errorf("other-provider defaults: %s %s %q", entra.GroupsSourceOrDefault(), entra.GroupMatchOrDefault(), entra.Label())
	}
}
