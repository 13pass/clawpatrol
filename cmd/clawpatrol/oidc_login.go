package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// Dashboard sign-in through an OpenID Connect provider (GitLab.com by
// default; see gateway.dashboard_oidc). The flow is the authorization
// code flow with PKCE: /__login/oidc redirects to the provider, which
// redirects back to /__login/oidc/callback. A sign-in only reaches a
// dashboard user an admin linked to the provider account.

const (
	oidcStartPath    = "/__login/oidc"
	oidcCallbackPath = "/__login/oidc/callback"
	// oidcStateCookie carries a sign-in in progress — state, nonce,
	// PKCE verifier and where to go after — signed with a key that
	// never leaves the gateway. Holding it in the browser binds the
	// callback to the browser that started the sign-in, and leaves no
	// server-side table a stranger could fill.
	oidcStateCookie = "cp_oidc_state"
	// auditKindOIDC marks sign-ins through the provider in the audit log.
	auditKindOIDC = "oidc"

	oidcPendingTTL      = 10 * time.Minute
	oidcDiscoveryTTL    = time.Hour
	oidcJWKSRefetchMin  = time.Minute
	oidcClockLeeway     = time.Minute
	oidcHTTPTimeout     = 10 * time.Second
	oidcResponseMaxSize = 1 << 20
	oidcRandomBytes     = 32
)

var oidcSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// oidcProvider is a provider's discovered configuration and keys.
type oidcProvider struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserinfoURL string `json:"userinfo_endpoint"`
	JWKSURL     string `json:"jwks_uri"`

	discoveredAt time.Time
	keys         jose.JSONWebKeySet
	keysAt       time.Time
}

// oidcPending is a sign-in in progress, carried in oidcStateCookie.
type oidcPending struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Expires  int64  `json:"e"`
}

// oidcState is the gateway-wide sign-in state, shared by every
// dashboard listener.
type oidcState struct {
	mu        sync.Mutex
	providers map[string]*oidcProvider
	// cookieKey signs oidcStateCookie. Random per process: a restart
	// only voids sign-ins in progress.
	cookieKey []byte
	// client is the HTTP client used to talk to the provider; tests
	// replace it.
	client *http.Client
}

func (g *Gateway) oidc() *oidcState {
	g.oidcOnce.Do(func() {
		if g.oidcState == nil {
			g.oidcState = &oidcState{client: &http.Client{Timeout: oidcHTTPTimeout}}
		}
		g.oidcState.providers = map[string]*oidcProvider{}
		g.oidcState.cookieKey = make([]byte, oidcRandomBytes)
		if _, err := rand.Read(g.oidcState.cookieKey); err != nil {
			panic("oidc: read random: " + err.Error())
		}
	})
	return g.oidcState
}

func (s *oidcState) sign(payload []byte) string {
	mac := hmac.New(sha256.New, s.cookieKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *oidcState) sealPending(p oidcPending) (string, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return s.sign(payload), nil
}

// openPending verifies and decodes a sign-in cookie; a forged,
// tampered or expired one is refused.
func (s *oidcState) openPending(cookie string) (oidcPending, bool) {
	var p oidcPending
	body, sig, ok := strings.Cut(cookie, ".")
	if !ok {
		return p, false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(body)
	got, err2 := base64.RawURLEncoding.DecodeString(sig)
	if err1 != nil || err2 != nil {
		return p, false
	}
	mac := hmac.New(sha256.New, s.cookieKey)
	mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return p, false
	}
	if json.Unmarshal(payload, &p) != nil || time.Now().Unix() > p.Expires {
		return p, false
	}
	return p, true
}

func (s *oidcState) getJSON(ctx context.Context, url, bearer string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, oidcResponseMaxSize)).Decode(dst)
}

// provider returns the issuer's configuration, discovering it at most
// once per oidcDiscoveryTTL. The document must name the configured
// issuer exactly — the ID token's iss is checked against it, and
// anything else would let tokens from another issuer in.
func (s *oidcState) provider(ctx context.Context, issuer string) (*oidcProvider, error) {
	s.mu.Lock()
	p := s.providers[issuer]
	s.mu.Unlock()
	if p != nil && time.Since(p.discoveredAt) < oidcDiscoveryTTL {
		return p, nil
	}
	var doc oidcProvider
	discovery := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	if err := s.getJSON(ctx, discovery, "", &doc); err != nil {
		return nil, fmt.Errorf("discover %s: %w", issuer, err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("discovery document names issuer %q; set dashboard_oidc.issuer to exactly that", doc.Issuer)
	}
	if doc.AuthURL == "" || doc.TokenURL == "" || doc.JWKSURL == "" {
		return nil, fmt.Errorf("discovery document of %s lacks endpoints", issuer)
	}
	doc.discoveredAt = time.Now()
	s.mu.Lock()
	s.providers[issuer] = &doc
	s.mu.Unlock()
	return &doc, nil
}

// signingKey finds the key a token names, refetching the key set (at
// most once per oidcJWKSRefetchMin) when the key is new.
func (s *oidcState) signingKey(ctx context.Context, p *oidcProvider, kid string) (*jose.JSONWebKey, error) {
	s.mu.Lock()
	keys, at := p.keys, p.keysAt
	s.mu.Unlock()
	if found := keys.Key(kid); len(found) > 0 {
		return &found[0], nil
	}
	if time.Since(at) < oidcJWKSRefetchMin {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	var fresh jose.JSONWebKeySet
	if err := s.getJSON(ctx, p.JWKSURL, "", &fresh); err != nil {
		return nil, fmt.Errorf("fetch signing keys: %w", err)
	}
	s.mu.Lock()
	p.keys, p.keysAt = fresh, time.Now()
	s.mu.Unlock()
	if found := fresh.Key(kid); len(found) > 0 {
		return &found[0], nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func oidcRandom() (string, error) {
	b := make([]byte, oidcRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (w *webMux) oidcOAuthConfig(b *config.DashboardOIDCBlock, p *oidcProvider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     b.ClientID,
		ClientSecret: resolveTemplate(b.ClientSecret),
		Endpoint:     oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL},
		RedirectURL:  strings.TrimRight(w.g.cfg.Load().PublicURL(), "/") + oidcCallbackPath,
		Scopes:       []string{"openid", "profile"},
	}
}

// apiOIDCStart begins a sign-in: GET /__login/oidc?next=...
func (w *webMux) apiOIDCStart(rw http.ResponseWriter, r *http.Request) {
	b := w.g.cfg.Load().DashboardOIDC()
	if b == nil {
		http.NotFound(rw, r)
		return
	}
	next := safeDashboardLoginNext(r.URL.Query().Get("next"))
	// The provider returns to public_url, so the sign-in cookie must be
	// set there: start over on that host when this one is another.
	if pu, err := url.Parse(w.g.cfg.Load().PublicURL()); err == nil && pu.Host != "" && !strings.EqualFold(pu.Host, r.Host) {
		http.Redirect(rw, r, strings.TrimRight(pu.String(), "/")+oidcStartPath+"?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	st := w.g.oidc()
	p, err := st.provider(r.Context(), b.IssuerOrDefault())
	if err != nil {
		log.Printf("dashboard oidc: %v", err)
		w.renderLogin(rw, next, "the sign-in provider is unreachable; try again or use a password", false, http.StatusBadGateway)
		return
	}
	state, err1 := oidcRandom()
	nonce, err2 := oidcRandom()
	if err1 != nil || err2 != nil {
		http.Error(rw, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	sealed, err := st.sealPending(oidcPending{State: state, Nonce: nonce, Verifier: verifier, Next: next,
		Expires: time.Now().Add(oidcPendingTTL).Unix()})
	if err != nil {
		http.Error(rw, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    sealed,
		Path:     oidcStartPath,
		HttpOnly: true,
		Secure:   strings.HasPrefix(w.g.cfg.Load().PublicURL(), "https://"),
		// Lax: the provider's redirect back is a top-level GET, which
		// carries Lax cookies.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcPendingTTL.Seconds()),
	})
	url := w.oidcOAuthConfig(b, p).AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(rw, r, url, http.StatusFound)
}

type oidcIDClaims struct {
	Nonce             string `json:"nonce"`
	PreferredUsername string `json:"preferred_username"`
	Nickname          string `json:"nickname"`
}

// apiOIDCCallback completes a sign-in: GET /__login/oidc/callback.
func (w *webMux) apiOIDCCallback(rw http.ResponseWriter, r *http.Request) {
	b := w.g.cfg.Load().DashboardOIDC()
	if b == nil {
		http.NotFound(rw, r)
		return
	}
	q := r.URL.Query()
	http.SetCookie(rw, &http.Cookie{Name: oidcStateCookie, Value: "", Path: oidcStartPath, HttpOnly: true, MaxAge: -1})
	st := w.g.oidc()
	var pending oidcPending
	var opened bool
	if c, err := r.Cookie(oidcStateCookie); err == nil {
		pending, opened = st.openPending(c.Value)
	}
	next := "/"
	if opened {
		next = pending.Next
	}
	fail := func(status int, msg, auditUser string) {
		w.recordAudit(r, auditUsername(auditUser), auditKindOIDC, "login oidc", status)
		w.renderLogin(rw, next, msg, false, status)
	}
	if e := q.Get("error"); e != "" {
		fail(http.StatusUnauthorized, "the sign-in provider refused or cancelled the sign-in", "")
		return
	}
	state := q.Get("state")
	if !opened || state == "" || subtle.ConstantTimeCompare([]byte(pending.State), []byte(state)) != 1 {
		fail(http.StatusBadRequest, "this sign-in was not started in this browser, or it expired; start again", "")
		return
	}
	issuer := b.IssuerOrDefault()
	p, err := st.provider(r.Context(), issuer)
	if err != nil {
		log.Printf("dashboard oidc: %v", err)
		fail(http.StatusBadGateway, "the sign-in provider is unreachable; try again", "")
		return
	}
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, st.client)
	tok, err := w.oidcOAuthConfig(b, p).Exchange(ctx, q.Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		log.Printf("dashboard oidc: code exchange: %v", err)
		fail(http.StatusUnauthorized, "the sign-in could not be completed; start again", "")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	subject, claims, err := w.verifyOIDCIDToken(ctx, st, p, b.ClientID, rawID, pending.Nonce)
	if err != nil {
		log.Printf("dashboard oidc: id token: %v", err)
		fail(http.StatusUnauthorized, "the sign-in could not be verified; start again", "")
		return
	}
	providerUser := claims.PreferredUsername
	if providerUser == "" {
		providerUser = claims.Nickname
	}
	if len(b.AllowedGroups) > 0 {
		member, err := w.oidcInAllowedGroups(ctx, st, p, tok.AccessToken, subject, b.AllowedGroups)
		if err != nil {
			log.Printf("dashboard oidc: groups: %v", err)
		}
		if !member {
			fail(http.StatusForbidden, "your account is not in a group allowed to use this dashboard", "@"+providerUser)
			return
		}
	}
	username, err := dashboardUserForOIDC(w.g.db, issuer+"|"+subject, providerUser)
	if errors.Is(err, errOIDCUnlinked) {
		fail(http.StatusForbidden, fmt.Sprintf("no dashboard user is linked to @%s; ask an admin to link it", providerUser), "@"+providerUser)
		return
	}
	if err != nil {
		http.Error(rw, "dashboard auth lookup failed", http.StatusServiceUnavailable)
		return
	}
	if err := w.mintAndSetSessionCookieWithMethod(rw, username, sessionMethodOIDC); err != nil {
		http.Error(rw, "could not mint session", http.StatusInternalServerError)
		return
	}
	w.recordAudit(r, username, auditKindOIDC, "login oidc", http.StatusFound)
	http.Redirect(rw, r, pending.Next, http.StatusFound)
}

// verifyOIDCIDToken checks an ID token's signature against the
// provider's keys, then its issuer, audience, expiry and nonce, and
// returns its subject.
func (w *webMux) verifyOIDCIDToken(ctx context.Context, st *oidcState, p *oidcProvider, clientID, raw, nonce string) (string, oidcIDClaims, error) {
	var claims oidcIDClaims
	if raw == "" {
		return "", claims, errors.New("token response has no id_token")
	}
	tok, err := jwt.ParseSigned(raw, oidcSignatureAlgorithms)
	if err != nil {
		return "", claims, err
	}
	if len(tok.Headers) != 1 {
		return "", claims, errors.New("id_token must carry exactly one signature")
	}
	key, err := st.signingKey(ctx, p, tok.Headers[0].KeyID)
	if err != nil {
		return "", claims, err
	}
	var std jwt.Claims
	if err := tok.Claims(key.Key, &std, &claims); err != nil {
		return "", claims, err
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		Issuer:      p.Issuer,
		AnyAudience: jwt.Audience{clientID},
		Time:        time.Now(),
	}, oidcClockLeeway); err != nil {
		return "", claims, err
	}
	if std.Expiry == nil {
		return "", claims, errors.New("id_token has no expiry")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return "", claims, errors.New("id_token nonce does not match this sign-in")
	}
	if std.Subject == "" {
		return "", claims, errors.New("id_token has no subject")
	}
	return std.Subject, claims, nil
}

// oidcInAllowedGroups reads the userinfo `groups` claim — GitLab lists
// every group the user belongs to, directly or through a parent — and
// reports whether one is an allowed group or inside one.
func (w *webMux) oidcInAllowedGroups(ctx context.Context, st *oidcState, p *oidcProvider, accessToken, subject string, allowed []string) (bool, error) {
	if p.UserinfoURL == "" {
		return false, errors.New("provider has no userinfo endpoint")
	}
	var info struct {
		Sub    string   `json:"sub"`
		Groups []string `json:"groups"`
	}
	if err := st.getJSON(ctx, p.UserinfoURL, accessToken, &info); err != nil {
		return false, err
	}
	if info.Sub != subject {
		return false, errors.New("userinfo subject differs from the id_token's")
	}
	for _, g := range info.Groups {
		for _, a := range allowed {
			a = strings.Trim(a, "/")
			if strings.EqualFold(g, a) || strings.HasPrefix(strings.ToLower(g), strings.ToLower(a)+"/") {
				return true, nil
			}
		}
	}
	return false, nil
}
