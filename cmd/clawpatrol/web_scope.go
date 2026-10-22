package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
)

// What a member may see and change, derived from the profiles they
// own (see doc/multi-user-dashboard.md, phase 4). An admin's viewer
// passes every check.

func (v viewer) ownsProfile(profile string) bool {
	return v.admin || (profile != "" && v.profiles[profile])
}

// visibleCredentials is the set of credentials the viewer's profiles
// use; nil means every credential (an admin).
func (v viewer) visibleCredentials(policy *config.CompiledPolicy) map[string]bool {
	if v.admin {
		return nil
	}
	out := map[string]bool{}
	for p := range v.profiles {
		for name := range credentialsInProfile(policy, p) {
			out[name] = true
		}
	}
	return out
}

// managesCredential reports whether the viewer may set, connect,
// refresh or clear a credential's secret. A member may only when every
// profile using it is theirs: rotating a credential another team
// shares would change that team's access.
func (v viewer) managesCredential(policy *config.CompiledPolicy, name string) bool {
	if v.admin {
		return true
	}
	if policy == nil || policy.Credentials[name] == nil {
		return false
	}
	profiles, _ := credentialBindings(policy, name)
	if len(profiles) == 0 {
		return false
	}
	for _, p := range profiles {
		if !v.profiles[p] {
			return false
		}
	}
	return true
}

// credentialRequestMaxBytes bounds a credential request body, read in
// full by guardCredential before the handler decodes it again.
const credentialRequestMaxBytes = 1 << 20

func principalOwner(r *http.Request) string {
	p, _ := principalFromContext(r.Context())
	return p.Owner
}

// credentialTarget names the credential a request acts on and, for an
// OAuth flow already started, the user who started it.
type credentialTarget func(w *webMux, r *http.Request, body []byte) (id, owner string)

func credentialFromBodyOrQuery(_ *webMux, r *http.Request, body []byte) (string, string) {
	var b struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &b)
	if b.ID == "" {
		b.ID = r.URL.Query().Get("id")
	}
	return b.ID, ""
}

func credentialFromOAuthSession(w *webMux, r *http.Request, body []byte) (string, string) {
	var b struct {
		State string `json:"state"`
	}
	_ = json.Unmarshal(body, &b)
	if b.State == "" {
		b.State = r.URL.Query().Get("state")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if sess := w.sessions[b.State]; sess != nil {
		return sess.id, sess.owner
	}
	return "", ""
}

// guardCredential lets a member through only to a credential they
// manage (viewer.managesCredential), and only into an OAuth flow they
// started. Admins pass unchecked.
func (w *webMux) guardCredential(target credentialTarget, next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		v, err := w.viewerFor(r)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		if v.admin {
			next(rw, r)
			return
		}
		var body []byte
		if r.Body != nil {
			if body, err = io.ReadAll(http.MaxBytesReader(rw, r.Body, credentialRequestMaxBytes)); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		id, owner := target(w, r, body)
		if !v.managesCredential(w.g.Policy(), id) {
			http.Error(rw, "only an admin can change this credential: it is not used by your profiles alone", http.StatusForbidden)
			return
		}
		if owner != "" && owner != v.username {
			http.Error(rw, "this sign-in was started by someone else", http.StatusForbidden)
			return
		}
		setAuditTarget(r, id)
		next(rw, r)
	}
}
