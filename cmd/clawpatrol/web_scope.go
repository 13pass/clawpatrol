package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

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
// profile using it is theirs and nothing outside profiles — an
// approver's Slack or model credential — depends on it: rotating a
// credential something else uses would change other teams' access.
func (v viewer) managesCredential(policy *config.CompiledPolicy, name string) bool {
	if v.admin {
		return true
	}
	if policy == nil || policy.Credentials[name] == nil || credentialUsedByApprover(policy, name) {
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

func credentialUsedByApprover(policy *config.CompiledPolicy, name string) bool {
	for _, ent := range policy.Approvers {
		if ent == nil {
			continue
		}
		for _, sym := range ent.Refs.All() {
			if sym != nil && sym.Kind == config.KindCredential && sym.Name == name {
				return true
			}
		}
	}
	return false
}

// Bounds on request bodies a guard reads before its handler.
const (
	credentialRequestMaxBytes = 1 << 20
	// onboardApproveMaxBytes matches decodeOnboardApproveBody's limit.
	onboardApproveMaxBytes = 4 << 10
)

// readAndRestoreBody reads the request body in full (at most max
// bytes) and puts it back for the handler.
func readAndRestoreBody(rw http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, max))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// requestValues collects every value a handler could read for field:
// the query parameter, and the body's field parsed both strictly
// (json.Unmarshal) and as a json.Decoder does (first value only,
// trailing data ignored), with Go's case-insensitive key matching. A
// guard requires the member to be entitled to all of them, so a
// request that a guard and its handler would read differently fails
// closed instead of authorizing one value and acting on another.
func requestValues(r *http.Request, body []byte, field string) []string {
	set := map[string]bool{}
	add := func(m map[string]any) {
		for k, v := range m {
			if s, ok := v.(string); ok && s != "" && strings.EqualFold(k, field) {
				set[s] = true
			}
		}
	}
	if v := r.URL.Query().Get(field); v != "" {
		set[v] = true
	}
	var strict map[string]any
	if json.Unmarshal(body, &strict) == nil {
		add(strict)
	}
	var lenient map[string]any
	if json.NewDecoder(bytes.NewReader(body)).Decode(&lenient) == nil {
		add(lenient)
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func principalOwner(r *http.Request) string {
	p, _ := principalFromContext(r.Context())
	return p.Owner
}

// credentialField is where a guarded route names its credential: an
// "id", or the "state" of an OAuth flow already started.
type credentialField string

const (
	credentialByID    credentialField = "id"
	credentialByState credentialField = "state"
)

// guardCredential lets a member through only when every credential the
// request could name is one they manage (viewer.managesCredential), and
// every OAuth flow it could name is one they started. Admins pass
// unchecked.
func (w *webMux) guardCredential(field credentialField, next http.HandlerFunc) http.HandlerFunc {
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
		body, err := readAndRestoreBody(rw, r, credentialRequestMaxBytes)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		values := requestValues(r, body, string(field))
		ids, owners, known := values, []string(nil), true
		if field == credentialByState {
			ids, owners, known = w.oauthSessionsFor(values)
		}
		setAuditTarget(r, strings.Join(ids, ","))
		policy := w.g.Policy()
		allowed := len(ids) > 0 && known
		for _, id := range ids {
			allowed = allowed && v.managesCredential(policy, id)
		}
		if !allowed {
			http.Error(rw, "only an admin can change this credential: it is not used by your profiles alone", http.StatusForbidden)
			return
		}
		for _, owner := range owners {
			if owner != v.username {
				http.Error(rw, "this sign-in was started by someone else", http.StatusForbidden)
				return
			}
		}
		next(rw, r)
	}
}

// oauthSessionsFor maps OAuth states to their credentials and owners;
// known is false if any state names no session.
func (w *webMux) oauthSessionsFor(states []string) (ids, owners []string, known bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	known = true
	for _, state := range states {
		sess := w.sessions[state]
		if sess == nil {
			known = false
			continue
		}
		ids = append(ids, sess.id)
		owners = append(owners, sess.owner)
	}
	return ids, owners, known
}

// guardDevice lets a member act only on a device of a profile they
// own, and move it only into another profile they own.
func (w *webMux) guardDevice(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		v, err := w.viewerFor(r)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		if !v.admin {
			ip := r.URL.Query().Get("ip")
			current := w.onboard.ProfileForIP(ip)
			if !v.ownsProfile(current) {
				http.Error(rw, "not found", http.StatusNotFound)
				return
			}
			if target := r.URL.Query().Get("profile"); target != "" && !v.ownsProfile(target) {
				http.Error(rw, "you can only move a device into a profile you own", http.StatusForbidden)
				return
			}
			setAuditTarget(r, ip)
		}
		next(rw, r)
	}
}

// guardOnboardApprove lets a member approve a joining device only into
// a profile they own, named explicitly, and only when the device asked
// for that profile (`clawpatrol join --profile X`): a member must not
// claim another team's pending enrollment by knowing its code.
func (w *webMux) guardOnboardApprove(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || principalRole(p) == dashboardRoleAdmin {
			next(rw, r)
			return
		}
		v, err := w.viewerFor(r)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		body, err := readAndRestoreBody(rw, r, onboardApproveMaxBytes)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		profiles := requestValues(r, body, "profile")
		if len(profiles) != 1 || !v.ownsProfile(profiles[0]) {
			http.Error(rw, "choose one of your profiles for this device", http.StatusForbidden)
			return
		}
		for _, code := range requestValues(r, body, "code") {
			s := w.onboard.byUserCode(code)
			if s == nil {
				continue
			}
			w.onboard.mu.Lock()
			asked := s.profile
			w.onboard.mu.Unlock()
			if asked != profiles[0] {
				http.Error(rw, fmt.Sprintf("this device did not ask to join %q; it must join with `clawpatrol join --profile %s`", profiles[0], profiles[0]), http.StatusForbidden)
				return
			}
		}
		next(rw, r)
	}
}
