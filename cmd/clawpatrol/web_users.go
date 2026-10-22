package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
)

// normalizeOIDCLinks checks links (provider name → account) against
// the configured providers — an unlink ("") is accepted at any — and
// trims a leading "@" from accounts.
func (w *webMux) normalizeOIDCLinks(links map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(links))
	for provider, account := range links {
		account = strings.TrimPrefix(strings.TrimSpace(account), "@")
		// Unlinking works at any provider, so links left by a removed or
		// renamed dashboard_oidc block can be cleared.
		if account != "" && w.g.cfg.Load().DashboardOIDCProvider(provider) == nil {
			return nil, fmt.Errorf("no sign-in provider %q is configured (gateway.dashboard_oidc); a linked account could never sign in", provider)
		}
		if account != "" && !validOIDCAccount(account) {
			return nil, fmt.Errorf("%q is not a valid account name", account)
		}
		out[provider] = account
	}
	return out, nil
}

// humanApproverType is the approver plugin a user's "require approval"
// rules may route to.
const humanApproverType = "human_approver"

// auditUsernameMaxLen bounds attacker-chosen usernames from failed
// logins before they reach the audit table.
const auditUsernameMaxLen = 64

func auditUsername(username string) string {
	if r := []rune(username); len(r) > auditUsernameMaxLen {
		return string(r[:auditUsernameMaxLen])
	}
	return username
}

// principalRole is the role roleGate enforces. Principals from the
// database always carry a normalized role; one built in code without a
// role (a tailnet operator before roles existed) is an admin, and any
// other unrecognised role is a member.
func principalRole(p principal) dashboardRole {
	switch p.Role {
	case "":
		return dashboardRoleAdmin
	case dashboardRoleAdmin, dashboardRoleMember:
		return p.Role
	}
	return dashboardRoleMember
}

func (w *webMux) apiUsers(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	users, err := listDashboardUsers(w.g.db)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	policy := w.g.Policy()
	oidc := []map[string]string{}
	for _, b := range w.g.cfg.Load().DashboardOIDCProviders() {
		oidc = append(oidc, map[string]string{"name": b.Name, "display_name": b.ProviderName(), "label": b.Label()})
	}
	writeJSON(rw, map[string]any{
		"users":           users,
		"profiles":        declaredProfiles(policy),
		"human_approvers": declaredHumanApprovers(policy),
		"oidc":            oidc,
	})
}

func declaredProfiles(policy *config.CompiledPolicy) []string {
	out := []string{}
	if policy == nil {
		return out
	}
	for name := range policy.Profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func declaredHumanApprovers(policy *config.CompiledPolicy) []string {
	out := []string{}
	if policy == nil {
		return out
	}
	for name, ent := range policy.Approvers {
		if ent != nil && ent.Symbol != nil && ent.Symbol.Type == humanApproverType {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// validateUserAssignment checks profiles and approver against the
// running config.
func validateUserAssignment(policy *config.CompiledPolicy, profiles *[]string, approver *string) error {
	if profiles != nil {
		for _, p := range *profiles {
			if policy == nil || policy.Profiles[p] == nil {
				return fmt.Errorf("profile %q is not declared in the config", p)
			}
		}
	}
	if approver != nil && *approver != "" {
		ent := (*config.Entity)(nil)
		if policy != nil {
			ent = policy.Approvers[*approver]
		}
		if ent == nil || ent.Symbol == nil || ent.Symbol.Type != humanApproverType {
			return fmt.Errorf("%q is not a human_approver declared in the config", *approver)
		}
	}
	return nil
}

func (w *webMux) apiUsersCreate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string        `json:"username"`
		Password string        `json:"password"`
		Role     dashboardRole `json:"role"`
		// OIDC links provider names to accounts there.
		OIDC map[string]string `json:"oidc"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, auditUsername(body.Username))
	if body.Role == "" {
		body.Role = dashboardRoleMember
	}
	links, err := w.normalizeOIDCLinks(body.OIDC)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	linked := false
	for _, account := range links {
		linked = linked || account != ""
	}
	if !validDashboardUsername(body.Username) {
		http.Error(rw, "username must match "+dashboardUsernameRe.String(), http.StatusBadRequest)
		return
	}
	if !validDashboardRole(body.Role) {
		http.Error(rw, "role must be admin or member", http.StatusBadRequest)
		return
	}
	// A user linked to a sign-in account may have no password.
	if (body.Password != "" || !linked) && len(body.Password) < dashboardMinPasswordLen {
		http.Error(rw, "password must be at least "+strconv.Itoa(dashboardMinPasswordLen)+" characters", http.StatusBadRequest)
		return
	}
	// A leftover rules file under this name would hand its rules to the
	// new account.
	if path := w.memberRulesPath(body.Username); path != "" {
		if _, err := os.Stat(path); err == nil {
			http.Error(rw, "a rules file for this username already exists ("+filepath.Base(path)+"); rename or remove it first", http.StatusConflict)
			return
		}
	}
	if err := createLinkedDashboardUser(w.g.db, body.Username, body.Password, body.Role, links); err != nil {
		if errors.Is(err, errDashboardUserExists) || errors.Is(err, errOIDCUsernameTaken) {
			http.Error(rw, err.Error(), http.StatusConflict)
			return
		}
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("dashboard auth: user %q created with role %s", body.Username, body.Role)
	writeJSONError(rw, http.StatusCreated, map[string]any{"ok": true})
}

// apiUsersUpdate changes a user's role and/or resets a member's
// password. Root stays an admin, and nobody changes their own role:
// together these keep at least one admin able to log in. An admin's
// password is never reset here, so one admin cannot take over another
// admin's (or root's) account and act under their name.
func (w *webMux) apiUsersUpdate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string        `json:"username"`
		Role     dashboardRole `json:"role"`
		Password string        `json:"password"`
		Profiles *[]string     `json:"profiles"`
		Approver *string       `json:"approver"`
		// OIDC sets the account linked at each named provider; ""
		// unlinks. Providers left out are unchanged.
		OIDC map[string]string `json:"oidc"`
		// OIDCRebind lists providers whose link keeps its account but
		// drops its bound subject: the next sign-in binds afresh.
		OIDCRebind []string `json:"oidc_rebind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, auditUsername(body.Username))
	if body.Role == "" && body.Password == "" && body.Profiles == nil && body.Approver == nil && body.OIDC == nil && len(body.OIDCRebind) == 0 {
		http.Error(rw, "nothing to update: set role, password, profiles, approver, oidc and/or oidc_rebind", http.StatusBadRequest)
		return
	}
	caller, _ := principalFromContext(r.Context())
	targetRole, exists, err := lookupDashboardUserRole(w.g.db, body.Username)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(rw, errDashboardUserNotFound.Error(), http.StatusNotFound)
		return
	}
	links, err := w.normalizeOIDCLinks(body.OIDC)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if len(links) > 0 || len(body.OIDCRebind) > 0 {
		// Linking an account decides who may sign in as the user: one
		// admin must not be able to take over another's (or root's).
		if targetRole == dashboardRoleAdmin && caller.Owner != body.Username {
			http.Error(rw, "an admin's sign-in accounts can only be linked by that admin", http.StatusForbidden)
			return
		}
		for provider, account := range links {
			if taken, err := oidcAccountTaken(w.g.db, provider, account, body.Username); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			} else if taken {
				http.Error(rw, errOIDCUsernameTaken.Error(), http.StatusConflict)
				return
			}
		}
		// Never leave a user with no way to sign in.
		current, err := listDashboardUserOIDC(w.g.db, body.Username)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		hasPassword, err := dashboardUserHasPassword(w.g.db, body.Username)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		final := map[string]string{}
		for _, l := range current {
			final[l.Provider] = l.Account
		}
		for provider, account := range links {
			final[provider] = account
		}
		signIn := hasPassword || body.Password != ""
		for provider, account := range final {
			signIn = signIn || (account != "" && w.g.cfg.Load().DashboardOIDCProvider(provider) != nil)
		}
		if !signIn {
			http.Error(rw, "this would leave the user no way to sign in: keep a link at a configured provider, or set a password", http.StatusBadRequest)
			return
		}
	}
	if err := validateUserAssignment(w.g.Policy(), body.Profiles, body.Approver); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Role != "" {
		if !validDashboardRole(body.Role) {
			http.Error(rw, "role must be admin or member", http.StatusBadRequest)
			return
		}
		if body.Username == dashboardRootUsername {
			http.Error(rw, "root is always an admin", http.StatusBadRequest)
			return
		}
		if caller.Owner == body.Username {
			http.Error(rw, "you cannot change your own role", http.StatusBadRequest)
			return
		}
	}
	if body.Password != "" && len(body.Password) < dashboardMinPasswordLen {
		http.Error(rw, "password must be at least "+strconv.Itoa(dashboardMinPasswordLen)+" characters", http.StatusBadRequest)
		return
	}
	// The steps that can still be refused run first — the password
	// reset, then the links in one transaction — so a refused request
	// leaves no role or profile change behind.
	if body.Password != "" {
		switch err := setDashboardMemberPassword(w.g.db, body.Username, body.Password); {
		case errors.Is(err, errDashboardUserNotFound):
			http.Error(rw, err.Error(), http.StatusNotFound)
			return
		case errors.Is(err, errDashboardUserNotMember):
			http.Error(rw, "an admin's password can only be changed by that admin, on the Account page (root also with `clawpatrol gateway --set-dashboard-password`)", http.StatusForbidden)
			return
		case err != nil:
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("dashboard auth: user %q password reset by an admin", body.Username)
	}
	relinked, err := setDashboardUserOIDCLinks(w.g.db, body.Username, links, body.OIDCRebind)
	switch {
	case errors.Is(err, errOIDCUsernameTaken):
		http.Error(rw, err.Error(), http.StatusConflict)
		return
	case err != nil:
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if relinked {
		log.Printf("dashboard auth: user %q sign-in links changed: %v, rebind %v", body.Username, links, body.OIDCRebind)
		// Relinking ends the user's sessions; one changing their own
		// links stays signed in.
		if caller.Owner == body.Username && caller.Kind == principalDashboardPassword {
			method := caller.Method
			if method == "" {
				method = sessionMethodPassword
			}
			if err := w.mintAndSetSessionCookieWithMethod(rw, caller.Owner, method); err != nil {
				http.Error(rw, "linked, but could not mint a new session; log in again", http.StatusInternalServerError)
				return
			}
		}
	}
	if body.Role != "" {
		if err := setDashboardUserRole(w.g.db, body.Username, body.Role); errors.Is(err, errDashboardUserNotFound) {
			http.Error(rw, err.Error(), http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("dashboard auth: user %q role set to %s", body.Username, body.Role)
	}
	if body.Profiles != nil {
		if err := setDashboardUserProfiles(w.g.db, body.Username, *body.Profiles); errors.Is(err, errDashboardUserNotFound) {
			http.Error(rw, err.Error(), http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if body.Approver != nil {
		if err := setDashboardUserApprover(w.g.db, body.Username, *body.Approver); errors.Is(err, errDashboardUserNotFound) {
			http.Error(rw, err.Error(), http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.bustStateCache()
	writeJSON(rw, map[string]any{"ok": true})
}

func (w *webMux) apiUsersDelete(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, auditUsername(body.Username))
	if body.Username == dashboardRootUsername {
		http.Error(rw, "root cannot be deleted; use `clawpatrol gateway --reset-dashboard-password`", http.StatusBadRequest)
		return
	}
	if p, _ := principalFromContext(r.Context()); p.Owner == body.Username {
		http.Error(rw, "you cannot delete yourself", http.StatusBadRequest)
		return
	}
	if _, exists, err := lookupDashboardUserRole(w.g.db, body.Username); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	} else if !exists {
		http.Error(rw, errDashboardUserNotFound.Error(), http.StatusNotFound)
		return
	}
	if err := w.archiveMemberRules(body.Username); err != nil {
		http.Error(rw, "could not set the user's rules aside: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := deleteDashboardUser(w.g.db, body.Username); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("dashboard auth: user %q deleted", body.Username)
	w.bustStateCache()
	writeJSON(rw, map[string]any{"ok": true})
}

func (w *webMux) apiMe(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	p, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(rw, "no authenticated principal", http.StatusUnauthorized)
		return
	}
	out := map[string]any{
		"username":  p.Owner,
		"role":      principalRole(p),
		"auth_kind": p.Kind,
		"profiles":  []string{},
		"approver":  "",
	}
	if p.Kind == principalDashboardPassword {
		profiles, err := listDashboardUserProfiles(w.g.db, p.Owner)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		approver, err := lookupDashboardUserApprover(w.g.db, p.Owner)
		if err != nil && !errors.Is(err, errDashboardUserNotFound) {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		out["profiles"], out["approver"] = profiles, approver
	}
	writeJSON(rw, out)
}

// apiMePassword lets a password user rotate their own password. The
// rotation revokes every session of the user, so the caller's session
// is re-minted to keep them logged in.
func (w *webMux) apiMePassword(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := principalFromContext(r.Context())
	if !ok || p.Kind != principalDashboardPassword {
		http.Error(rw, "only password sessions have a password to change", http.StatusBadRequest)
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, p.Owner)
	if hash, _, err := lookupDashboardUser(w.g.db, p.Owner); err == nil && hash == "" {
		http.Error(rw, "this account signs in through its linked account and has no password", http.StatusBadRequest)
		return
	}
	limits := w.g.loginLimits()
	buckets := loginBuckets(p.Owner, true, r.RemoteAddr)
	if wait := limits.blocked(buckets); wait > 0 {
		rw.Header().Set("Retry-After", strconv.Itoa(loginRetryAfterSeconds(wait)))
		http.Error(rw, "too many failed password checks — try again later", http.StatusTooManyRequests)
		return
	}
	ok, _, err := checkDashboardPassword(w.g.db, p.Owner, body.Current)
	if err != nil {
		http.Error(rw, "dashboard auth check failed", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		limits.recordFailure(buckets)
		http.Error(rw, "current password is wrong", http.StatusForbidden)
		return
	}
	limits.recordSuccess(p.Owner)
	if len(body.New) < dashboardMinPasswordLen {
		http.Error(rw, "password must be at least "+strconv.Itoa(dashboardMinPasswordLen)+" characters", http.StatusBadRequest)
		return
	}
	if err := setDashboardUser(w.g.db, p.Owner, body.New); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := w.mintAndSetSessionCookie(rw, p.Owner); err != nil {
		http.Error(rw, "password changed, but could not mint a new session; log in again", http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

func (w *webMux) apiAudit(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	records, err := listDashboardAudit(w.g.db, before, limit)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"records": records})
}
