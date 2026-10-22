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

	"github.com/denoland/clawpatrol/internal/config"
)

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
	writeJSON(rw, map[string]any{
		"users":           users,
		"profiles":        declaredProfiles(policy),
		"human_approvers": declaredHumanApprovers(policy),
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
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, auditUsername(body.Username))
	if body.Role == "" {
		body.Role = dashboardRoleMember
	}
	if !validDashboardUsername(body.Username) {
		http.Error(rw, "username must match "+dashboardUsernameRe.String(), http.StatusBadRequest)
		return
	}
	if !validDashboardRole(body.Role) {
		http.Error(rw, "role must be admin or member", http.StatusBadRequest)
		return
	}
	if len(body.Password) < dashboardMinPasswordLen {
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
	if err := createDashboardUser(w.g.db, body.Username, body.Password, body.Role); err != nil {
		if errors.Is(err, errDashboardUserExists) {
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
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, auditUsername(body.Username))
	if body.Role == "" && body.Password == "" && body.Profiles == nil && body.Approver == nil {
		http.Error(rw, "nothing to update: set role, password, profiles and/or approver", http.StatusBadRequest)
		return
	}
	if err := validateUserAssignment(w.g.Policy(), body.Profiles, body.Approver); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if _, exists, err := lookupDashboardUserRole(w.g.db, body.Username); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	} else if !exists {
		http.Error(rw, errDashboardUserNotFound.Error(), http.StatusNotFound)
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
		if p, _ := principalFromContext(r.Context()); p.Owner == body.Username {
			http.Error(rw, "you cannot change your own role", http.StatusBadRequest)
			return
		}
	}
	if body.Password != "" && len(body.Password) < dashboardMinPasswordLen {
		http.Error(rw, "password must be at least "+strconv.Itoa(dashboardMinPasswordLen)+" characters", http.StatusBadRequest)
		return
	}
	// The password step runs first: it is the one that can still be
	// refused, and a refused request must not leave a role change behind.
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
