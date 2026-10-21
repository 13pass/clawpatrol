package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
)

// auditUsernameMaxLen bounds attacker-chosen usernames from failed
// logins before they reach the audit table.
const auditUsernameMaxLen = 64

func auditUsername(username string) string {
	if r := []rune(username); len(r) > auditUsernameMaxLen {
		return string(r[:auditUsernameMaxLen])
	}
	return username
}

// principalRole treats a principal without a role (tailnet operators,
// principals built before roles existed) as an admin, matching
// roleGate.
func principalRole(p principal) dashboardRole {
	if p.Role == "" {
		return dashboardRoleAdmin
	}
	return p.Role
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
	writeJSON(rw, map[string]any{"users": users})
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

// apiUsersUpdate changes a user's role and/or resets their password.
// Root stays an admin, and nobody changes their own role: together
// these keep at least one admin able to log in.
func (w *webMux) apiUsersUpdate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string        `json:"username"`
		Role     dashboardRole `json:"role"`
		Password string        `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, auditUsername(body.Username))
	if body.Role == "" && body.Password == "" {
		http.Error(rw, "nothing to update: set role and/or password", http.StatusBadRequest)
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
	if body.Role != "" {
		if err := setDashboardUserRole(w.g.db, body.Username, body.Role); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("dashboard auth: user %q role set to %s", body.Username, body.Role)
	}
	if body.Password != "" {
		if err := setDashboardUser(w.g.db, body.Username, body.Password); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("dashboard auth: user %q password reset by an admin", body.Username)
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
	writeJSON(rw, map[string]any{
		"username":  p.Owner,
		"role":      principalRole(p),
		"auth_kind": p.Kind,
	})
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
	ok, _, err := checkDashboardPassword(w.g.db, p.Owner, body.Current)
	if err != nil {
		http.Error(rw, "dashboard auth check failed", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		http.Error(rw, "current password is wrong", http.StatusForbidden)
		return
	}
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
