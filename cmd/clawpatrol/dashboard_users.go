package main

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// dashboardUsersBcryptCost is the bcrypt cost used for stored passwords.
// 12 is the current OWASP default — about ~250 ms on a 2024 laptop.
const dashboardUsersBcryptCost = 12

// dashboardRootUsername is the username of the bootstrap operator row.
// Its existence is the first-run condition, so it can be neither
// deleted from the dashboard nor demoted.
const dashboardRootUsername = "root"

type dashboardRole string

const (
	dashboardRoleAdmin  dashboardRole = "admin"
	dashboardRoleMember dashboardRole = "member"
)

func validDashboardRole(role dashboardRole) bool {
	return role == dashboardRoleAdmin || role == dashboardRoleMember
}

// normalizeDashboardRole maps a stored role to one the gate knows,
// failing closed: root is always an admin, and anything unrecognised
// (a role written by another version, a hand-edited row) is a member.
func normalizeDashboardRole(username, stored string) dashboardRole {
	if username == dashboardRootUsername {
		return dashboardRoleAdmin
	}
	if role := dashboardRole(stored); validDashboardRole(role) {
		return role
	}
	return dashboardRoleMember
}

// dashboardUsernameRe keeps usernames usable as the `<user>-` prefix of
// HCL block names a user's config file declares.
var dashboardUsernameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

func validDashboardUsername(username string) bool {
	return dashboardUsernameRe.MatchString(username)
}

var (
	errDashboardUserExists    = errors.New("dashboard user already exists")
	errDashboardUserNotFound  = errors.New("dashboard user not found")
	errDashboardUserNotMember = errors.New("dashboard user is not a member")
)

type dashboardUser struct {
	Username string        `json:"username"`
	Role     dashboardRole `json:"role"`
	Profiles []string      `json:"profiles"`
	Approver string        `json:"approver"`
	// OIDC lists the provider accounts an admin linked.
	OIDC        []oidcLink `json:"oidc"`
	HasPassword bool       `json:"has_password"`
	CreatedNs   int64      `json:"created_ns"`
	UpdatedNs   int64      `json:"updated_ns"`
}

// lookupDashboardUser returns the stored bcrypt hash for the given
// username. The bool is false when no row exists; the caller is
// expected to treat that as "no auth configured yet" and trigger the
// first-run flow.
func lookupDashboardUser(db *sql.DB, username string) (string, bool, error) {
	if db == nil {
		return "", false, fmt.Errorf("no db")
	}
	var hash string
	err := db.QueryRow(
		`SELECT password_hash FROM dashboard_users WHERE username = ?`,
		username,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// setDashboardUser upserts the row for username with a bcrypt hash of
// password. Used by the first-run web flow and the
// --set-dashboard-password CLI flag.
func setDashboardUser(db *sql.DB, username, password string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), dashboardUsersBcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	newRowRole := dashboardRoleMember
	if username == dashboardRootUsername {
		newRowRole = dashboardRoleAdmin
	}
	now := time.Now().UnixNano()
	_, err = db.Exec(
		`INSERT INTO dashboard_users (username, password_hash, role, created_ns, updated_ns)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   password_hash = excluded.password_hash,
		   updated_ns    = excluded.updated_ns`,
		username, string(hash), string(newRowRole), now, now,
	)
	if err != nil {
		return err
	}
	// Rotating the password invalidates every session minted under
	// the old one. Belt-and-suspenders alongside the natural TTL —
	// otherwise an operator who suspects credential leak would have
	// to wait out dashboard_session_ttl after `--set-dashboard-
	// password` before old cookies stopped working.
	return revokeAllDashboardSessionsFor(db, username)
}

// deleteDashboardUser removes the row for username. Used by
// --reset-dashboard-password. Also wipes the user's sessions so the
// reset is immediate. No-op if the row doesn't exist.
func deleteDashboardUser(db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	if _, err := db.Exec(`DELETE FROM dashboard_users WHERE username = ?`, username); err != nil {
		return err
	}
	if _, err := db.Exec(`DELETE FROM dashboard_user_profiles WHERE username = ?`, username); err != nil {
		return err
	}
	if _, err := db.Exec(`DELETE FROM dashboard_user_oidc WHERE username = ?`, username); err != nil {
		return err
	}
	return revokeAllDashboardSessionsFor(db, username)
}

// checkDashboardPassword constant-time compares password against the
// stored hash for username. Returns (ok, exists, err) — exists=false
// means there is no row at all (caller should trigger first-run).
func checkDashboardPassword(db *sql.DB, username, password string) (bool, bool, error) {
	hash, ok, err := lookupDashboardUser(db, username)
	if err != nil || !ok {
		return false, ok, err
	}
	if hash == "" {
		// No password: the account signs in through its provider only.
		burnPasswordCheck(password)
		return false, true, nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, true, nil
		}
		return false, true, err
	}
	return true, true, nil
}

// createDashboardUser inserts a new operator account. Unlike
// setDashboardUser it never overwrites an existing row.
func createDashboardUser(db *sql.DB, username, password string, role dashboardRole) error {
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	return createLinkedDashboardUser(db, username, password, role, nil)
}

// createLinkedDashboardUser inserts a new account linked to provider
// accounts (links: provider name → account). password may be empty
// when there is a link: the account then signs in only through a
// provider.
func createLinkedDashboardUser(db *sql.DB, username, password string, role dashboardRole, links map[string]string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	linked := false
	for provider, account := range links {
		if account == "" {
			continue
		}
		linked = true
		if taken, err := oidcAccountTaken(db, provider, account, username); err != nil {
			return err
		} else if taken {
			return errOIDCUsernameTaken
		}
	}
	if password == "" && !linked {
		return fmt.Errorf("a user needs a password or a linked sign-in account")
	}
	hash := ""
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), dashboardUsersBcryptCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		hash = string(h)
	}
	now := time.Now().UnixNano()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(
		`INSERT INTO dashboard_users (username, password_hash, role, created_ns, updated_ns)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(username) DO NOTHING`,
		username, hash, string(role), now, now,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errDashboardUserExists
	}
	for provider, account := range links {
		if account == "" {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO dashboard_user_oidc (provider, username, account) VALUES (?, ?, ?)`,
			provider, username, account,
		); isUniqueViolation(err) {
			return errOIDCUsernameTaken
		} else if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// lookupDashboardUserRole returns the role of username. Root is always
// an admin, whatever its row says.
func lookupDashboardUserRole(db *sql.DB, username string) (dashboardRole, bool, error) {
	if db == nil {
		return "", false, fmt.Errorf("no db")
	}
	var role string
	err := db.QueryRow(
		`SELECT role FROM dashboard_users WHERE username = ?`,
		username,
	).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return normalizeDashboardRole(username, role), true, nil
}

// setDashboardMemberPassword resets a member's password and ends their
// sessions. It never creates a row, so a reset racing a delete cannot
// bring the account back, and it never touches an admin: an admin's
// password changes only through that admin (/api/me/password) or, for
// root, the --set-dashboard-password flag.
func setDashboardMemberPassword(db *sql.DB, username, password string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), dashboardUsersBcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	res, err := db.Exec(
		`UPDATE dashboard_users SET password_hash = ?, updated_ns = ?
		 WHERE username = ? AND role = ? AND username != ?`,
		string(hash), time.Now().UnixNano(), username, string(dashboardRoleMember), dashboardRootUsername,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		if _, exists, err := lookupDashboardUserRole(db, username); err != nil {
			return err
		} else if !exists {
			return errDashboardUserNotFound
		}
		return errDashboardUserNotMember
	}
	return revokeAllDashboardSessionsFor(db, username)
}

func setDashboardUserRole(db *sql.DB, username string, role dashboardRole) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	res, err := db.Exec(
		`UPDATE dashboard_users SET role = ?, updated_ns = ? WHERE username = ?`,
		string(role), time.Now().UnixNano(), username,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errDashboardUserNotFound
	}
	return nil
}

func listDashboardUsers(db *sql.DB) ([]dashboardUser, error) {
	if db == nil {
		return nil, fmt.Errorf("no db")
	}
	rows, err := db.Query(
		`SELECT username, role, approver, password_hash != '', created_ns, updated_ns
		 FROM dashboard_users ORDER BY username`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardUser{}
	for rows.Next() {
		var u dashboardUser
		var role string
		if err := rows.Scan(&u.Username, &role, &u.Approver, &u.HasPassword, &u.CreatedNs, &u.UpdatedNs); err != nil {
			return nil, err
		}
		u.Role = normalizeDashboardRole(u.Username, role)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	profiles, err := allDashboardUserProfiles(db)
	if err != nil {
		return nil, err
	}
	links, err := allDashboardUserOIDC(db)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Profiles = append([]string{}, profiles[out[i].Username]...)
		out[i].OIDC = append([]oidcLink{}, links[out[i].Username]...)
	}
	return out, nil
}

// allDashboardUserProfiles returns every user's profiles, sorted.
func allDashboardUserProfiles(db *sql.DB) (map[string][]string, error) {
	rows, err := db.Query(`SELECT username, profile FROM dashboard_user_profiles ORDER BY username, profile`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var u, p string
		if err := rows.Scan(&u, &p); err != nil {
			return nil, err
		}
		out[u] = append(out[u], p)
	}
	return out, rows.Err()
}

// listDashboardUserProfiles returns the profiles username owns, sorted.
func listDashboardUserProfiles(db *sql.DB, username string) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("no db")
	}
	rows, err := db.Query(
		`SELECT profile FROM dashboard_user_profiles WHERE username = ? ORDER BY profile`,
		username,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// setDashboardUserProfiles replaces the profiles username owns.
func setDashboardUserProfiles(db *sql.DB, username string, profiles []string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM dashboard_users WHERE username = ?`, username).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return errDashboardUserNotFound
	}
	if _, err := tx.Exec(`DELETE FROM dashboard_user_profiles WHERE username = ?`, username); err != nil {
		return err
	}
	for _, p := range profiles {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO dashboard_user_profiles (username, profile) VALUES (?, ?)`,
			username, p,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// setDashboardUserApprover sets the approver username's "require
// approval" rules route to; "" means the dashboard only.
func setDashboardUserApprover(db *sql.DB, username, approver string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	res, err := db.Exec(
		`UPDATE dashboard_users SET approver = ?, updated_ns = ? WHERE username = ?`,
		approver, time.Now().UnixNano(), username,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errDashboardUserNotFound
	}
	return nil
}

// lookupDashboardUserApprover returns the approver set for username.
func lookupDashboardUserApprover(db *sql.DB, username string) (string, error) {
	if db == nil {
		return "", fmt.Errorf("no db")
	}
	var approver string
	err := db.QueryRow(`SELECT approver FROM dashboard_users WHERE username = ?`, username).Scan(&approver)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errDashboardUserNotFound
	}
	return approver, err
}

var (
	timingDummyHashOnce sync.Once
	timingDummyHash     []byte
)

// burnPasswordCheck spends the same bcrypt work as a real password
// check, so a login for an unknown username can't be told apart from
// a wrong password by its response time.
func burnPasswordCheck(password string) {
	timingDummyHashOnce.Do(func() {
		timingDummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), dashboardUsersBcryptCost)
	})
	_ = bcrypt.CompareHashAndPassword(timingDummyHash, []byte(password))
}

var (
	// oidcAccountRe accepts provider account names: GitLab usernames,
	// and email-shaped names (Entra ID UPNs, Google emails).
	oidcAccountRe = regexp.MustCompile(`^[A-Za-z0-9_.@+'-]{1,254}$`)

	errOIDCUsernameTaken = errors.New("another dashboard user is already linked to that account")
	errOIDCUnlinked      = errors.New("no dashboard user is linked to that account")
)

func validOIDCAccount(name string) bool {
	return oidcAccountRe.MatchString(name)
}

// oidcLink is one provider account linked to a dashboard user; Linked
// is whether its first sign-in has bound the permanent subject.
type oidcLink struct {
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Linked   bool   `json:"linked"`
}

// allDashboardUserOIDC returns every user's provider links.
func allDashboardUserOIDC(db *sql.DB) (map[string][]oidcLink, error) {
	rows, err := db.Query(`SELECT username, provider, account, subject != '' FROM dashboard_user_oidc ORDER BY username, provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]oidcLink{}
	for rows.Next() {
		var u string
		var l oidcLink
		if err := rows.Scan(&u, &l.Provider, &l.Account, &l.Linked); err != nil {
			return nil, err
		}
		out[u] = append(out[u], l)
	}
	return out, rows.Err()
}

func listDashboardUserOIDC(db *sql.DB, username string) ([]oidcLink, error) {
	all, err := allDashboardUserOIDC(db)
	return append([]oidcLink{}, all[username]...), err
}

// oidcAccountTaken reports whether a user other than except is linked
// to the account at provider.
func oidcAccountTaken(db *sql.DB, provider, account, except string) (bool, error) {
	if account == "" {
		return false, nil
	}
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM dashboard_user_oidc WHERE provider = ? AND lower(account) = lower(?) AND username != ?`,
		provider, account, except,
	).Scan(&n)
	return n > 0, err
}

// isUniqueViolation reports a SQLite UNIQUE constraint failure.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// setDashboardUserOIDC links username to an account at one provider
// ("" unlinks); see setDashboardUserOIDCLinks.
func setDashboardUserOIDC(db *sql.DB, username, provider, account string) (bool, error) {
	return setDashboardUserOIDCLinks(db, username, map[string]string{provider: account}, nil)
}

// setDashboardUserOIDCLinks applies link changes (provider → account,
// "" unlinks) and rebinds (a link keeps its account but its bound
// subject is dropped, so the next sign-in binds afresh), all in one
// transaction, and reports whether anything changed. A change ends
// the user's sessions, since a different provider account may now
// sign in as them. Accounts compare case-insensitively.
func setDashboardUserOIDCLinks(db *sql.DB, username string, links map[string]string, rebind []string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("no db")
	}
	if _, exists, err := lookupDashboardUserRole(db, username); err != nil {
		return false, err
	} else if !exists {
		return false, errDashboardUserNotFound
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	changed := false
	providers := make([]string, 0, len(links))
	for p := range links {
		providers = append(providers, p)
	}
	sort.Strings(providers)
	for _, provider := range providers {
		account := links[provider]
		var current string
		err := tx.QueryRow(`SELECT account FROM dashboard_user_oidc WHERE provider = ? AND username = ?`, provider, username).Scan(&current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if strings.EqualFold(current, account) {
			continue
		}
		if account == "" {
			_, err = tx.Exec(`DELETE FROM dashboard_user_oidc WHERE provider = ? AND username = ?`, provider, username)
		} else {
			_, err = tx.Exec(
				`INSERT INTO dashboard_user_oidc (provider, username, account) VALUES (?, ?, ?)
				 ON CONFLICT(provider, username) DO UPDATE SET account = excluded.account, subject = ''`,
				provider, username, account,
			)
		}
		if isUniqueViolation(err) {
			return false, errOIDCUsernameTaken
		}
		if err != nil {
			return false, err
		}
		changed = true
	}
	for _, provider := range rebind {
		res, err := tx.Exec(
			`UPDATE dashboard_user_oidc SET subject = '' WHERE provider = ? AND username = ? AND subject != ''`,
			provider, username,
		)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			changed = true
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	return true, revokeAllDashboardSessionsFor(db, username)
}

// dashboardUserHasPassword reports whether username can sign in with
// a password.
func dashboardUserHasPassword(db *sql.DB, username string) (bool, error) {
	hash, _, err := lookupDashboardUser(db, username)
	return hash != "", err
}

// dashboardUserForOIDC resolves a sign-in at provider to the dashboard
// user it is for. A bound subject decides; otherwise the one user
// linked to the account whose subject is still unbound gets this
// subject bound, once. An account already bound to another subject
// never matches: the provider account was replaced.
func dashboardUserForOIDC(db *sql.DB, provider, subject, account string) (string, error) {
	if db == nil {
		return "", fmt.Errorf("no db")
	}
	var username string
	err := db.QueryRow(
		`SELECT username FROM dashboard_user_oidc WHERE provider = ? AND subject = ?`, provider, subject,
	).Scan(&username)
	if err == nil {
		return username, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if account == "" {
		return "", errOIDCUnlinked
	}
	err = db.QueryRow(
		`SELECT username FROM dashboard_user_oidc WHERE provider = ? AND lower(account) = lower(?) AND subject = ''`,
		provider, account,
	).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errOIDCUnlinked
	}
	if err != nil {
		return "", err
	}
	res, err := db.Exec(
		`UPDATE dashboard_user_oidc SET subject = ? WHERE provider = ? AND username = ? AND subject = ''`,
		subject, provider, username,
	)
	if isUniqueViolation(err) {
		return "", errOIDCUnlinked
	}
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", errOIDCUnlinked
	}
	return username, nil
}
