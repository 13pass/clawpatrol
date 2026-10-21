package main

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
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
	Username  string        `json:"username"`
	Role      dashboardRole `json:"role"`
	CreatedNs int64         `json:"created_ns"`
	UpdatedNs int64         `json:"updated_ns"`
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
	now := time.Now().UnixNano()
	res, err := db.Exec(
		`INSERT INTO dashboard_users (username, password_hash, role, created_ns, updated_ns)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(username) DO NOTHING`,
		username, string(hash), string(role), now, now,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errDashboardUserExists
	}
	return nil
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
		`SELECT username, role, created_ns, updated_ns FROM dashboard_users ORDER BY username`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardUser{}
	for rows.Next() {
		var u dashboardUser
		var role string
		if err := rows.Scan(&u.Username, &role, &u.CreatedNs, &u.UpdatedNs); err != nil {
			return nil, err
		}
		u.Role = normalizeDashboardRole(u.Username, role)
		out = append(out, u)
	}
	return out, rows.Err()
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
