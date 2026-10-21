package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	// dashboardAuditMaxPage caps one /api/audit page.
	dashboardAuditMaxPage = 500
	// defaultDashboardAuditKeep applies when gateway.dashboard_audit_keep
	// is unset.
	defaultDashboardAuditKeep   = 365 * 24 * time.Hour
	dashboardAuditSweepInterval = time.Hour
)

type dashboardAuditRecord struct {
	ID         int64  `json:"id"`
	TsNs       int64  `json:"ts_ns"`
	Username   string `json:"username"`
	AuthKind   string `json:"auth_kind"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Target     string `json:"target,omitempty"`
	Status     int    `json:"status"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

func recordDashboardAudit(db *sql.DB, rec dashboardAuditRecord) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	if rec.TsNs == 0 {
		rec.TsNs = time.Now().UnixNano()
	}
	_, err := db.Exec(
		`INSERT INTO dashboard_audit (ts_ns, username, auth_kind, method, path, target, status, remote_addr)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.TsNs, rec.Username, rec.AuthKind, rec.Method, rec.Path, rec.Target, rec.Status, rec.RemoteAddr,
	)
	return err
}

// listDashboardAudit returns up to limit records, newest first, with
// an id below beforeID (0 means from the newest).
func listDashboardAudit(db *sql.DB, beforeID int64, limit int) ([]dashboardAuditRecord, error) {
	if db == nil {
		return nil, fmt.Errorf("no db")
	}
	if limit <= 0 || limit > dashboardAuditMaxPage {
		limit = dashboardAuditMaxPage
	}
	query := `SELECT id, ts_ns, username, auth_kind, method, path, target, status, remote_addr
	          FROM dashboard_audit`
	args := []any{}
	if beforeID > 0 {
		query += ` WHERE id < ?`
		args = append(args, beforeID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardAuditRecord{}
	for rows.Next() {
		var rec dashboardAuditRecord
		if err := rows.Scan(&rec.ID, &rec.TsNs, &rec.Username, &rec.AuthKind, &rec.Method,
			&rec.Path, &rec.Target, &rec.Status, &rec.RemoteAddr); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// pruneDashboardAudit deletes records older than before.
func pruneDashboardAudit(db *sql.DB, before time.Time) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("no db")
	}
	res, err := db.Exec(`DELETE FROM dashboard_audit WHERE ts_ns < ?`, before.UnixNano())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// startDashboardAuditSweeper enforces gateway.dashboard_audit_keep. A
// keep of 0 keeps the log forever.
func (g *Gateway) startDashboardAuditSweeper(keep time.Duration) {
	if g.db == nil || keep == 0 {
		return
	}
	go func() {
		t := time.NewTicker(dashboardAuditSweepInterval)
		defer t.Stop()
		for {
			if n, err := pruneDashboardAudit(g.db, time.Now().Add(-keep)); err != nil {
				log.Printf("dashboard audit: retention sweep: %v", err)
			} else if n > 0 {
				log.Printf("dashboard audit: pruned %d records older than %s", n, keep)
			}
			<-t.C
		}
	}()
}

type auditNoteKey struct{}

type auditNote struct {
	target string
}

// setAuditTarget names what a state-changing request acted on, for its
// audit record. No-op outside the audit middleware.
func setAuditTarget(r *http.Request, target string) {
	if n, ok := r.Context().Value(auditNoteKey{}).(*auditNote); ok {
		n.target = target
	}
}

type auditStatusWriter struct {
	http.ResponseWriter
	status int
}

func (a *auditStatusWriter) WriteHeader(status int) {
	if a.status == 0 {
		a.status = status
	}
	a.ResponseWriter.WriteHeader(status)
}

func (a *auditStatusWriter) Write(b []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	return a.ResponseWriter.Write(b)
}

func (a *auditStatusWriter) Unwrap() http.ResponseWriter {
	return a.ResponseWriter
}

// auditLog records every state-changing request to an operator route
// once its handler returns. It runs inside the auth gates, so the
// principal is known. Bodies are never recorded.
func (w *webMux) auditLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !csrfRelevantMethod(r.Method) || !needsOperatorGate(w.authRequirementForPath(r.URL.Path)) {
			next.ServeHTTP(rw, r)
			return
		}
		note := &auditNote{}
		sw := &auditStatusWriter{ResponseWriter: rw}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), auditNoteKey{}, note)))
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		p, _ := principalFromContext(r.Context())
		w.recordAudit(r, p.Owner, string(p.Kind), note.target, sw.status)
	})
}

func (w *webMux) recordAudit(r *http.Request, username, authKind, target string, status int) {
	err := recordDashboardAudit(w.g.db, dashboardAuditRecord{
		Username:   username,
		AuthKind:   authKind,
		Method:     r.Method,
		Path:       r.URL.Path,
		Target:     target,
		Status:     status,
		RemoteAddr: r.RemoteAddr,
	})
	if err != nil {
		log.Printf("dashboard audit: %s %s by %q: %v", r.Method, r.URL.Path, username, err)
	}
}
