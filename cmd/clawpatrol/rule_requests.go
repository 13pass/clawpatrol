package main

// Rule change requests (doc/multi-user-dashboard.md): a member's rule
// change that can only tighten their profile is written at once; one
// that could loosen it waits for an admin, who approves it (as asked
// or edited) or rejects it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/rules"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// What a request asks for.
const (
	ruleChangeCreate  = "create"
	ruleChangeDisable = "disable"
	ruleChangeEnable  = "enable"
	ruleChangeDelete  = "delete"
)

// Where a request stands.
const (
	ruleRequestPending   = "pending"
	ruleRequestApproved  = "approved"
	ruleRequestRejected  = "rejected"
	ruleRequestWithdrawn = "withdrawn"
)

const (
	// ruleRequestsDecidedShown is how many decided requests a listing
	// returns after the pending ones.
	ruleRequestsDecidedShown = 50
	// ruleRequestTextMaxLen bounds a member's reason and an admin's
	// note.
	ruleRequestTextMaxLen = 1000
	// ruleRequestDecideMaxBytes bounds a decision body, which may carry
	// an edited rule.
	ruleRequestDecideMaxBytes = 64 << 10
	// ruleRequestWithdrawMaxBytes bounds a withdrawal body: an id.
	ruleRequestWithdrawMaxBytes = 1 << 10
)

var (
	errRuleRequestPending    = errors.New("a request for this rule is already waiting for an admin")
	errRuleRequestNotPending = errors.New("this request was already decided or withdrawn")
	errRuleRequestNotFound   = errors.New("no such rule request")
	errNoSuchMemberRule      = errors.New("no such rule")
)

type ruleChangeRequest struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Kind         string `json:"kind"`
	RuleName     string `json:"rule_name"`
	Profile      string `json:"profile,omitempty"`
	Summary      string `json:"summary"`
	HCL          string `json:"hcl,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Status       string `json:"status"`
	CreatedNs    int64  `json:"created_ns"`
	DecidedBy    string `json:"decided_by,omitempty"`
	DecidedNs    int64  `json:"decided_ns,omitempty"`
	DecisionNote string `json:"decision_note,omitempty"`
	Edited       bool   `json:"edited,omitempty"`
}

// ruleCreateNeedsReview reports whether a member's new rule with this
// verdict could let through what the profile's other rules stop. Only
// a deny cannot. A pre-approval skips admin approvals; a required
// approval sits above admin rules, so it can stand in for an admin's
// deny or approver.
func ruleCreateNeedsReview(verdict string) bool {
	return verdict != ruleVerdictDeny
}

// ruleEditNeedsReview reports whether a change to a member's existing
// rule could loosen the profile: switching a rule off loosens it
// unless the rule pre-approves, switching one on unless it denies.
// A change that leaves the rule as it is — disabling a disabled rule,
// deleting one — needs no review.
func ruleEditNeedsReview(kind string, r *rules.Rule) bool {
	allows := len(r.Approve) == 0 && r.Verdict == ruleVerdictAllow
	denies := len(r.Approve) == 0 && r.Verdict == ruleVerdictDeny
	switch kind {
	case ruleChangeEnable:
		return r.Disabled && !denies
	default:
		return !r.Disabled && !allows
	}
}

// ruleChangesNeedingReview lists the changes to r a member must ask
// an admin for, so the dashboard can say so before they try.
func ruleChangesNeedingReview(r *rules.Rule) []string {
	out := []string{}
	for _, kind := range []string{ruleChangeDisable, ruleChangeEnable, ruleChangeDelete} {
		if ruleEditNeedsReview(kind, r) {
			out = append(out, kind)
		}
	}
	return out
}

// ruleOutcomeLabel names what a rule does, for a request's summary.
func ruleOutcomeLabel(r *rules.Rule) string {
	switch {
	case len(r.Approve) > 0:
		return "require approval"
	case r.Verdict == ruleVerdictAllow:
		return "pre-approve"
	default:
		return "block"
	}
}

// ruleCreateSummary describes a new rule in a line: what it does to
// which requests.
func ruleCreateSummary(req RuleRequest, rule *ScopedRule, ev *Event) string {
	what := map[string]string{
		ruleVerdictDeny:    "block",
		ruleVerdictAllow:   "pre-approve",
		ruleVerdictApprove: "require approval for",
	}[req.Verdict]
	target := strings.TrimSpace(ev.Method + " " + ev.Path)
	if req.Scope == ruleScopeAnyPath {
		target = ev.Method
	}
	if target == "" {
		target = ev.Host
	}
	where := ev.Endpoint
	if where == "" {
		where = ev.Host
	}
	scopeLabel := map[string]string{
		ruleScopeAnyMethod: ", any method",
		ruleScopeAnyPath:   ", any path",
		ruleScopePattern:   ", IDs generalized",
		ruleScopeAnyName:   ", any object name",
	}[req.Scope]
	if rule.HandWritten {
		return fmt.Sprintf("%s requests on %s matching a condition written by hand", what, where)
	}
	return fmt.Sprintf("%s %s on %s%s", what, target, where, scopeLabel)
}

func ruleEditSummary(kind, name string, r *rules.Rule) string {
	return fmt.Sprintf("%s rule %s (%s)", kind, name, ruleOutcomeLabel(r))
}

// insertRuleRequest stores a pending request; the partial unique index
// rule_requests_one_pending keeps it to one per member and rule.
func insertRuleRequest(db *sql.DB, req *ruleChangeRequest) error {
	req.Status = ruleRequestPending
	req.CreatedNs = time.Now().UnixNano()
	res, err := db.Exec(
		`INSERT INTO rule_requests (username, kind, rule_name, profile, summary, hcl, reason, status, created_ns)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Username, req.Kind, req.RuleName, req.Profile, req.Summary, req.HCL, req.Reason, req.Status, req.CreatedNs,
	)
	if isUniqueViolation(err) {
		return errRuleRequestPending
	}
	if err != nil {
		return err
	}
	req.ID, err = res.LastInsertId()
	return err
}

const ruleRequestColumns = `id, username, kind, rule_name, profile, summary, hcl, reason, status,
	created_ns, decided_by, decided_ns, decision_note, edited`

func scanRuleRequest(row interface{ Scan(...any) error }) (ruleChangeRequest, error) {
	var r ruleChangeRequest
	err := row.Scan(&r.ID, &r.Username, &r.Kind, &r.RuleName, &r.Profile, &r.Summary, &r.HCL, &r.Reason,
		&r.Status, &r.CreatedNs, &r.DecidedBy, &r.DecidedNs, &r.DecisionNote, &r.Edited)
	return r, err
}

func getRuleRequest(db *sql.DB, id int64) (ruleChangeRequest, error) {
	r, err := scanRuleRequest(db.QueryRow(`SELECT `+ruleRequestColumns+` FROM rule_requests WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, errRuleRequestNotFound
	}
	return r, err
}

// listRuleRequests returns the pending requests, oldest first, then the
// most recent decided ones. username "" lists everyone's.
func listRuleRequests(db *sql.DB, username string) ([]ruleChangeRequest, error) {
	out := []ruleChangeRequest{}
	for _, q := range []struct {
		where, order string
		limit        int
	}{
		{"status = ?", "id ASC", -1},
		{"status != ?", "id DESC", ruleRequestsDecidedShown},
	} {
		query := `SELECT ` + ruleRequestColumns + ` FROM rule_requests WHERE ` + q.where
		args := []any{ruleRequestPending}
		if username != "" {
			query += ` AND username = ?`
			args = append(args, username)
		}
		query += ` ORDER BY ` + q.order + ` LIMIT ?`
		args = append(args, q.limit)
		rows, err := db.Query(query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			r, err := scanRuleRequest(rows)
			if err != nil {
				_ = rows.Close()
				return nil, err
			}
			out = append(out, r)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func countPendingRuleRequests(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM rule_requests WHERE status = ?`, ruleRequestPending).Scan(&n)
	return n, err
}

// closeRuleRequest records a decision or withdrawal of a pending
// request; hcl replaces the stored rule when the admin edited it.
func closeRuleRequest(db *sql.DB, id int64, status, by, note, hcl string, edited bool) error {
	query := `UPDATE rule_requests SET status = ?, decided_by = ?, decided_ns = ?, decision_note = ?, edited = ?`
	args := []any{status, by, time.Now().UnixNano(), note, edited}
	if edited {
		query += `, hcl = ?`
		args = append(args, hcl)
	}
	query += ` WHERE id = ? AND status = ?`
	args = append(args, id, ruleRequestPending)
	res, err := db.Exec(query, args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errRuleRequestNotPending
	}
	return nil
}

// retireRuleRequests closes a deleted user's pending requests and files
// all of theirs under a former-user name, as their rules file is: a
// later user of the same name must not see or withdraw them.
func retireRuleRequests(db *sql.DB, username string, now time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		`UPDATE rule_requests SET status = ?, decided_ns = ?, decision_note = 'the user was deleted'
		 WHERE username = ? AND status = ?`,
		ruleRequestWithdrawn, now.UnixNano(), username, ruleRequestPending,
	); err != nil {
		return err
	}
	former := fmt.Sprintf("%s (deleted %s)", username, formerMemberStamp(now))
	if _, err := tx.Exec(`UPDATE rule_requests SET username = ? WHERE username = ?`, former, username); err != nil {
		return err
	}
	return tx.Commit()
}

// fileRuleRequest stores a member's request, tells the admins and
// answers 202 with it.
func (w *webMux) fileRuleRequest(rw http.ResponseWriter, req ruleChangeRequest, extra map[string]any) {
	if err := insertRuleRequest(w.g.db, &req); err != nil {
		if errors.Is(err, errRuleRequestPending) {
			http.Error(rw, err.Error(), http.StatusConflict)
			return
		}
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("dashboard rules: %s asked to %s (request %d)", req.Username, req.Summary, req.ID)
	w.bustStateCache()
	w.notifyAdmins(req)
	out := map[string]any{"ok": true, "pending": true, "request_id": req.ID, "rule_name": req.RuleName}
	for k, v := range extra {
		out[k] = v
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(rw).Encode(out)
}

// memberViewer is the viewer a member's request is applied as: their
// profiles now, not when they asked.
func (w *webMux) memberViewer(username string) (viewer, error) {
	_, exists, err := lookupDashboardUserRole(w.g.db, username)
	if err != nil {
		return viewer{}, err
	}
	if !exists {
		return viewer{}, fmt.Errorf("user %q no longer exists; reject the request", username)
	}
	return w.viewerForPrincipal(principal{Owner: username, Role: dashboardRoleMember})
}

// memberRuleEditLocked returns the change that applies kind to rule
// name in a rules file. g.configMu must be held.
func memberRuleEditLocked(file, path, name, kind string) ([]configChange, error) {
	current, err := readConfigFileOrEmpty(path)
	if err != nil {
		return nil, err
	}
	f, diags := hclwrite.ParseConfig(current, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	var target *hclwrite.Block
	for _, blk := range f.Body().Blocks() {
		if blk.Type() == "rule" && len(blk.Labels()) == 1 && blk.Labels()[0] == name {
			target = blk
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("%w %q in %s", errNoSuchMemberRule, name, file)
	}
	switch kind {
	case ruleChangeDisable:
		target.Body().SetAttributeValue("disabled", cty.True)
	case ruleChangeEnable:
		target.Body().RemoveAttribute("disabled")
	case ruleChangeDelete:
		f.Body().RemoveBlock(target)
	default:
		return nil, fmt.Errorf("unknown rule change %q", kind)
	}
	return []configChange{{Name: file, Content: f.Bytes()}}, nil
}

// apiRuleRequests lists rule requests: every member's for an admin,
// the caller's own for a member.
func (w *webMux) apiRuleRequests(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	username := v.username
	if v.admin {
		username = ""
	}
	out, err := listRuleRequests(w.g.db, username)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"requests": out})
}

// apiRuleRequestWithdraw lets a member take back their own pending
// request.
func (w *webMux) apiRuleRequestWithdraw(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	r.Body = http.MaxBytesReader(rw, r.Body, ruleRequestWithdrawMaxBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, fmt.Sprintf("rule request %d", body.ID))
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	// Under the config lock, so a withdrawal cannot land between an
	// approval's config write and its status update.
	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	req, err := getRuleRequest(w.g.db, body.ID)
	if errors.Is(err, errRuleRequestNotFound) || (err == nil && req.Username != v.username) {
		http.Error(rw, errRuleRequestNotFound.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := closeRuleRequest(w.g.db, req.ID, ruleRequestWithdrawn, v.username, "", "", false); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errRuleRequestNotPending) {
			status = http.StatusConflict
		}
		http.Error(rw, err.Error(), status)
		return
	}
	w.bustStateCache()
	writeJSON(rw, map[string]any{"ok": true})
}

// apiRuleRequestDecide is an admin's answer to a request: approve it as
// asked, approve an edited rule (a create only), or reject it. An
// approved change is applied as the member, to their rules file.
func (w *webMux) apiRuleRequestDecide(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID       int64  `json:"id"`
		Decision string `json:"decision"`
		Note     string `json:"note"`
		// HCL, when present, replaces the requested rule of a create.
		HCL *string `json:"hcl"`
	}
	r.Body = http.MaxBytesReader(rw, r.Body, ruleRequestDecideMaxBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, fmt.Sprintf("rule request %d: %s", body.ID, body.Decision))
	if len(body.Note) > ruleRequestTextMaxLen {
		http.Error(rw, fmt.Sprintf("the note is longer than %d characters", ruleRequestTextMaxLen), http.StatusBadRequest)
		return
	}
	admin, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	decidedBy := admin.username
	if decidedBy == "" {
		decidedBy = "an admin"
	}

	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	req, err := getRuleRequest(w.g.db, body.ID)
	if errors.Is(err, errRuleRequestNotFound) {
		http.Error(rw, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Status != ruleRequestPending {
		http.Error(rw, errRuleRequestNotPending.Error(), http.StatusConflict)
		return
	}

	switch body.Decision {
	case "reject":
		if err := closeRuleRequest(w.g.db, req.ID, ruleRequestRejected, decidedBy, body.Note, "", false); err != nil {
			http.Error(rw, err.Error(), http.StatusConflict)
			return
		}
		req.Status, req.DecidedBy, req.DecisionNote = ruleRequestRejected, decidedBy, body.Note
	case "approve":
		hclText, edited := req.HCL, false
		if body.HCL != nil && strings.TrimSpace(*body.HCL) != strings.TrimSpace(req.HCL) {
			if req.Kind != ruleChangeCreate {
				http.Error(rw, "only a new rule can be edited; approve or reject this change", http.StatusBadRequest)
				return
			}
			if strings.TrimSpace(*body.HCL) == "" {
				http.Error(rw, "the edited rule is empty; reject the request instead", http.StatusBadRequest)
				return
			}
			hclText, edited = *body.HCL, true
		}
		changes, status, err := w.planRuleRequestLocked(req, hclText)
		if err != nil {
			http.Error(rw, err.Error(), status)
			return
		}
		if err := w.g.writeConfigFilesLocked(changes); err != nil {
			var invalid *configInvalidError
			if errors.As(err, &invalid) {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := closeRuleRequest(w.g.db, req.ID, ruleRequestApproved, decidedBy, body.Note, hclText, edited); err != nil {
			http.Error(rw, "the change was applied, but the request could not be marked approved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		req.Status, req.DecidedBy, req.DecisionNote, req.Edited = ruleRequestApproved, decidedBy, body.Note, edited
	default:
		http.Error(rw, "decision must be approve or reject", http.StatusBadRequest)
		return
	}
	log.Printf("dashboard rules: %s %s request %d of %s (%s)", decidedBy, req.Status, req.ID, req.Username, req.Summary)
	w.bustStateCache()
	w.notifyRequester(req)
	writeJSON(rw, map[string]any{"ok": true, "status": req.Status})
}

// planRuleRequestLocked returns the config change an approved request
// makes, checked against the member as they are now, and the HTTP
// status of a refusal. g.configMu must be held.
func (w *webMux) planRuleRequestLocked(req ruleChangeRequest, hclText string) ([]configChange, int, error) {
	if !w.g.cfg.Load().DashboardConfigWrites() {
		return nil, http.StatusForbidden, errConfigWritesDisabled
	}
	member, err := w.memberViewer(req.Username)
	if err != nil {
		return nil, http.StatusConflict, err
	}
	if req.Profile != "" && !member.ownsProfile(req.Profile) {
		return nil, http.StatusConflict, fmt.Errorf("%s no longer owns profile %q; reject the request", req.Username, req.Profile)
	}
	file, path, err := w.rulesFile(member)
	if err != nil {
		return nil, http.StatusConflict, err
	}
	if req.Kind != ruleChangeCreate {
		changes, err := memberRuleEditLocked(file, path, req.RuleName, req.Kind)
		if errors.Is(err, errNoSuchMemberRule) {
			return nil, http.StatusConflict, fmt.Errorf("%w; reject the request", err)
		}
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		return changes, 0, nil
	}
	if err := checkRequestedRuleStillFits(w.g.cfg.Load(), w.g.Policy(), req, hclText); err != nil {
		return nil, http.StatusConflict, err
	}
	current, err := readConfigFileOrEmpty(path)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	changes, err := planConfigAppend(w.g.cfgPath, file, current, hclText)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return changes, 0, nil
}

// checkRequestedRuleStillFits repeats, at approval, the checks a rule
// passed when it was asked for: its name is free, and an endpoint it
// declares for a host does not shadow one the profile has gained since.
func checkRequestedRuleStillFits(gw *config.Gateway, policy *config.CompiledPolicy, req ruleChangeRequest, hclText string) error {
	if gw == nil || gw.Policy == nil || policy == nil {
		return errors.New("no config is loaded")
	}
	if gw.Policy.Rules[req.RuleName] != nil {
		return fmt.Errorf("rule %q already exists; reject the request", req.RuleName)
	}
	f, diags := hclsyntax.ParseConfig([]byte(hclText), "request.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		return nil // validation reports it with the full config
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return nil
	}
	for _, blk := range body.Blocks {
		if blk.Type != "endpoint" {
			continue
		}
		attr := blk.Body.Attributes["hosts"]
		if attr == nil {
			continue
		}
		hosts, diags := attr.Expr.Value(nil)
		if diags.HasErrors() || !hosts.CanIterateElements() {
			continue
		}
		for it := hosts.ElementIterator(); it.Next(); {
			_, h := it.Element()
			if !h.Type().Equals(cty.String) || h.IsNull() {
				continue
			}
			host := h.AsString()
			if ep := runtime.HostEndpoint(policy, req.Profile, host); ep != nil {
				return fmt.Errorf("%s now has endpoint %q in profile %q; reject the request and ask for a rule from a request made since", host, ep.Name, req.Profile)
			}
		}
	}
	return nil
}

// validateConfigChangesLocked checks the config would load with
// changes applied, without writing them. g.configMu must be held.
func (g *Gateway) validateConfigChangesLocked(changes []configChange) error {
	if !configIsDir(g.cfgPath) {
		return errMemberRulesNeedDir
	}
	overrides := make(map[string][]byte, len(changes))
	for _, c := range changes {
		overrides[c.Name] = c.Content
	}
	if _, _, err := loadConfigOverlay(g.cfgPath, overrides); err != nil {
		return &configInvalidError{err}
	}
	return nil
}

// notifyAdmins tells every admin with a verified channel that a request
// waits. Sent in the background: a slow channel must not hold up the
// member's answer.
func (w *webMux) notifyAdmins(req ruleChangeRequest) {
	w.notifications.Add(1)
	go func() {
		defer w.notifications.Done()
		w.sendToAdmins(req)
	}()
}

func (w *webMux) sendToAdmins(req ruleChangeRequest) {
	users, err := listDashboardUsers(w.g.db)
	if err != nil {
		log.Printf("dashboard rules: notify admins of request %d: %v", req.ID, err)
		return
	}
	text := fmt.Sprintf("Claw Patrol: %s asks to %s.", req.Username, req.Summary)
	if req.Reason != "" {
		text += " Reason: " + req.Reason
	}
	text += w.reviewLink()
	sent := 0
	for _, u := range users {
		if u.Role != dashboardRoleAdmin {
			continue
		}
		if w.sendToUser(u.Username, text) {
			sent++
		}
	}
	if sent == 0 {
		log.Printf("dashboard rules: request %d waits on the Rules page; no admin has a verified notification channel", req.ID)
	}
}

// notifyRequester tells the member how their request was decided.
func (w *webMux) notifyRequester(req ruleChangeRequest) {
	text := fmt.Sprintf("Claw Patrol: %s %s your request to %s.", req.DecidedBy, req.Status, req.Summary)
	if req.Edited {
		text += " The rule was edited before it was applied."
	}
	if req.DecisionNote != "" {
		text += " Note: " + req.DecisionNote
	}
	w.sendToUser(req.Username, text+w.reviewLink())
}

func (w *webMux) reviewLink() string {
	if u := strings.TrimRight(w.g.cfg.Load().PublicURL(), "/"); u != "" {
		return " " + u + "/#/rules"
	}
	return ""
}

// sendToUser sends text to username's verified channel in the
// background, and reports whether there was one.
func (w *webMux) sendToUser(username, text string) bool {
	c, err := lookupUserChannel(w.g.db, username)
	if err != nil || c.VerifiedNs == 0 {
		return false
	}
	w.notifications.Add(1)
	go func() {
		defer w.notifications.Done()
		if err := w.g.sendChannelText(context.Background(), c, text); err != nil {
			log.Printf("dashboard rules: notify %s: %v", username, err)
		}
	}()
	return true
}
