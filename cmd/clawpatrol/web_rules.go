package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/internal/config/plugins/rules"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

const (
	// memberRulesFilePrefix names a member's rules file in a directory
	// config: 50-user-<username>.hcl, sorted between hand-written files
	// and the admin dashboard file.
	memberRulesFilePrefix = "50-user-"
	// myActionsMaxPage caps one /api/my/actions page.
	myActionsMaxPage = 200
	// rulePreviewSample is how many recent requests a preview replays.
	rulePreviewSample = 200
)

var (
	errMemberRulesNeedDir   = errors.New("member rules need a directory config (pass the gateway a directory of .hcl files)")
	errConfigWritesDisabled = errors.New("dashboard config writes are disabled (gateway.dashboard_config_writes)")
)

// viewer is who is asking, and what they may see: an admin sees
// everything, a member only the actions of profiles they own.
type viewer struct {
	admin    bool
	username string
	profiles map[string]bool
	approver string
}

func (w *webMux) viewerFor(r *http.Request) (viewer, error) {
	p, ok := principalFromContext(r.Context())
	if !ok {
		return viewer{}, fmt.Errorf("no authenticated principal")
	}
	if principalRole(p) == dashboardRoleAdmin {
		return viewer{admin: true, username: p.Owner}, nil
	}
	profiles, err := listDashboardUserProfiles(w.g.db, p.Owner)
	if err != nil {
		return viewer{}, err
	}
	approver, err := lookupDashboardUserApprover(w.g.db, p.Owner)
	if err != nil {
		return viewer{}, err
	}
	v := viewer{username: p.Owner, profiles: map[string]bool{}, approver: approver}
	for _, name := range profiles {
		v.profiles[name] = true
	}
	return v, nil
}

func (v viewer) canSee(ev *Event) bool {
	return v.admin || (ev.Profile != "" && v.profiles[ev.Profile])
}

func (v viewer) author() *RuleAuthor {
	if v.admin {
		return nil
	}
	return &RuleAuthor{Username: v.username, Approver: v.approver}
}

func (v viewer) sortedProfiles() []string {
	out := make([]string, 0, len(v.profiles))
	for p := range v.profiles {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// rulesFile is the config file the viewer's rules live in, and its
// path. Members need a directory config: their rules get a file of
// their own.
func (w *webMux) rulesFile(v viewer) (string, string, error) {
	if v.admin {
		return resolveConfigFile(w.g.cfgPath, "")
	}
	if !configIsDir(w.g.cfgPath) {
		return "", "", errMemberRulesNeedDir
	}
	return resolveConfigFile(w.g.cfgPath, memberRulesFilePrefix+v.username+".hcl")
}

type myActionRow struct {
	Cursor   int64  `json:"cursor"`
	ID       string `json:"id"`
	TsNs     int64  `json:"ts_ns"`
	Family   string `json:"family,omitempty"`
	Host     string `json:"host"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Status   string `json:"status,omitempty"`
	Action   string `json:"action,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Profile  string `json:"profile,omitempty"`
}

// apiMyActions pages through the actions the caller may see, newest
// first. ?before= takes the smallest cursor of the previous page.
func (w *webMux) apiMyActions(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > myActionsMaxPage {
		limit = myActionsMaxPage
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)

	var where []string
	var args []any
	if !v.admin {
		profiles := v.sortedProfiles()
		if len(profiles) == 0 {
			writeJSON(rw, map[string]any{"actions": []myActionRow{}})
			return
		}
		where = append(where, "profile IN (?"+strings.Repeat(",?", len(profiles)-1)+")")
		for _, p := range profiles {
			args = append(args, p)
		}
	}
	if before > 0 {
		where = append(where, "id < ?")
		args = append(args, before)
	}
	query := `SELECT id, action_id, ts_ns, family, host, method, path, status, action, endpoint, rule, profile FROM actions`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := w.g.db.Query(query, args...)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []myActionRow{}
	for rows.Next() {
		var row myActionRow
		var actionID, family, method, path, status, action, endpoint, rule, profile sql.NullString
		if err := rows.Scan(&row.Cursor, &actionID, &row.TsNs, &family, &row.Host, &method, &path,
			&status, &action, &endpoint, &rule, &profile); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		row.ID, row.Family, row.Method, row.Path = actionID.String, family.String, method.String, path.String
		row.Status, row.Action, row.Endpoint = status.String, action.String, endpoint.String
		row.Rule, row.Profile = rule.String, profile.String
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"actions": out})
}

type ruleRequestBody struct {
	ActionID string `json:"action_id"`
	RuleRequest
}

// scopedRuleFor loads the action and generates the rule the caller
// asked for. A member gets a 404 for an action outside their profiles,
// the same answer as for one that does not exist.
func (w *webMux) scopedRuleFor(rw http.ResponseWriter, r *http.Request) (viewer, *Event, *ScopedRule, bool) {
	var body ruleRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return viewer{}, nil, nil, false
	}
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return viewer{}, nil, nil, false
	}
	ev, err := w.loadAction(body.ActionID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !v.canSee(ev)) {
		http.Error(rw, "not found", http.StatusNotFound)
		return viewer{}, nil, nil, false
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return viewer{}, nil, nil, false
	}
	if !v.admin {
		body.Approver = ""
	} else if err := validateUserAssignment(w.g.Policy(), nil, &body.Approver); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return viewer{}, nil, nil, false
	}
	rule, err := GenerateScopedRule(w.g.Policy(), ev, body.RuleRequest, v.author())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return viewer{}, nil, nil, false
	}
	return v, ev, rule, true
}

// apiRulePreview generates a rule from an action without writing it,
// and replays recent requests against it.
func (w *webMux) apiRulePreview(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	v, ev, rule, ok := w.scopedRuleFor(rw, r)
	if !ok {
		return
	}
	matched, sampled, err := w.countRecentMatches(v, ev, rule)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	file, _, fileErr := w.rulesFile(v)
	out := map[string]any{
		"rule":           rule,
		"file":           file,
		"recent_matches": matched,
		"recent_sampled": sampled,
		"writes_enabled": w.g.cfg.Load().DashboardConfigWrites() && fileErr == nil,
	}
	if fileErr != nil {
		out["writes_unavailable"] = fileErr.Error()
	} else if !w.g.cfg.Load().DashboardConfigWrites() {
		out["writes_unavailable"] = errConfigWritesDisabled.Error()
	}
	writeJSON(rw, out)
}

// countRecentMatches replays up to rulePreviewSample recent requests
// the rule could apply to: same endpoint (or, for a new endpoint, same
// host with no endpoint), and for a member the same profile.
func (w *webMux) countRecentMatches(v viewer, ev *Event, rule *ScopedRule) (int, int, error) {
	query := `SELECT action_id FROM actions WHERE `
	var args []any
	if rule.NewEndpoint {
		query += `host = ? AND (endpoint IS NULL OR endpoint = '')`
		args = append(args, ev.Host)
	} else {
		query += `endpoint = ?`
		args = append(args, rule.EndpointName)
	}
	if !v.admin {
		query += ` AND profile = ?`
		args = append(args, ev.Profile)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, rulePreviewSample)
	rows, err := w.g.db.Query(query, args...)
	if err != nil {
		return 0, 0, err
	}
	var ids []string
	for rows.Next() {
		var id sql.NullString
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, 0, err
		}
		ids = append(ids, id.String)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	replay := *rule
	if rule.NewEndpoint {
		// Recorded requests predate the generated credential.
		replay.Credential = ""
	}
	matched, sampled := 0, 0
	for _, id := range ids {
		recorded, err := w.loadAction(id)
		if err != nil {
			continue
		}
		if m, ok := ruleMatchesEvent(&replay, recorded); ok {
			sampled++
			if m {
				matched++
			}
		}
	}
	return matched, sampled, nil
}

// apiRuleCreate generates a rule from an action and appends it to the
// caller's rules file.
func (w *webMux) apiRuleCreate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	v, _, rule, ok := w.scopedRuleFor(rw, r)
	if !ok {
		return
	}
	setAuditTarget(r, rule.RuleName)
	file, path, err := w.rulesFile(v)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusConflict)
		return
	}
	if !w.g.cfg.Load().DashboardConfigWrites() {
		http.Error(rw, errConfigWritesDisabled.Error(), http.StatusForbidden)
		return
	}
	current, err := readConfigFileOrEmpty(path)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	changes, err := planConfigAppend(w.g.cfgPath, file, current, rule.HCL)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.writeRuleChanges(rw, changes, map[string]any{"ok": true, "rule_name": rule.RuleName, "file": file})
}

func (w *webMux) writeRuleChanges(rw http.ResponseWriter, changes []configChange, ok map[string]any) {
	if err := w.g.writeConfigFilesLocked(changes); err != nil {
		var invalid *configInvalidError
		if errors.As(err, &invalid) {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.bustStateCache()
	writeJSON(rw, ok)
}

type myRule struct {
	Name       string   `json:"name"`
	Endpoints  []string `json:"endpoints"`
	Priority   int      `json:"priority"`
	Disabled   bool     `json:"disabled"`
	Condition  string   `json:"condition,omitempty"`
	Credential string   `json:"credential,omitempty"`
	Profile    string   `json:"profile,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Approve    []string `json:"approve,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// apiMyRules lists the rules declared in the caller's rules file.
func (w *webMux) apiMyRules(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	file, path, err := w.rulesFile(v)
	if err != nil {
		writeJSON(rw, map[string]any{"file": "", "rules": []myRule{}, "unavailable": err.Error()})
		return
	}
	out := []myRule{}
	if gw := w.g.cfg.Load(); gw != nil && gw.Policy != nil {
		for name, ent := range gw.Policy.Rules {
			if ent == nil || ent.Symbol == nil || ent.Symbol.Block == nil ||
				filepath.Clean(ent.Symbol.Block.DefRange.Filename) != filepath.Clean(path) {
				continue
			}
			body, ok := ent.Body.(*rules.Rule)
			if !ok {
				continue
			}
			rule := myRule{
				Name: name, Endpoints: body.Endpoints, Priority: body.Priority, Disabled: body.Disabled,
				Condition: body.Condition, Credential: body.Credential, Profile: body.Profile,
				Verdict: body.Verdict, Reason: body.Reason,
			}
			for _, stage := range body.Approve {
				rule.Approve = append(rule.Approve, stage.Name)
			}
			out = append(out, rule)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(rw, map[string]any{"file": file, "rules": out})
}

// apiMyRulesUpdate disables or re-enables a rule in the caller's file.
func (w *webMux) apiMyRulesUpdate(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Disabled bool   `json:"disabled"`
	}
	w.editMyRule(rw, r, &body, func() string { return body.Name }, func(f *hclwrite.File, blk *hclwrite.Block) {
		if body.Disabled {
			blk.Body().SetAttributeValue("disabled", cty.True)
		} else {
			blk.Body().RemoveAttribute("disabled")
		}
	})
}

// apiMyRulesDelete removes a rule from the caller's file. An endpoint
// and passthrough credential generated with it stay: a profile in
// another file may list that credential.
func (w *webMux) apiMyRulesDelete(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	w.editMyRule(rw, r, &body, func() string { return body.Name }, func(f *hclwrite.File, blk *hclwrite.Block) {
		f.Body().RemoveBlock(blk)
	})
}

func (w *webMux) editMyRule(rw http.ResponseWriter, r *http.Request, body any, name func() string, edit func(*hclwrite.File, *hclwrite.Block)) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, name())
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	file, path, err := w.rulesFile(v)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusConflict)
		return
	}
	if !w.g.cfg.Load().DashboardConfigWrites() {
		http.Error(rw, errConfigWritesDisabled.Error(), http.StatusForbidden)
		return
	}
	current, err := readConfigFileOrEmpty(path)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	f, diags := hclwrite.ParseConfig(current, path, hcl.InitialPos)
	if diags.HasErrors() {
		http.Error(rw, diags.Error(), http.StatusInternalServerError)
		return
	}
	var target *hclwrite.Block
	for _, blk := range f.Body().Blocks() {
		if blk.Type() == "rule" && len(blk.Labels()) == 1 && blk.Labels()[0] == name() {
			target = blk
			break
		}
	}
	if target == nil {
		http.Error(rw, "no rule "+strconv.Quote(name())+" in "+file, http.StatusNotFound)
		return
	}
	edit(f, target)
	w.writeRuleChanges(rw, []configChange{{Name: file, Content: f.Bytes()}}, map[string]any{"ok": true, "file": file})
}

// memberActionPrefix is the one path prefix members may use: the
// handler under it checks the action belongs to their profiles.
const memberActionPrefix = "/api/actions/"

// isMemberRoute reports whether a member may call path: an exact
// member route, or an action under memberActionPrefix that is not
// itself a registered (admin) route such as /api/actions/rule-preview.
func (w *webMux) isMemberRoute(path string) bool {
	if memberRoutes[path] {
		return true
	}
	_, registered := w.routeAuth[path]
	return strings.HasPrefix(path, memberActionPrefix) && !registered && path != memberActionPrefix
}
