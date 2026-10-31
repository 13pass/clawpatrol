package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config/plugins/rules"
	"github.com/denoland/clawpatrol/internal/config/runtime"
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
	// ruleRequestMaxBytes bounds a rule request body, read in full
	// before the config lock is taken.
	ruleRequestMaxBytes = 64 << 10
	// formerMemberRulesFilePrefix names the rules file of a deleted
	// user: still loaded, so its rules keep applying, but owned by no
	// account. An admin edits or removes it like any config file.
	formerMemberRulesFilePrefix = "50-former-user-"
	formerMemberRulesTimeFormat = "20060102-150405"
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
	return w.viewerForPrincipal(p)
}

func (w *webMux) viewerForPrincipal(p principal) (viewer, error) {
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
	// The gateway dials a declared Postgres endpoint from its own host,
	// so an address the relay would refuse today must not become one.
	if ip, ok := postgresRelayAddr(ev); ok {
		if err := w.g.relayDestOK(ip.String()); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return viewer{}, nil, nil, false
		}
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
// host with no endpoint), and for a member the same profile. One query
// reads only what the replay needs. A new endpoint with no rule, or a
// new Postgres endpoint, which has no recorded statements to replay,
// counts every request or connection, as one it would now inspect.
func (w *webMux) countRecentMatches(v viewer, ev *Event, rule *ScopedRule) (int, int, error) {
	countsConnections := rule.NewEndpoint && (rule.Family == "sql" || rule.RuleName == "")
	replayRule := *rule
	if rule.NewEndpoint {
		// Recorded requests predate the generated credential.
		replayRule.Credential = ""
	}
	replay, err := newRuleReplay(&replayRule)
	if err != nil {
		return 0, 0, err
	}
	query := `SELECT method, path, host, req_headers, extra, credential, profile, agent_ip
	          FROM actions WHERE `
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
	defer rows.Close()
	matched, sampled := 0, 0
	for rows.Next() {
		var method, path, host, headers, extra, credential, profile, agentIP sql.NullString
		if err := rows.Scan(&method, &path, &host, &headers, &extra, &credential, &profile, &agentIP); err != nil {
			return 0, 0, err
		}
		recorded := &Event{
			Method: method.String, Path: path.String, Host: host.String,
			Credential: credential.String, Profile: profile.String, AgentIP: agentIP.String,
		}
		unmarshalHeaders(headers.String, &recorded.ReqHeaders)
		if extra.String != "" {
			_ = json.Unmarshal([]byte(extra.String), &recorded.Facets)
		}
		if countsConnections {
			sampled++
			matched++
			continue
		}
		if m, ok := replay.matches(recorded); ok {
			sampled++
			if m {
				matched++
			}
		}
	}
	return matched, sampled, rows.Err()
}

// apiRuleCreate generates a rule from an action and appends it to the
// caller's rules file.
func (w *webMux) apiRuleCreate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	// Read the body before taking the config lock, so a slow client
	// cannot hold up every other config write.
	if _, err := readAndRestoreBody(rw, r, ruleRequestMaxBytes); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	v, _, rule, ok := w.scopedRuleFor(rw, r)
	if !ok {
		return
	}
	// An endpoint that only logs comes with no rule.
	target := rule.RuleName
	if target == "" {
		target = rule.EndpointName
	}
	setAuditTarget(r, target)
	if gw := w.g.cfg.Load(); rule.RuleName != "" && gw != nil && gw.Policy != nil && gw.Policy.Rules[rule.RuleName] != nil {
		http.Error(rw, "rule "+strconv.Quote(rule.RuleName)+" already exists", http.StatusConflict)
		return
	}
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
	w.writeRuleChanges(rw, changes, map[string]any{
		"ok": true, "rule_name": rule.RuleName, "endpoint_name": rule.EndpointName,
		"new_credential": rule.NewCredential, "file": file,
	})
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
	Name string `json:"name"`
	// Owned is false for a rule pinned to a profile the viewer no
	// longer owns: it still applies, but only an admin may change it.
	Owned      bool     `json:"owned"`
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
				Name: name, Owned: v.ownsRule(body), Endpoints: body.Endpoints, Priority: body.Priority, Disabled: body.Disabled,
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
	if !v.admin {
		var body *rules.Rule
		if gw := w.g.cfg.Load(); gw != nil && gw.Policy != nil {
			if ent := gw.Policy.Rules[name()]; ent != nil {
				body, _ = ent.Body.(*rules.Rule)
			}
		}
		if body == nil || !v.ownsRule(body) {
			http.Error(rw, "this rule is pinned to a profile you no longer own; ask an admin to change it", http.StatusForbidden)
			return
		}
	}
	edit(f, target)
	w.writeRuleChanges(rw, []configChange{{Name: file, Content: f.Bytes()}}, map[string]any{"ok": true, "file": file})
}

// ownsRule reports whether the viewer may change a rule of their file:
// an admin always; a member only while they own the profile it is
// pinned to.
func (v viewer) ownsRule(r *rules.Rule) bool {
	return v.admin || (r.Profile != "" && v.profiles[r.Profile])
}

// decidesPending reports whether the viewer may see and decide a
// pending approval. A member may for a profile they still own, when
// the approver routed it to the profile's owners, or when a rule of
// their own file raised it; other approvals stay with the admins.
func (w *webMux) decidesPending(v viewer, p runtime.HITLPending) bool {
	if v.admin {
		return true
	}
	if !v.ownsProfile(p.Profile) {
		return false
	}
	if slices.Contains(p.Deciders, v.username) {
		return true
	}
	if p.Rule == "" {
		return false
	}
	path := w.memberRulesPath(v.username)
	gw := w.g.cfg.Load()
	if path == "" || gw == nil || gw.Policy == nil {
		return false
	}
	ent := gw.Policy.Rules[p.Rule]
	if ent == nil || ent.Symbol == nil || ent.Symbol.Block == nil ||
		filepath.Clean(ent.Symbol.Block.DefRange.Filename) != filepath.Clean(path) {
		return false
	}
	body, ok := ent.Body.(*rules.Rule)
	return ok && v.ownsRule(body)
}

// memberRulesPath is the rules file of username in a directory config,
// "" for a single-file config.
func (w *webMux) memberRulesPath(username string) string {
	if !configIsDir(w.g.cfgPath) {
		return ""
	}
	return filepath.Join(w.g.cfgPath, memberRulesFilePrefix+username+".hcl")
}

// archiveMemberRules renames a deleted user's rules file so its rules
// keep applying but belong to no account — a later user of the same
// name must not inherit them. The content is unchanged, so the config
// stays valid.
func (w *webMux) archiveMemberRules(username string) error {
	path := w.memberRulesPath(username)
	if path == "" {
		return nil
	}
	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	archived := formerMemberRulesFilePrefix + username + "-" + time.Now().UTC().Format(formerMemberRulesTimeFormat) + ".hcl"
	if err := os.Rename(path, filepath.Join(w.g.cfgPath, archived)); err != nil {
		return err
	}
	log.Printf("dashboard auth: rules of deleted user %q kept as %s", username, archived)
	return nil
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
