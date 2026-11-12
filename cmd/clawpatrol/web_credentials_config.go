package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/net/http/httpguts"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/credentials"
)

// credentialConfigMaxBytes bounds a credential declaration request.
const credentialConfigMaxBytes = 16 << 10

// newEndpointType is the endpoint type the form declares for a new
// host.
const newEndpointType = "https"

var (
	// configNameRE is what the form accepts as a credential or endpoint
	// name: an HCL identifier, so `<type>.<name>` stays a reference.
	configNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	// endpointHostRE is a lowercase DNS name, optionally `*.`-prefixed.
	endpointHostRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

	errNoSuchCredential     = errors.New("no such credential")
	errBadCredentialRequest = errors.New("bad request")
)

// credentialTypeOption is a credential type the dashboard declares and
// edits: the settings it sets, and the endpoint families it binds to.
type credentialTypeOption struct {
	Type     string   `json:"type"`
	Fields   []string `json:"fields"`
	Families []string `json:"families"`
}

var editableCredentialTypes = []credentialTypeOption{
	{Type: "header_token", Fields: []string{"header", "prefix"}, Families: []string{"http"}},
	{Type: "bearer_token", Fields: []string{}, Families: []string{"http", "k8s"}},
}

func editableCredentialType(typ string) (credentialTypeOption, bool) {
	for _, t := range editableCredentialTypes {
		if t.Type == typ {
			return t, true
		}
	}
	return credentialTypeOption{}, false
}

// credentialConfigRequest declares or edits a credential. Profiles is
// the full set of profiles that list it afterwards. On an edit, a nil
// Header, Prefix, Endpoint or Profiles keeps the current value.
type credentialConfigRequest struct {
	Type        string              `json:"type,omitempty"`
	Name        string              `json:"name"`
	Header      *string             `json:"header,omitempty"`
	Prefix      *string             `json:"prefix,omitempty"`
	Endpoint    *string             `json:"endpoint,omitempty"`
	NewEndpoint *newEndpointRequest `json:"new_endpoint,omitempty"`
	Profiles    *[]string           `json:"profiles,omitempty"`
}

// newEndpointRequest declares an https endpoint for one host,
// alongside the credential that binds it.
type newEndpointRequest struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

// configTree is the config's files parsed for editing, in load order.
type configTree struct {
	cfgPath string
	names   []string
	files   map[string]*hclwrite.File
	orig    map[string][]byte
	ro      map[string]bool
}

func loadConfigTree(cfgPath string) (*configTree, error) {
	infos, err := configFiles(cfgPath)
	if err != nil {
		return nil, err
	}
	t := &configTree{cfgPath: cfgPath, files: map[string]*hclwrite.File{}, orig: map[string][]byte{}, ro: map[string]bool{}}
	for _, info := range infos {
		if err := t.add(info.Name); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *configTree) path(name string) string {
	if configIsDir(t.cfgPath) {
		return filepath.Join(t.cfgPath, name)
	}
	return t.cfgPath
}

func (t *configTree) add(name string) error {
	content, err := readConfigFileOrEmpty(t.path(name))
	if err != nil {
		return err
	}
	f, diags := hclwrite.ParseConfig(content, name, hcl.InitialPos)
	if diags.HasErrors() {
		return errors.New(diags.Error())
	}
	t.names = append(t.names, name)
	t.files[name] = f
	t.orig[name] = content
	t.ro[name] = configFileReadOnly(content)
	return nil
}

// file returns a file of the tree, parsing it first if the tree does
// not hold it yet (the dashboard's own file before its first write).
func (t *configTree) file(name string) (*hclwrite.File, error) {
	if f, ok := t.files[name]; ok {
		return f, nil
	}
	if err := t.add(name); err != nil {
		return nil, err
	}
	return t.files[name], nil
}

// find returns the first block of the given type whose last label is
// name, and the file declaring it.
func (t *configTree) find(blockType, name string) (string, *hclwrite.Block) {
	for _, file := range t.names {
		for _, blk := range t.files[file].Body().Blocks() {
			labels := blk.Labels()
			if blk.Type() == blockType && len(labels) > 0 && labels[len(labels)-1] == name {
				return file, blk
			}
		}
	}
	return "", nil
}

// blocks returns every block of the given type, with its file.
func (t *configTree) blocks(blockType string) (files []string, blocks []*hclwrite.Block) {
	for _, file := range t.names {
		for _, blk := range t.files[file].Body().Blocks() {
			if blk.Type() == blockType {
				files = append(files, file)
				blocks = append(blocks, blk)
			}
		}
	}
	return files, blocks
}

func (t *configTree) readOnly(file string) bool {
	return t.ro[file]
}

// changes returns the files whose content changed, first file first,
// last file last, the rest in load order. hclwrite formats what it
// writes, so a file counts as changed only when it differs from its
// original formatted the same way: one nobody edited is left alone.
func (t *configTree) changes(first, last string) []configChange {
	var head, mid, tail []configChange
	for _, name := range t.names {
		content := t.files[name].Bytes()
		if bytes.Equal(content, hclwrite.Format(t.orig[name])) {
			continue
		}
		c := configChange{Name: name, Content: content}
		switch name {
		case first:
			head = append(head, c)
		case last:
			tail = append(tail, c)
		default:
			mid = append(mid, c)
		}
	}
	return append(append(head, mid...), tail...)
}

// profileCredentials is a profile's `credentials` list as written: its
// source, and the credential each entry names. An entry may be a
// reference (`header_token.gh`) or an object
// (`{ credential = header_token.gh, placeholder = "..." }`); one the form
// cannot read names "" and is left as it is. Edits splice the source,
// so the other entries, their comments and the list's layout stay.
type profileCredentials struct {
	src     []byte
	closeAt int // offset of the closing bracket
	entries []profileCredentialEntry
}

type profileCredentialEntry struct {
	name       string
	start, end int // offsets of the entry in src
}

func parseProfileCredentials(profile *hclwrite.Block) (*profileCredentials, error) {
	src := []byte("[]")
	if attr := profile.Body().GetAttribute("credentials"); attr != nil {
		src = attr.Expr().BuildTokens(nil).Bytes()
	}
	expr, diags := hclsyntax.ParseExpression(src, "", hcl.InitialPos)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	tuple, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return nil, fmt.Errorf("profile %q: credentials is not a list", profile.Labels()[0])
	}
	l := &profileCredentials{src: src, closeAt: tuple.SrcRange.End.Byte - 1}
	for _, item := range tuple.Exprs {
		r := item.Range()
		l.entries = append(l.entries, profileCredentialEntry{name: credentialEntryName(item), start: r.Start.Byte, end: r.End.Byte})
	}
	return l, nil
}

// credentialEntryName is the credential a list entry names, or "".
func credentialEntryName(e hclsyntax.Expression) string {
	if obj, ok := e.(*hclsyntax.ObjectConsExpr); ok {
		for _, item := range obj.Items {
			if hcl.ExprAsKeyword(item.KeyExpr) == "credential" {
				return credentialEntryName(item.ValueExpr)
			}
		}
		return ""
	}
	ref, diags := hcl.AbsTraversalForExpr(e)
	if diags.HasErrors() || len(ref) == 0 {
		return ""
	}
	switch step := ref[len(ref)-1].(type) {
	case hcl.TraverseAttr:
		return step.Name
	case hcl.TraverseRoot:
		return step.Name
	}
	return ""
}

func (l *profileCredentials) names() []string {
	out := []string{}
	for _, e := range l.entries {
		if e.name != "" {
			out = append(out, e.name)
		}
	}
	return out
}

func (l *profileCredentials) has(name string) bool {
	return slices.Contains(l.names(), name)
}

// without returns the list's source with the entries naming name
// removed, each with its comma, and with its line when it had one to
// itself.
func (l *profileCredentials) without(name string) []byte {
	src := slices.Clone(l.src)
	for i := len(l.entries) - 1; i >= 0; i-- {
		e := l.entries[i]
		if e.name != name {
			continue
		}
		start, end := e.start, e.end
		afterComma := end
		if j := skipBlanks(src, end); j < len(src) && src[j] == ',' {
			afterComma = j + 1
		}
		ls, le := lineStart(src, start), lineEnd(src, afterComma)
		switch {
		case isBlank(src[ls:start]) && isBlankOrComment(src[afterComma:le]) && le < len(src):
			// Alone on its line: the line goes, with the entry's comment.
			start, end = ls, le+1
		case afterComma != end:
			end = skipBlanks(src, afterComma)
		default:
			if k := lastNonBlank(src, start); k >= 0 && src[k] == ',' {
				start = k
			}
		}
		src = append(src[:start:start], src[end:]...)
	}
	return src
}

// with returns the list's source with ref appended: on a line of its
// own in a multi-line list, after ", " in a one-line list.
func (l *profileCredentials) with(ref string) []byte {
	src := slices.Clone(l.src)
	closeAt := l.closeAt
	if len(l.entries) == 0 {
		return slices.Concat(src[:closeAt], []byte(ref), src[closeAt:])
	}
	last := l.entries[len(l.entries)-1]
	comma := skipBlanks(src, last.end)
	trailingComma := comma < len(src) && src[comma] == ','
	if !trailingComma {
		src = slices.Concat(src[:last.end], []byte(","), src[last.end:])
		comma, closeAt = last.end, closeAt+1
	}
	if !bytes.Contains(src[:closeAt], []byte("\n")) {
		return slices.Concat(src[:comma+1], []byte(" "+ref), src[comma+1:])
	}
	indent := src[lineStart(src, last.start):last.start]
	if !isBlank(indent) {
		indent = []byte("  ")
	}
	entry := "\n" + string(indent) + ref
	if trailingComma {
		entry += ","
	}
	at := min(lineEnd(src, comma+1), closeAt)
	return slices.Concat(src[:at], []byte(entry), src[at:])
}

func skipBlanks(src []byte, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	return i
}

func lastNonBlank(src []byte, i int) int {
	for i--; i >= 0 && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n'); i-- {
	}
	return i
}

func lineStart(src []byte, i int) int {
	return bytes.LastIndexByte(src[:i], '\n') + 1
}

func lineEnd(src []byte, i int) int {
	if j := bytes.IndexByte(src[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(src)
}

func isBlank(b []byte) bool {
	return len(bytes.Trim(b, " \t")) == 0
}

func isBlankOrComment(b []byte) bool {
	b = bytes.Trim(b, " \t")
	return len(b) == 0 || b[0] == '#' || bytes.HasPrefix(b, []byte("//"))
}

// setProfileCredentialsSource replaces a profile's `credentials` list
// with src.
func setProfileCredentialsSource(profile *hclwrite.Block, src []byte) error {
	f, diags := hclwrite.ParseConfig(slices.Concat([]byte("credentials = "), src, []byte("\n")), "", hcl.InitialPos)
	if diags.HasErrors() {
		return fmt.Errorf("profile %q: edited credentials list does not parse: %s", profile.Labels()[0], diags.Error())
	}
	profile.Body().SetAttributeRaw("credentials", f.Body().GetAttribute("credentials").Expr().BuildTokens(nil))
	return nil
}

// appendBlock appends a block to a file, after a blank line unless
// the file is empty.
func appendBlock(f *hclwrite.File, blockType string, labels []string) *hclwrite.Block {
	if len(bytes.TrimSpace(f.Bytes())) > 0 {
		f.Body().AppendNewline()
	}
	return f.Body().AppendNewBlock(blockType, labels)
}

func entityRef(typ, name string) hcl.Traversal {
	return hcl.Traversal{hcl.TraverseRoot{Name: typ}, hcl.TraverseAttr{Name: name}}
}

// setCredentialProfiles makes exactly the profiles in want list the
// credential: it is appended to the lists that lack it and dropped
// from the others.
func (t *configTree) setCredentialProfiles(credType, credName string, want []string) error {
	wanted := map[string]bool{}
	for _, p := range want {
		wanted[p] = true
	}
	_, profiles := t.blocks("profile")
	for _, profile := range profiles {
		labels := profile.Labels()
		if len(labels) != 1 {
			continue
		}
		list, err := parseProfileCredentials(profile)
		if err != nil {
			// The form cannot read this list, so it leaves it alone; a
			// request to add the credential to it is refused. If the
			// list still names a removed credential, the reload says so.
			if wanted[labels[0]] {
				return fmt.Errorf("%w: profile %q: %v; change it in the config", errBadCredentialRequest, labels[0], err)
			}
			continue
		}
		has := list.has(credName)
		switch {
		case wanted[labels[0]] && !has:
			err = setProfileCredentialsSource(profile, list.with(credType+"."+credName))
		case !wanted[labels[0]] && has:
			err = setProfileCredentialsSource(profile, list.without(credName))
		}
		if err != nil {
			return err
		}
		delete(wanted, labels[0])
	}
	if len(wanted) > 0 {
		missing := make([]string, 0, len(wanted))
		for p := range wanted {
			missing = append(missing, p)
		}
		sort.Strings(missing)
		return fmt.Errorf("%w: no such profile: %s", errBadCredentialRequest, strings.Join(missing, ", "))
	}
	return nil
}

// endpointHost reduces a URL or a host to the lowercase host an https
// endpoint matches.
func endpointHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("%w: host: %v", errBadCredentialRequest, err)
		}
		if u.Scheme != "https" {
			return "", fmt.Errorf("%w: host: only https URLs can be declared here", errBadCredentialRequest)
		}
		if port := u.Port(); port != "" && port != "443" {
			return "", fmt.Errorf("%w: host: a port other than 443 needs an endpoint written in the config", errBadCredentialRequest)
		}
		raw = u.Hostname()
	}
	host := strings.ToLower(strings.TrimSuffix(raw, "."))
	if !endpointHostRE.MatchString(host) {
		return "", fmt.Errorf("%w: host %q is not a DNS name", errBadCredentialRequest, raw)
	}
	return host, nil
}

// credentialEndpointRef resolves the endpoint a credential should bind:
// an existing endpoint by name, or a new https endpoint declared in
// target. It returns nil when the request names neither.
func (t *configTree) credentialEndpointRef(gw *config.Gateway, typ credentialTypeOption, req credentialConfigRequest, target string) (hcl.Traversal, error) {
	if req.NewEndpoint != nil {
		name := req.NewEndpoint.Name
		if !configNameRE.MatchString(name) {
			return nil, fmt.Errorf("%w: endpoint name %q: use letters, digits, - and _, starting with a letter", errBadCredentialRequest, name)
		}
		if _, exists := gw.Policy.Endpoints[name]; exists {
			return nil, fmt.Errorf("%w: an endpoint named %q already exists", errBadCredentialRequest, name)
		}
		if !slices.Contains(typ.Families, "http") {
			return nil, fmt.Errorf("%w: a %s credential cannot bind an https endpoint", errBadCredentialRequest, typ.Type)
		}
		host, err := endpointHost(req.NewEndpoint.Host)
		if err != nil {
			return nil, err
		}
		f, err := t.file(target)
		if err != nil {
			return nil, err
		}
		if err := t.declareEndpoint(gw, f, name, host); err != nil {
			return nil, err
		}
		return entityRef(newEndpointType, name), nil
	}
	if req.Endpoint == nil {
		return nil, nil
	}
	ent := gw.Policy.Endpoints[*req.Endpoint]
	if ent == nil || ent.Symbol == nil {
		return nil, fmt.Errorf("%w: no such endpoint %q", errBadCredentialRequest, *req.Endpoint)
	}
	if !slices.Contains(typ.Families, ent.Symbol.Family) {
		return nil, fmt.Errorf("%w: a %s credential cannot bind the %s endpoint %q", errBadCredentialRequest, typ.Type, ent.Symbol.Type, *req.Endpoint)
	}
	return entityRef(ent.Symbol.Type, *req.Endpoint), nil
}

// declareEndpoint appends an https endpoint for host to f, then a rule
// for each defaults.new_endpoint_rule, so the endpoint never loads
// without them.
func (t *configTree) declareEndpoint(gw *config.Gateway, f *hclwrite.File, name, host string) error {
	blk := appendBlock(f, "endpoint", []string{newEndpointType, name})
	blk.Body().SetAttributeValue("hosts", cty.ListVal([]cty.Value{cty.StringVal(host)}))
	for _, def := range t.newEndpointRules() {
		ruleName := newEndpointRuleName(name, def.Labels()[0])
		if _, exists := gw.Policy.Rules[ruleName]; exists {
			return fmt.Errorf("%w: endpoint %q would add the rule %q, which already exists", errBadCredentialRequest, name, ruleName)
		}
		rule := appendBlock(f, "rule", []string{ruleName})
		rule.Body().SetAttributeTraversal("endpoint", entityRef(newEndpointType, name))
		body := def.Body().BuildTokens(nil)
		for len(body) > 0 && body[0].Type == hclsyntax.TokenNewline {
			body = body[1:]
		}
		rule.Body().AppendUnstructuredTokens(body)
	}
	return nil
}

// newEndpointRules returns the defaults.new_endpoint_rule blocks in
// declaration order.
func (t *configTree) newEndpointRules() []*hclwrite.Block {
	var rules []*hclwrite.Block
	_, defaults := t.blocks("defaults")
	for _, d := range defaults {
		for _, blk := range d.Body().Blocks() {
			if blk.Type() == "new_endpoint_rule" && len(blk.Labels()) == 1 {
				rules = append(rules, blk)
			}
		}
	}
	return rules
}

func newEndpointRuleName(endpoint, rule string) string {
	return endpoint + "-" + rule
}

// newEndpointRuleProbe names the endpoint checkNewEndpointRules
// declares; a number is appended while the config already has one.
const newEndpointRuleProbe = "new-endpoint-rule-probe"

// checkNewEndpointRules declares a probe endpoint in the config at path
// the way the dashboard declares a new host, and loads the result. A
// defaults.new_endpoint_rule that cannot become a rule then fails this
// load, not the first host added on the dashboard.
func checkNewEndpointRules(path string, gw *config.Gateway) error {
	if gw.Defaults == nil || len(gw.Defaults.NewEndpointRules) == 0 {
		return nil
	}
	tree, err := loadConfigTree(path)
	if err != nil {
		return err
	}
	target, _, err := resolveConfigFile(path, "")
	if err != nil {
		return err
	}
	f, err := tree.file(target)
	if err != nil {
		return err
	}
	name := newEndpointRuleProbe
	for i := 2; gw.Policy.Endpoints[name] != nil; i++ {
		name = fmt.Sprintf("%s%d", newEndpointRuleProbe, i)
	}
	if err := tree.declareEndpoint(gw, f, name, "probe.invalid"); err != nil {
		return fmt.Errorf("defaults.new_endpoint_rule: %w", err)
	}
	if configIsDir(path) {
		overrides := map[string][]byte{}
		for _, c := range tree.changes(target, "") {
			overrides[c.Name] = c.Content
		}
		_, _, err = loadConfigOverlay(path, overrides)
	} else {
		var tmpPath string
		tmpPath, err = writeTempConfig(filepath.Dir(path), f.Bytes())
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(tmpPath) }()
		probed, diags := config.Load(tmpPath)
		_, _, err = compileLoadedConfig(probed, diags)
	}
	if err != nil {
		return fmt.Errorf("defaults.new_endpoint_rule: a new endpoint with these rules would not load: %w", err)
	}
	return nil
}

// setCredentialFields applies the request's type-specific settings to
// a credential block.
func setCredentialFields(blk *hclwrite.Block, typ credentialTypeOption, req credentialConfigRequest) error {
	if !slices.Contains(typ.Fields, "header") && (req.Header != nil || req.Prefix != nil) {
		return fmt.Errorf("%w: a %s credential has no header settings", errBadCredentialRequest, typ.Type)
	}
	if req.Header != nil {
		if !httpguts.ValidHeaderFieldName(*req.Header) {
			return fmt.Errorf("%w: %q is not an HTTP header name", errBadCredentialRequest, *req.Header)
		}
		blk.Body().SetAttributeValue("header", cty.StringVal(*req.Header))
	}
	if req.Prefix != nil {
		if strings.ContainsAny(*req.Prefix, "\r\n") {
			return fmt.Errorf("%w: the prefix must be one line", errBadCredentialRequest)
		}
		if *req.Prefix == "" {
			blk.Body().RemoveAttribute("prefix")
		} else {
			blk.Body().SetAttributeValue("prefix", cty.StringVal(*req.Prefix))
		}
	}
	return nil
}

type credentialConfigFile struct {
	Name     string `json:"name"`
	File     string `json:"file"`
	ReadOnly bool   `json:"read_only"`
}

type credentialConfigProfile struct {
	credentialConfigFile
	Credentials []string `json:"credentials"`
}

type credentialConfigEndpoint struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Family string `json:"family"`
	Hosts  string `json:"hosts,omitempty"`
}

type credentialConfigEntry struct {
	credentialConfigFile
	Type     string `json:"type"`
	Endpoint string `json:"endpoint,omitempty"`
	Header   string `json:"header,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

// apiCredentialOptions lists what the credential form needs: the types
// it declares, the endpoints and profiles to pick from, where each
// credential and profile is declared, so the form can tell which ones
// it may change, and the rules a new host gets. The loaded config and the files are read under the
// config lock, so both describe the same revision.
func (w *webMux) apiCredentialOptions(rw http.ResponseWriter, r *http.Request) {
	w.g.configMu.Lock()
	gw := w.g.cfg.Load()
	tree, err := loadConfigTree(w.g.cfgPath)
	target, _, terr := resolveConfigFile(w.g.cfgPath, "")
	w.g.configMu.Unlock()
	if gw == nil || gw.Policy == nil {
		http.Error(rw, "no config loaded", http.StatusServiceUnavailable)
		return
	}
	if err == nil {
		err = terr
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	endpoints := []credentialConfigEndpoint{}
	for name, ent := range gw.Policy.Endpoints {
		if ent == nil || ent.Symbol == nil {
			continue
		}
		ep := credentialConfigEndpoint{Name: name, Type: ent.Symbol.Type, Family: ent.Symbol.Family}
		ep.Hosts = credentialConfig(ent, name)["hosts"]
		endpoints = append(endpoints, ep)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].Name < endpoints[j].Name })

	profiles := []credentialConfigProfile{}
	files, blocks := tree.blocks("profile")
	for i, blk := range blocks {
		labels := blk.Labels()
		if len(labels) != 1 {
			continue
		}
		prof := credentialConfigProfile{
			credentialConfigFile: credentialConfigFile{Name: labels[0], File: files[i], ReadOnly: tree.readOnly(files[i])},
			Credentials:          []string{},
		}
		if list, err := parseProfileCredentials(blk); err == nil {
			prof.Credentials = list.names()
		} else {
			// A list the form cannot read is one it cannot change.
			prof.ReadOnly = true
		}
		profiles = append(profiles, prof)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	declaredIn := map[string]string{}
	files, blocks = tree.blocks("credential")
	for i, blk := range blocks {
		if labels := blk.Labels(); len(labels) == 2 {
			if _, seen := declaredIn[labels[1]]; !seen {
				declaredIn[labels[1]] = files[i]
			}
		}
	}
	creds := map[string]credentialConfigEntry{}
	for name, ent := range gw.Policy.Credentials {
		if ent == nil || ent.Symbol == nil {
			continue
		}
		file := declaredIn[name]
		entry := credentialConfigEntry{
			credentialConfigFile: credentialConfigFile{Name: name, File: file, ReadOnly: file == "" || tree.readOnly(file)},
			Type:                 ent.Symbol.Type,
		}
		if targets := config.CredentialEndpointTargets(ent); len(targets) == 1 {
			entry.Endpoint = targets[0]
		}
		if h, ok := ent.Body.(*credentials.HeaderToken); ok {
			entry.Header, entry.Prefix = h.Header, h.Prefix
		}
		creds[name] = entry
	}

	newEndpointRules := []string{}
	for _, def := range tree.newEndpointRules() {
		newEndpointRules = append(newEndpointRules, def.Labels()[0])
	}

	writeJSON(rw, map[string]any{
		"writes":             gw.DashboardConfigWrites(),
		"file":               target,
		"types":              editableCredentialTypes,
		"endpoints":          endpoints,
		"profiles":           profiles,
		"credentials":        creds,
		"new_endpoint_rules": newEndpointRules,
	})
}

// credentialPlan is a planned credential change: the files to write,
// and what to do just before and just after writing them, still under
// the config lock.
type credentialPlan struct {
	changes []configChange
	before  func() error
	after   func() error
	// secretCleared tells the form the credential needs its secret again.
	secretCleared bool
}

// apiCredentialDeclare declares a credential in the dashboard's file,
// optionally with a new https endpoint for it, and adds it to the
// requested profiles wherever they are declared.
func (w *webMux) apiCredentialDeclare(rw http.ResponseWriter, r *http.Request) {
	w.editCredentialConfig(rw, r, func(tree *configTree, gw *config.Gateway, req credentialConfigRequest) (credentialPlan, error) {
		typ, ok := editableCredentialType(req.Type)
		if !ok {
			return credentialPlan{}, fmt.Errorf("%w: the form cannot declare a %q credential", errBadCredentialRequest, req.Type)
		}
		if !configNameRE.MatchString(req.Name) {
			return credentialPlan{}, fmt.Errorf("%w: credential name %q: use letters, digits, - and _, starting with a letter", errBadCredentialRequest, req.Name)
		}
		if _, exists := gw.Policy.Credentials[req.Name]; exists {
			return credentialPlan{}, fmt.Errorf("%w: a credential named %q already exists", errBadCredentialRequest, req.Name)
		}
		if slices.Contains(typ.Fields, "header") && (req.Header == nil || *req.Header == "") {
			return credentialPlan{}, fmt.Errorf("%w: a %s credential needs a header", errBadCredentialRequest, typ.Type)
		}
		target, _, err := resolveConfigFile(w.g.cfgPath, "")
		if err != nil {
			return credentialPlan{}, err
		}
		ref, err := tree.credentialEndpointRef(gw, typ, req, target)
		if err != nil {
			return credentialPlan{}, err
		}
		if ref == nil {
			return credentialPlan{}, fmt.Errorf("%w: pick an endpoint or declare a new host", errBadCredentialRequest)
		}
		f, err := tree.file(target)
		if err != nil {
			return credentialPlan{}, err
		}
		blk := appendBlock(f, "credential", []string{typ.Type, req.Name})
		if err := setCredentialFields(blk, typ, req); err != nil {
			return credentialPlan{}, err
		}
		blk.Body().SetAttributeTraversal("endpoint", ref)
		var profiles []string
		if req.Profiles != nil {
			profiles = *req.Profiles
		}
		if err := tree.setCredentialProfiles(typ.Type, req.Name, profiles); err != nil {
			return credentialPlan{}, err
		}
		// A secret left under this name by an earlier credential must
		// never become the new one's, not even for the first requests.
		return credentialPlan{changes: tree.changes(target, ""), before: w.clearCredentialState(req.Name), secretCleared: true}, nil
	})
}

// apiCredentialEdit changes a credential's settings, its endpoint, or
// the profiles that list it. Settings and endpoint change only for the
// types the form declares; profiles change for any credential.
func (w *webMux) apiCredentialEdit(rw http.ResponseWriter, r *http.Request) {
	w.editCredentialConfig(rw, r, func(tree *configTree, gw *config.Gateway, req credentialConfigRequest) (credentialPlan, error) {
		file, blk := tree.find("credential", req.Name)
		if blk == nil || len(blk.Labels()) != 2 {
			return credentialPlan{}, fmt.Errorf("%w %q", errNoSuchCredential, req.Name)
		}
		credType := blk.Labels()[0]
		target, _, err := resolveConfigFile(w.g.cfgPath, "")
		if err != nil {
			return credentialPlan{}, err
		}
		settings := req.Header != nil || req.Prefix != nil || req.Endpoint != nil || req.NewEndpoint != nil
		rebound := false
		if settings {
			typ, ok := editableCredentialType(credType)
			if !ok {
				return credentialPlan{}, fmt.Errorf("%w: the form cannot change a %s credential's settings; change them in %s", errBadCredentialRequest, credType, file)
			}
			if err := setCredentialFields(blk, typ, req); err != nil {
				return credentialPlan{}, err
			}
			ref, err := tree.credentialEndpointRef(gw, typ, req, target)
			if err != nil {
				return credentialPlan{}, err
			}
			if ref != nil {
				blk.Body().RemoveAttribute("endpoints")
				blk.Body().SetAttributeTraversal("endpoint", ref)
				current := config.CredentialEndpointTargets(gw.Policy.Credentials[req.Name])
				newEndpoint := ref[len(ref)-1].(hcl.TraverseAttr).Name
				rebound = len(current) != 1 || current[0] != newEndpoint
			}
		}
		if req.Profiles != nil {
			if err := tree.setCredentialProfiles(credType, req.Name, *req.Profiles); err != nil {
				return credentialPlan{}, err
			}
		}
		first := file
		if req.NewEndpoint != nil {
			// The new endpoint's file lands before the credential
			// that references it.
			first = target
		}
		p := credentialPlan{changes: tree.changes(first, "")}
		switch {
		case rebound:
			// The secret was issued for the old endpoint's host: it must
			// never reach the new one, so it goes before the change is live.
			p.before, p.secretCleared = w.clearCredentialState(req.Name), true
		case settings:
			// The last verification checked the old header.
			p.after = func() error {
				defer w.lockCredentialSave(req.Name)()
				return clearCredentialVerification(w.g.db, req.Name)
			}
		}
		return p, nil
	})
}

// apiCredentialRemove removes a credential's block and its entries in
// profile lists, then clears its stored secret. Only the types the
// form declares can be removed: their secret is a plain slot. Removing a
// name the config no longer declares clears what is still stored under
// it, so a remove whose clear failed can be retried.
func (w *webMux) apiCredentialRemove(rw http.ResponseWriter, r *http.Request) {
	w.editCredentialConfig(rw, r, func(tree *configTree, gw *config.Gateway, req credentialConfigRequest) (credentialPlan, error) {
		file, blk := tree.find("credential", req.Name)
		if blk == nil && gw.Policy.Credentials[req.Name] == nil && configNameRE.MatchString(req.Name) {
			return credentialPlan{after: w.clearCredentialState(req.Name), secretCleared: true}, nil
		}
		if blk == nil || len(blk.Labels()) != 2 {
			return credentialPlan{}, fmt.Errorf("%w %q", errNoSuchCredential, req.Name)
		}
		credType := blk.Labels()[0]
		if _, ok := editableCredentialType(credType); !ok {
			return credentialPlan{}, fmt.Errorf("%w: the form cannot remove a %s credential; remove it from %s", errBadCredentialRequest, credType, file)
		}
		if err := tree.setCredentialProfiles(credType, req.Name, nil); err != nil {
			return credentialPlan{}, err
		}
		tree.files[file].Body().RemoveBlock(blk)
		return credentialPlan{changes: tree.changes("", file), after: w.clearCredentialState(req.Name), secretCleared: true}, nil
	})
}

// clearCredentialState returns a step that drops everything stored for
// a credential name: its secret slots, an OAuth token (the secret store
// falls back to one under the same name) and its verification result.
// It runs under the config lock, so no credential of that name can be
// declared and given a secret meanwhile.
func (w *webMux) clearCredentialState(name string) func() error {
	return func() error {
		defer w.lockCredentialSave(name)()
		if err := clearCredentialSecrets(w.g.db, name); err != nil {
			return fmt.Errorf("clear the stored secret of %s: %w", name, err)
		}
		if w.g.oauth != nil {
			w.g.oauth.Revoke(name)
		}
		if _, err := w.g.db.Exec("DELETE FROM credentials WHERE id=?", name); err != nil {
			return fmt.Errorf("clear the stored OAuth token of %s: %w", name, err)
		}
		if err := clearCredentialVerification(w.g.db, name); err != nil {
			return fmt.Errorf("clear the verification result of %s: %w", name, err)
		}
		return nil
	}
}

// editCredentialConfig decodes a credential request, plans the change
// with the config lock held, writes it, runs the plan's after step and
// answers.
func (w *webMux) editCredentialConfig(rw http.ResponseWriter, r *http.Request,
	plan func(*configTree, *config.Gateway, credentialConfigRequest) (credentialPlan, error)) {
	var req credentialConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, credentialConfigMaxBytes)).Decode(&req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	setAuditTarget(r, req.Name)

	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	gw := w.g.cfg.Load()
	if !gw.DashboardConfigWrites() {
		http.Error(rw, errConfigWritesDisabled.Error(), http.StatusForbidden)
		return
	}
	if gw.Policy == nil {
		http.Error(rw, "no config loaded", http.StatusServiceUnavailable)
		return
	}
	tree, err := loadConfigTree(w.g.cfgPath)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	p, err := plan(tree, gw, req)
	switch {
	case errors.Is(err, errNoSuchCredential):
		http.Error(rw, err.Error(), http.StatusNotFound)
		return
	case errors.Is(err, errBadCredentialRequest):
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	files := make([]string, 0, len(p.changes))
	for _, c := range p.changes {
		files = append(files, c.Name)
	}
	if p.before != nil {
		if err := p.before(); err != nil {
			http.Error(rw, "nothing was written: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if len(p.changes) > 0 && !w.applyConfigChanges(rw, p.changes) {
		return
	}
	if p.after != nil {
		if err := p.after(); err != nil {
			log.Printf("credentials: %s written, then: %v", req.Name, err)
			http.Error(rw, "the config change was written, but "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(rw, map[string]any{"ok": true, "name": req.Name, "files": files, "secret_cleared": p.secretCleared})
}
