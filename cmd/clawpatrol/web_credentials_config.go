package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/net/http/httpguts"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/credentials"
	"github.com/denoland/clawpatrol/internal/config/plugins/rules"
)

// credentialConfigMaxBytes bounds a credential declaration request.
const credentialConfigMaxBytes = 16 << 10

// newEndpointType is the endpoint type the dashboard declares for a
// host.
const newEndpointType = "https"

var (
	// configNameRE is what the form accepts as a credential name: an HCL
	// identifier, so `<type>.<name>` stays a reference.
	configNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

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
	Type     string    `json:"type,omitempty"`
	Name     string    `json:"name"`
	Header   *string   `json:"header,omitempty"`
	Prefix   *string   `json:"prefix,omitempty"`
	Endpoint *string   `json:"endpoint,omitempty"`
	Profiles *[]string `json:"profiles,omitempty"`
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
	paths := &configTree{cfgPath: cfgPath}
	sources := map[string][]byte{}
	for _, info := range infos {
		if sources[info.Name], err = readConfigFileOrEmpty(paths.path(info.Name)); err != nil {
			return nil, err
		}
	}
	return newConfigTree(cfgPath, sources)
}

func (t *configTree) path(name string) string {
	if configIsDir(t.cfgPath) {
		return filepath.Join(t.cfgPath, name)
	}
	return t.cfgPath
}

func newConfigTree(cfgPath string, sources map[string][]byte) (*configTree, error) {
	t := &configTree{cfgPath: cfgPath, files: map[string]*hclwrite.File{}, orig: map[string][]byte{}, ro: map[string]bool{}}
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		if err := t.addContent(name, sources[name]); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *configTree) add(name string) error {
	content, err := readConfigFileOrEmpty(t.path(name))
	if err != nil {
		return err
	}
	return t.addContent(name, content)
}

func (t *configTree) addContent(name string, content []byte) error {
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
	return parseCredentialList(src, profile.Labels()[0])
}

func parseCredentialList(src []byte, profile string) (*profileCredentials, error) {
	expr, diags := hclsyntax.ParseExpression(src, "", hcl.InitialPos)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	tuple, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return nil, fmt.Errorf("profile %q: credentials is not a list", profile)
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

// placeholderSwap is how the passthrough placeholders the dashboard
// adds with a host follow a credential change.
type placeholderSwap struct {
	// replace are the placeholders of the endpoint the credential binds:
	// a profile that gains it, or keeps it while it moves, drops them.
	replace []string
	// restore is the placeholder of the endpoint it bound before the
	// change: a profile that loses it, or keeps it while it moves, gets
	// it back, so that endpoint stays claimed with its rules.
	restore string
	rebound bool
}

// setCredentialProfiles makes exactly the profiles in want list the
// credential, moving placeholders as swap says. It returns the
// placeholders each profile dropped.
func (t *configTree) setCredentialProfiles(credType, credName string, want []string, swap placeholderSwap) (map[string][]string, error) {
	wanted := map[string]bool{}
	for _, p := range want {
		wanted[p] = true
	}
	ref := credType + "." + credName
	replaced := map[string][]string{}
	files, profiles := t.blocks("profile")
	for i, profile := range profiles {
		labels := profile.Labels()
		if len(labels) != 1 {
			continue
		}
		name := labels[0]
		list, err := parseProfileCredentials(profile)
		if err != nil {
			// The form cannot read this list, so it leaves it alone; a
			// request to add the credential to it is refused. If the
			// list still names a removed credential, the reload says so.
			if wanted[name] {
				return nil, fmt.Errorf("%w: profile %q: %v; change it in the config", errBadCredentialRequest, name, err)
			}
			continue
		}
		has := list.has(credName)
		var drop []string
		restore := !wanted[name] && has || wanted[name] && has && swap.rebound
		if wanted[name] && (!has || swap.rebound) {
			drop = slices.DeleteFunc(slices.Clone(swap.replace), func(p string) bool { return !list.has(p) })
		}
		restore = restore && swap.restore != "" && !list.has(swap.restore)
		var edits []string
		if wanted[name] && !has {
			edits = append(edits, "add "+ref)
		}
		if !wanted[name] && has {
			edits = append(edits, "remove "+ref)
		}
		for _, p := range drop {
			edits = append(edits, "remove passthrough."+p)
		}
		if restore {
			edits = append(edits, "add passthrough."+swap.restore)
		}
		if len(edits) > 0 && t.readOnly(files[i]) {
			return nil, fmt.Errorf("%w: profile %q is declared in %s, which the dashboard does not change: change its credentials list in that file (%s)",
				errBadCredentialRequest, name, files[i], strings.Join(edits, " and "))
		}
		for _, p := range drop {
			if list, err = parseCredentialList(list.without(p), name); err != nil {
				return nil, err
			}
		}
		if restore {
			if list, err = parseCredentialList(list.with("passthrough."+swap.restore), name); err != nil {
				return nil, err
			}
		}
		switch {
		case wanted[name] && !has:
			err = setProfileCredentialsSource(profile, list.with(ref))
		case !wanted[name] && has:
			err = setProfileCredentialsSource(profile, list.without(credName))
		case len(edits) > 0:
			err = setProfileCredentialsSource(profile, list.src)
		}
		if err != nil {
			return nil, err
		}
		if len(drop) > 0 {
			replaced[name] = drop
		}
		delete(wanted, name)
	}
	if len(wanted) > 0 {
		missing := make([]string, 0, len(wanted))
		for p := range wanted {
			missing = append(missing, p)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: no such profile: %s", errBadCredentialRequest, strings.Join(missing, ", "))
	}
	return replaced, nil
}

// placeholders are the passthrough credentials the dashboard added with
// endpoint (generatedPassthroughCredName), other than except.
func placeholders(gw *config.Gateway, endpoint, except string) []string {
	var names []string
	for name, ent := range gw.Policy.Credentials {
		if name == except || ent == nil || ent.Symbol == nil || ent.Symbol.Type != "passthrough" {
			continue
		}
		base := endpoint + "_passthrough"
		if suffix, ok := strings.CutPrefix(name, base+"_"); name != base && (!ok || strings.Trim(suffix, "0123456789") != "") {
			continue
		}
		if targets := config.CredentialEndpointTargets(ent); len(targets) == 1 && targets[0] == endpoint {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// placeholderFor is the placeholder a profile gets back when it stops
// reaching endpoint through except, or "".
func placeholderFor(gw *config.Gateway, endpoint, except string) string {
	if p := placeholders(gw, endpoint, except); len(p) > 0 {
		return p[0]
	}
	return ""
}

// checkReplacedCredentials refuses a swap that would stop a rule: a
// rule pinned to a profile and a credential the profile no longer
// lists never matches again.
func checkReplacedCredentials(gw *config.Gateway, replaced map[string][]string) error {
	for name, ent := range gw.Policy.Rules {
		r, ok := ent.Body.(*rules.Rule)
		if !ok || r.Credential == "" {
			continue
		}
		for profile, creds := range replaced {
			if (r.Profile == "" || r.Profile == profile) && slices.Contains(creds, r.Credential) {
				return fmt.Errorf("%w: rule %q is pinned to %s, which this change removes from profile %q, so the rule would stop matching; change or remove the rule first",
					errBadCredentialRequest, name, r.Credential, profile)
			}
		}
	}
	return nil
}

// credentialEndpointRef resolves the endpoint a credential should bind,
// or nil when the request names none.
func credentialEndpointRef(gw *config.Gateway, typ credentialTypeOption, req credentialConfigRequest) (hcl.Traversal, error) {
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
// for each defaults.new_endpoint_rule, as a host added from a request
// gets them.
func (t *configTree) declareEndpoint(gw *config.Gateway, f *hclwrite.File, name, host string) error {
	blk := appendBlock(f, "endpoint", []string{newEndpointType, name})
	blk.Body().SetAttributeValue("hosts", cty.ListVal([]cty.Value{cty.StringVal(host)}))
	names, err := appendNewEndpointRules(f, name, t.newEndpointRules())
	if err != nil {
		return err
	}
	return checkNewEndpointRuleNames(gw, name, names)
}

func checkNewEndpointRuleNames(gw *config.Gateway, endpoint string, names []string) error {
	for _, name := range names {
		if _, exists := gw.Policy.Rules[name]; exists {
			return fmt.Errorf("endpoint %q would add the rule %q, which already exists", endpoint, name)
		}
	}
	return nil
}

// appendNewEndpointRules appends a rule for endpoint to f for each
// defaults.new_endpoint_rule, its body copied as written, and returns
// their names.
func appendNewEndpointRules(f *hclwrite.File, endpoint string, defs []*hclwrite.Block) ([]string, error) {
	var names []string
	for _, def := range defs {
		ruleName := newEndpointRuleName(endpoint, def.Labels()[0])
		if slices.Contains(names, ruleName) {
			return nil, fmt.Errorf("defaults declares new_endpoint_rule %q more than once", def.Labels()[0])
		}
		names = append(names, ruleName)
		rule := appendBlock(f, "rule", []string{ruleName})
		rule.Body().SetAttributeTraversal("endpoint", entityRef(newEndpointType, endpoint))
		// Copies: formatting the file rewrites tokens' spacing in place,
		// which would re-indent the defaults block too.
		var body hclwrite.Tokens
		for _, tok := range def.Body().BuildTokens(nil) {
			body = append(body, &hclwrite.Token{Type: tok.Type, Bytes: slices.Clone(tok.Bytes), SpacesBefore: tok.SpacesBefore})
		}
		for len(body) > 0 && body[0].Type == hclsyntax.TokenNewline {
			body = body[1:]
		}
		if last := len(body) - 1; last >= 0 && body[last].Type != hclsyntax.TokenNewline &&
			!(body[last].Type == hclsyntax.TokenComment && bytes.HasSuffix(body[last].Bytes, []byte("\n"))) {
			// A one-line block's body ends at its closing brace; a line
			// comment already ends its line.
			body = append(body, &hclwrite.Token{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")})
		}
		rule.Body().AppendUnstructuredTokens(body)
	}
	return names, nil
}

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

const newEndpointRuleProbe = "new-endpoint-rule-probe"

// checkNewEndpointRules declares a probe endpoint in the config's
// sources the way the dashboard declares a new host, and loads the
// result. A defaults.new_endpoint_rule that cannot become a rule then
// fails this load, not the first host added on the dashboard.
func checkNewEndpointRules(path string, sources map[string][]byte, gw *config.Gateway) error {
	if gw.Defaults == nil || len(gw.Defaults.NewEndpointRules) == 0 {
		return nil
	}
	sum := configSourcesSum(path, sources, configIsDir(path))
	newEndpointRulesChecked.Lock()
	defer newEndpointRulesChecked.Unlock()
	if newEndpointRulesChecked.sum == sum {
		return nil
	}
	tree, err := newConfigTree(path, sources)
	if err != nil {
		return err
	}
	target, _, err := resolveConfigFile(path, "")
	if err != nil {
		return err
	}
	if _, ok := tree.files[target]; !ok {
		if err := tree.addContent(target, nil); err != nil {
			return err
		}
	}
	name := newEndpointRuleProbe
	for i := 2; probeNameTaken(tree, gw, name); i++ {
		name = fmt.Sprintf("%s%d", newEndpointRuleProbe, i)
	}
	if err := tree.declareEndpoint(gw, tree.files[target], name, "probe.invalid"); err != nil {
		return fmt.Errorf("defaults.new_endpoint_rule: %w", err)
	}
	probe := maps.Clone(sources)
	for _, c := range tree.changes(target, "") {
		probe[c.Name] = c.Content
	}
	if _, _, err := compileConfigSources(path, probe); err != nil {
		// A single file may be a dashboard write's temporary copy.
		where := target
		if !configIsDir(path) {
			where = "the config file"
		}
		return fmt.Errorf("defaults.new_endpoint_rule: the rules a host added on the dashboard gets would not load "+
			"(checked by adding endpoint %q to %s in memory, so positions there are not in the file): %w", name, where, err)
	}
	newEndpointRulesChecked.sum = sum
	return nil
}

// newEndpointRulesChecked holds the sum of the last config that passed
// checkNewEndpointRules: a dashboard write validates a change, then
// reloads the same files, and the check runs once.
var newEndpointRulesChecked struct {
	sync.Mutex
	sum [sha256.Size]byte
}

// configSourcesSum identifies a config by its directory and contents.
// A single file's name is left out: a dashboard write validates it as
// a temporary file next to it, then reloads it under its own name.
func configSourcesSum(path string, sources map[string][]byte, isDir bool) [sha256.Size]byte {
	h := sha256.New()
	dir := path
	if !isDir {
		dir = filepath.Dir(path)
	}
	fmt.Fprintf(h, "%q %t\n", dir, isDir)
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		if isDir {
			fmt.Fprintf(h, "%q ", name)
		}
		fmt.Fprintf(h, "%d\n", len(sources[name]))
		h.Write(sources[name])
	}
	return [sha256.Size]byte(h.Sum(nil))
}

func probeNameTaken(tree *configTree, gw *config.Gateway, name string) bool {
	if gw.Policy.Endpoints[name] != nil {
		return true
	}
	for _, def := range tree.newEndpointRules() {
		if gw.Policy.Rules[newEndpointRuleName(name, def.Labels()[0])] != nil {
			return true
		}
	}
	return false
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
// it declares, the endpoints and profiles to pick from, and where each
// credential and profile is declared, so the form can tell which ones
// it may change. The loaded config and the files are read under the
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

	writeJSON(rw, map[string]any{
		"writes":      gw.DashboardConfigWrites(),
		"file":        target,
		"types":       editableCredentialTypes,
		"endpoints":   endpoints,
		"profiles":    profiles,
		"credentials": creds,
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

// apiCredentialDeclare declares a credential in the dashboard's file
// for an existing endpoint, and adds it to the requested profiles
// wherever they are declared.
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
		ref, err := credentialEndpointRef(gw, typ, req)
		if err != nil {
			return credentialPlan{}, err
		}
		if ref == nil {
			return credentialPlan{}, fmt.Errorf("%w: pick an endpoint; a host with none is added from a request to it in the log", errBadCredentialRequest)
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
		replaced, err := tree.setCredentialProfiles(typ.Type, req.Name, profiles, placeholderSwap{replace: placeholders(gw, *req.Endpoint, req.Name)})
		if err != nil {
			return credentialPlan{}, err
		}
		if err := checkReplacedCredentials(gw, replaced); err != nil {
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
		settings := req.Header != nil || req.Prefix != nil || req.Endpoint != nil
		rebound := false
		if settings {
			typ, ok := editableCredentialType(credType)
			if !ok {
				return credentialPlan{}, fmt.Errorf("%w: the form cannot change a %s credential's settings; change them in %s", errBadCredentialRequest, credType, file)
			}
			if err := setCredentialFields(blk, typ, req); err != nil {
				return credentialPlan{}, err
			}
			ref, err := credentialEndpointRef(gw, typ, req)
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
		profiles := req.Profiles
		if profiles == nil && rebound {
			// The profiles listing it keep it, and swap placeholders.
			listing := []string{}
			_, blocks := tree.blocks("profile")
			for _, profile := range blocks {
				if list, err := parseProfileCredentials(profile); err == nil && len(profile.Labels()) == 1 && list.has(req.Name) {
					listing = append(listing, profile.Labels()[0])
				}
			}
			profiles = &listing
		}
		if profiles != nil {
			current := ""
			if targets := config.CredentialEndpointTargets(gw.Policy.Credentials[req.Name]); len(targets) == 1 {
				current = targets[0]
			}
			endpoint := current
			if req.Endpoint != nil {
				endpoint = *req.Endpoint
			}
			swap := placeholderSwap{replace: placeholders(gw, endpoint, req.Name), restore: placeholderFor(gw, current, req.Name), rebound: rebound}
			replaced, err := tree.setCredentialProfiles(credType, req.Name, *profiles, swap)
			if err != nil {
				return credentialPlan{}, err
			}
			if err := checkReplacedCredentials(gw, replaced); err != nil {
				return credentialPlan{}, err
			}
		}
		p := credentialPlan{changes: tree.changes(file, "")}
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
		swap := placeholderSwap{}
		if targets := config.CredentialEndpointTargets(gw.Policy.Credentials[req.Name]); len(targets) == 1 {
			swap.restore = placeholderFor(gw, targets[0], req.Name)
		}
		if _, err := tree.setCredentialProfiles(credType, req.Name, nil, swap); err != nil {
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
