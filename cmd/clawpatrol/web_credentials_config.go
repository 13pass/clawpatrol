package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

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
	// httpHeaderNameRE is an RFC 9110 field name.
	httpHeaderNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
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
// Header, Prefix or Endpoint keeps the current value.
type credentialConfigRequest struct {
	Type        string              `json:"type,omitempty"`
	Name        string              `json:"name"`
	Header      *string             `json:"header,omitempty"`
	Prefix      *string             `json:"prefix,omitempty"`
	Endpoint    *string             `json:"endpoint,omitempty"`
	NewEndpoint *newEndpointRequest `json:"new_endpoint,omitempty"`
	Profiles    []string            `json:"profiles"`
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
}

func loadConfigTree(cfgPath string) (*configTree, error) {
	infos, err := configFiles(cfgPath)
	if err != nil {
		return nil, err
	}
	t := &configTree{cfgPath: cfgPath, files: map[string]*hclwrite.File{}, orig: map[string][]byte{}}
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
	return configFileReadOnly(t.orig[file])
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

// profileCredentialRefs returns the references in a profile block's
// `credentials` list.
func profileCredentialRefs(profile *hclwrite.Block) ([]hcl.Traversal, error) {
	attr := profile.Body().GetAttribute("credentials")
	if attr == nil {
		return nil, nil
	}
	src := attr.Expr().BuildTokens(nil).Bytes()
	expr, diags := hclsyntax.ParseExpression(src, "", hcl.InitialPos)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	tuple, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return nil, fmt.Errorf("profile %q: credentials is not a list", profile.Labels()[0])
	}
	refs := make([]hcl.Traversal, 0, len(tuple.Exprs))
	for _, item := range tuple.Exprs {
		ref, diags := hcl.AbsTraversalForExpr(item)
		if diags.HasErrors() {
			return nil, fmt.Errorf("profile %q: credentials holds something other than references", profile.Labels()[0])
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// appendBlock appends a block to a file, after a blank line unless
// the file is empty.
func appendBlock(f *hclwrite.File, blockType string, labels []string) *hclwrite.Block {
	if len(bytes.TrimSpace(f.Bytes())) > 0 {
		f.Body().AppendNewline()
	}
	return f.Body().AppendNewBlock(blockType, labels)
}

func setProfileCredentialRefs(profile *hclwrite.Block, refs []hcl.Traversal) {
	items := make([]hclwrite.Tokens, 0, len(refs))
	for _, ref := range refs {
		items = append(items, hclwrite.TokensForTraversal(ref))
	}
	profile.Body().SetAttributeRaw("credentials", hclwrite.TokensForTuple(items))
}

// refNames reports whether a reference's last step is name.
func refNames(ref hcl.Traversal, name string) bool {
	if len(ref) == 0 {
		return false
	}
	switch step := ref[len(ref)-1].(type) {
	case hcl.TraverseAttr:
		return step.Name == name
	case hcl.TraverseRoot:
		return step.Name == name
	}
	return false
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
		refs, err := profileCredentialRefs(profile)
		if err != nil {
			return err
		}
		has := slices.ContainsFunc(refs, func(ref hcl.Traversal) bool { return refNames(ref, credName) })
		switch {
		case wanted[labels[0]] && !has:
			setProfileCredentialRefs(profile, append(refs, entityRef(credType, credName)))
		case !wanted[labels[0]] && has:
			setProfileCredentialRefs(profile, slices.DeleteFunc(refs, func(ref hcl.Traversal) bool { return refNames(ref, credName) }))
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
		if u.Port() != "" {
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
		blk := appendBlock(f, "endpoint", []string{newEndpointType, name})
		blk.Body().SetAttributeValue("hosts", cty.ListVal([]cty.Value{cty.StringVal(host)}))
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

// setCredentialFields applies the request's type-specific settings to
// a credential block.
func setCredentialFields(blk *hclwrite.Block, typ credentialTypeOption, req credentialConfigRequest) error {
	if !slices.Contains(typ.Fields, "header") && (req.Header != nil || req.Prefix != nil) {
		return fmt.Errorf("%w: a %s credential has no header settings", errBadCredentialRequest, typ.Type)
	}
	if req.Header != nil {
		if !httpHeaderNameRE.MatchString(*req.Header) {
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
// it may change.
func (w *webMux) apiCredentialOptions(rw http.ResponseWriter, r *http.Request) {
	gw := w.g.cfg.Load()
	if gw == nil || gw.Policy == nil {
		http.Error(rw, "no config loaded", http.StatusServiceUnavailable)
		return
	}
	w.g.configMu.Lock()
	tree, err := loadConfigTree(w.g.cfgPath)
	target, _, terr := resolveConfigFile(w.g.cfgPath, "")
	w.g.configMu.Unlock()
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
		refs, err := profileCredentialRefs(blk)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, ref := range refs {
			if attr, ok := ref[len(ref)-1].(hcl.TraverseAttr); ok {
				prof.Credentials = append(prof.Credentials, attr.Name)
			}
		}
		profiles = append(profiles, prof)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	creds := map[string]credentialConfigEntry{}
	for name, ent := range gw.Policy.Credentials {
		if ent == nil || ent.Symbol == nil {
			continue
		}
		file, _ := tree.find("credential", name)
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

// apiCredentialDeclare declares a credential in the dashboard's file,
// optionally with a new https endpoint for it, and adds it to the
// requested profiles wherever they are declared.
func (w *webMux) apiCredentialDeclare(rw http.ResponseWriter, r *http.Request) {
	w.editCredentialConfig(rw, r, func(tree *configTree, gw *config.Gateway, req credentialConfigRequest) ([]configChange, error) {
		typ, ok := editableCredentialType(req.Type)
		if !ok {
			return nil, fmt.Errorf("%w: the form cannot declare a %q credential", errBadCredentialRequest, req.Type)
		}
		if !configNameRE.MatchString(req.Name) {
			return nil, fmt.Errorf("%w: credential name %q: use letters, digits, - and _, starting with a letter", errBadCredentialRequest, req.Name)
		}
		if _, exists := gw.Policy.Credentials[req.Name]; exists {
			return nil, fmt.Errorf("%w: a credential named %q already exists", errBadCredentialRequest, req.Name)
		}
		if slices.Contains(typ.Fields, "header") && (req.Header == nil || *req.Header == "") {
			return nil, fmt.Errorf("%w: a %s credential needs a header", errBadCredentialRequest, typ.Type)
		}
		target, _, err := resolveConfigFile(w.g.cfgPath, "")
		if err != nil {
			return nil, err
		}
		ref, err := tree.credentialEndpointRef(gw, typ, req, target)
		if err != nil {
			return nil, err
		}
		if ref == nil {
			return nil, fmt.Errorf("%w: pick an endpoint or declare a new host", errBadCredentialRequest)
		}
		f, err := tree.file(target)
		if err != nil {
			return nil, err
		}
		blk := appendBlock(f, "credential", []string{typ.Type, req.Name})
		if err := setCredentialFields(blk, typ, req); err != nil {
			return nil, err
		}
		blk.Body().SetAttributeTraversal("endpoint", ref)
		if err := tree.setCredentialProfiles(typ.Type, req.Name, req.Profiles); err != nil {
			return nil, err
		}
		return tree.changes(target, ""), nil
	})
}

// apiCredentialEdit changes a credential's settings, its endpoint, or
// the profiles that list it. Settings and endpoint change only for the
// types the form declares; profiles change for any credential.
func (w *webMux) apiCredentialEdit(rw http.ResponseWriter, r *http.Request) {
	w.editCredentialConfig(rw, r, func(tree *configTree, gw *config.Gateway, req credentialConfigRequest) ([]configChange, error) {
		file, blk := tree.find("credential", req.Name)
		if blk == nil || len(blk.Labels()) != 2 {
			return nil, fmt.Errorf("%w %q", errNoSuchCredential, req.Name)
		}
		credType := blk.Labels()[0]
		changesSettings := req.Header != nil || req.Prefix != nil || req.Endpoint != nil || req.NewEndpoint != nil
		if changesSettings {
			typ, ok := editableCredentialType(credType)
			if !ok {
				return nil, fmt.Errorf("%w: the form cannot change a %s credential's settings; change them in %s", errBadCredentialRequest, credType, file)
			}
			if err := setCredentialFields(blk, typ, req); err != nil {
				return nil, err
			}
			target, _, err := resolveConfigFile(w.g.cfgPath, "")
			if err != nil {
				return nil, err
			}
			ref, err := tree.credentialEndpointRef(gw, typ, req, target)
			if err != nil {
				return nil, err
			}
			if ref != nil {
				blk.Body().RemoveAttribute("endpoints")
				blk.Body().SetAttributeTraversal("endpoint", ref)
			}
		}
		if err := tree.setCredentialProfiles(credType, req.Name, req.Profiles); err != nil {
			return nil, err
		}
		first := file
		if req.NewEndpoint != nil {
			// The new endpoint's file lands before the credential
			// that references it.
			first, _, _ = resolveConfigFile(w.g.cfgPath, "")
		}
		return tree.changes(first, ""), nil
	})
}

// apiCredentialRemove removes a credential's block and its entries in
// profile lists, then clears its stored secret. Only the types the
// form declares can be removed: their secret is a plain slot.
func (w *webMux) apiCredentialRemove(rw http.ResponseWriter, r *http.Request) {
	var removed string
	ok := w.editCredentialConfig(rw, r, func(tree *configTree, _ *config.Gateway, req credentialConfigRequest) ([]configChange, error) {
		file, blk := tree.find("credential", req.Name)
		if blk == nil || len(blk.Labels()) != 2 {
			return nil, fmt.Errorf("%w %q", errNoSuchCredential, req.Name)
		}
		credType := blk.Labels()[0]
		if _, ok := editableCredentialType(credType); !ok {
			return nil, fmt.Errorf("%w: the form cannot remove a %s credential; remove it from %s", errBadCredentialRequest, credType, file)
		}
		if err := tree.setCredentialProfiles(credType, req.Name, nil); err != nil {
			return nil, err
		}
		tree.files[file].Body().RemoveBlock(blk)
		removed = req.Name
		return tree.changes("", file), nil
	})
	if !ok || removed == "" {
		return
	}
	unlock := w.lockCredentialSave(removed)
	defer unlock()
	if err := clearCredentialSecrets(w.g.db, removed); err != nil {
		log.Printf("credentials: clear secrets of removed credential %s: %v", removed, err)
	}
	if err := clearCredentialVerification(w.g.db, removed); err != nil {
		log.Printf("credentials: clear verification of removed credential %s: %v", removed, err)
	}
}

// editCredentialConfig decodes a credential request, plans the change
// with the config lock held, writes it and answers. It reports whether
// the change was written.
func (w *webMux) editCredentialConfig(rw http.ResponseWriter, r *http.Request,
	plan func(*configTree, *config.Gateway, credentialConfigRequest) ([]configChange, error)) bool {
	var req credentialConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, credentialConfigMaxBytes)).Decode(&req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return false
	}
	setAuditTarget(r, req.Name)

	w.g.configMu.Lock()
	defer w.g.configMu.Unlock()
	gw := w.g.cfg.Load()
	if !gw.DashboardConfigWrites() {
		http.Error(rw, errConfigWritesDisabled.Error(), http.StatusForbidden)
		return false
	}
	if gw.Policy == nil {
		http.Error(rw, "no config loaded", http.StatusServiceUnavailable)
		return false
	}
	tree, err := loadConfigTree(w.g.cfgPath)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return false
	}
	changes, err := plan(tree, gw, req)
	switch {
	case errors.Is(err, errNoSuchCredential):
		http.Error(rw, err.Error(), http.StatusNotFound)
		return false
	case errors.Is(err, errBadCredentialRequest):
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return false
	case err != nil:
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return false
	}
	files := make([]string, 0, len(changes))
	for _, c := range changes {
		files = append(files, c.Name)
	}
	if len(changes) > 0 && !w.applyConfigChanges(rw, changes) {
		return false
	}
	writeJSON(rw, map[string]any{"ok": true, "name": req.Name, "files": files})
	return true
}
