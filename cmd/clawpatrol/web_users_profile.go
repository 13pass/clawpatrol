package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

// newUserProfile asks /api/users/create to also declare a profile for
// the new user, modelled on an existing profile.
type newUserProfile struct {
	Name     string `json:"name"`
	Template string `json:"template"`
}

var (
	errUserProfileInvalid  = errors.New("invalid profile request")
	errUserProfileConflict = errors.New("profile conflict")
)

// planUserProfile returns the HCL declaring profile req.Name with the
// template's credentials. A credential only the template uses is the
// template owner's own: it is cloned under a name for the new profile,
// and its secret starts empty for the new owner to fill. A credential
// other profiles use too is shared as is.
func planUserProfile(cfgPath string, policy *config.CompiledPolicy, req newUserProfile) (string, error) {
	if !validDashboardUsername(req.Name) {
		return "", fmt.Errorf("%w: profile name must match %s", errUserProfileInvalid, dashboardUsernameRe)
	}
	if policy == nil {
		return "", fmt.Errorf("%w: no config is loaded", errUserProfileInvalid)
	}
	if policy.Profiles[req.Name] != nil {
		return "", fmt.Errorf("%w: profile %q is already declared", errUserProfileConflict, req.Name)
	}
	template := policy.Profiles[req.Template]
	if template == nil {
		return "", fmt.Errorf("%w: template profile %q is not declared", errUserProfileInvalid, req.Template)
	}

	blocks, err := configTopLevelBlocks(cfgPath)
	if err != nil {
		return "", err
	}
	templateBlock := blocks.find("profile", req.Template)
	if templateBlock == nil {
		return "", fmt.Errorf("%w: profile %q is not in the config files", errUserProfileInvalid, req.Template)
	}
	if profileHasInlineCredentials(templateBlock) {
		return "", fmt.Errorf("%w: profile %q sets per-credential options inline; declare the new profile by hand", errUserProfileInvalid, req.Template)
	}

	users := credentialProfileCounts(policy)
	out := hclwrite.NewEmptyFile()
	body := out.Body()
	body.AppendUnstructuredTokens(commentTokens(fmt.Sprintf("Profile %q, created on the dashboard from profile %q.", req.Name, req.Template)))
	var refs []string
	for _, ent := range template.Credentials {
		sym := ent.Symbol
		if users[sym.Name] > 1 {
			refs = append(refs, sym.Type+"."+sym.Name)
			continue
		}
		clone := cloneCredentialName(sym.Name, req.Template, req.Name)
		if policy.Credentials[clone] != nil {
			return "", fmt.Errorf("%w: credential %q is already declared", errUserProfileConflict, clone)
		}
		src := blocks.find("credential", sym.Type, sym.Name)
		if src == nil {
			return "", fmt.Errorf("%w: credential %q is not in the config files", errUserProfileInvalid, sym.Name)
		}
		dst := body.AppendNewBlock("credential", []string{sym.Type, clone})
		dst.Body().AppendUnstructuredTokens(trimLeadingNewlines(src.Body().BuildTokens(nil)))
		refs = append(refs, sym.Type+"."+clone)
	}
	profile := body.AppendNewBlock("profile", []string{req.Name})
	profile.Body().SetAttributeRaw("credentials", referenceListTokens(refs))
	if template.HITLAsyncGrants {
		profile.Body().SetAttributeRaw("hitl_async_grants", hclwrite.Tokens{{Type: hclsyntax.TokenIdent, Bytes: []byte("true")}})
	}
	return string(hclwrite.Format(out.Bytes())), nil
}

// cloneCredentialName names the new profile's copy of a template
// credential: a "-<template>" suffix is swapped for "-<profile>",
// otherwise "-<profile>" is appended.
func cloneCredentialName(name, template, profile string) string {
	return strings.TrimSuffix(name, "-"+template) + "-" + profile
}

// credentialProfileCounts maps each credential to the number of
// profiles listing it.
func credentialProfileCounts(policy *config.CompiledPolicy) map[string]int {
	counts := map[string]int{}
	for _, p := range policy.Profiles {
		seen := map[string]bool{}
		for _, ent := range p.Credentials {
			if name := ent.Symbol.Name; !seen[name] {
				seen[name] = true
				counts[name]++
			}
		}
	}
	return counts
}

// profileHasInlineCredentials reports whether a profile's credentials
// list holds `{ credential = ..., placeholder = ... }` entries, which
// bind options to that profile and are not copied.
func profileHasInlineCredentials(b *hclwrite.Block) bool {
	attr := b.Body().GetAttribute("credentials")
	if attr == nil {
		return false
	}
	for _, t := range attr.Expr().BuildTokens(nil) {
		if t.Type == hclsyntax.TokenOBrace {
			return true
		}
	}
	return false
}

// trimLeadingNewlines drops the newline a block body starts with; the
// new block already opens on its own line.
func trimLeadingNewlines(toks hclwrite.Tokens) hclwrite.Tokens {
	for len(toks) > 0 && toks[0].Type == hclsyntax.TokenNewline {
		toks = toks[1:]
	}
	return toks
}

func referenceListTokens(refs []string) hclwrite.Tokens {
	toks := hclwrite.Tokens{{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")}}
	for i, ref := range refs {
		if i > 0 {
			toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")})
		}
		for j, part := range strings.Split(ref, ".") {
			if j > 0 {
				toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenDot, Bytes: []byte(".")})
			}
			toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(part)})
		}
	}
	return append(toks, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
}

func commentTokens(text string) hclwrite.Tokens {
	return hclwrite.Tokens{{Type: hclsyntax.TokenComment, Bytes: []byte("# " + text + "\n")}}
}

type configBlocks []*hclwrite.Block

func (bs configBlocks) find(typeName string, labels ...string) *hclwrite.Block {
	for _, b := range bs {
		if b.Type() == typeName && strings.Join(b.Labels(), "\x00") == strings.Join(labels, "\x00") {
			return b
		}
	}
	return nil
}

// configTopLevelBlocks parses every file the config loads, in load
// order, and returns their top-level blocks.
func configTopLevelBlocks(cfgPath string) (configBlocks, error) {
	files, err := configFiles(cfgPath)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(cfgPath)
	if configIsDir(cfgPath) {
		dir = cfgPath
	}
	var out configBlocks
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			return nil, err
		}
		parsed, diags := hclwrite.ParseConfig(src, f.Name, hcl.InitialPos)
		if diags.HasErrors() {
			return nil, fmt.Errorf("parse %s: %s", f.Name, diags.Error())
		}
		out = append(out, parsed.Body().Blocks()...)
	}
	return out, nil
}

// applyUserProfileLocked declares the profile in the dashboard's config
// file and reloads. g.configMu must be held.
func (g *Gateway) applyUserProfileLocked(req newUserProfile) error {
	if !g.cfg.Load().DashboardConfigWrites() {
		return fmt.Errorf("%w: dashboard config writes are disabled (gateway.dashboard_config_writes)", errUserProfileInvalid)
	}
	snippet, err := planUserProfile(g.cfgPath, g.Policy(), req)
	if err != nil {
		return err
	}
	target, targetPath, err := resolveConfigFile(g.cfgPath, "")
	if err != nil {
		return err
	}
	current, err := readConfigFileOrEmpty(targetPath)
	if err != nil {
		return err
	}
	changes, err := planConfigAppend(g.cfgPath, target, current, snippet)
	if err != nil {
		return err
	}
	return g.writeConfigFilesLocked(changes)
}
