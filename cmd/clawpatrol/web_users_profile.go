package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
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

// userProfilePlan is a profile ready to declare: the HCL to append and
// the credentials it clones.
type userProfilePlan struct {
	snippet string
	clones  []string
}

// planUserProfile returns the HCL declaring profile req.Name with the
// template's credentials. A credential only the template uses is the
// template owner's own: it is cloned under a name for the new profile,
// and its secret starts empty for the new owner to fill. A credential
// other profiles use too is shared as is. Rules that name the template
// profile or its credentials are not copied.
func planUserProfile(cfgPath string, policy *config.CompiledPolicy, req newUserProfile) (userProfilePlan, error) {
	if !validDashboardUsername(req.Name) {
		return userProfilePlan{}, fmt.Errorf("%w: profile name must match %s", errUserProfileInvalid, dashboardUsernameRe)
	}
	if policy == nil {
		return userProfilePlan{}, fmt.Errorf("%w: no config is loaded", errUserProfileInvalid)
	}
	if policy.Profiles[req.Name] != nil {
		return userProfilePlan{}, fmt.Errorf("%w: profile %q is already declared", errUserProfileConflict, req.Name)
	}
	template := policy.Profiles[req.Template]
	if template == nil {
		return userProfilePlan{}, fmt.Errorf("%w: template profile %q is not declared", errUserProfileInvalid, req.Template)
	}

	blocks, err := configTopLevelBlocks(cfgPath)
	if err != nil {
		return userProfilePlan{}, err
	}
	templateBlock := blocks.find("profile", req.Template)
	if templateBlock == nil {
		return userProfilePlan{}, fmt.Errorf("%w: profile %q is not in the config files", errUserProfileInvalid, req.Template)
	}
	if profileHasInlineCredentials(templateBlock) {
		return userProfilePlan{}, fmt.Errorf("%w: profile %q sets per-credential options inline; declare the new profile by hand", errUserProfileInvalid, req.Template)
	}

	users := credentialProfileCounts(policy)
	out := hclwrite.NewEmptyFile()
	body := out.Body()
	body.AppendUnstructuredTokens(commentTokens(fmt.Sprintf("Profile %q, created on the dashboard from profile %q.", req.Name, req.Template)))
	var refs, clones []string
	cloned := map[string]string{}
	for _, ent := range template.Credentials {
		sym := ent.Symbol
		if users[sym.Name] > 1 {
			refs = append(refs, sym.Type+"."+sym.Name)
			continue
		}
		clone := cloneCredentialName(sym.Name, req.Template, req.Name)
		if other, ok := cloned[clone]; ok {
			return userProfilePlan{}, fmt.Errorf("%w: credentials %q and %q would both be copied as %q", errUserProfileConflict, other, sym.Name, clone)
		}
		cloned[clone] = sym.Name
		if policy.Credentials[clone] != nil {
			return userProfilePlan{}, fmt.Errorf("%w: credential %q is already declared", errUserProfileConflict, clone)
		}
		src := blocks.find("credential", sym.Type, sym.Name)
		if src == nil {
			return userProfilePlan{}, fmt.Errorf("%w: credential %q is not in the config files", errUserProfileInvalid, sym.Name)
		}
		dst := body.AppendNewBlock("credential", []string{sym.Type, clone})
		dst.Body().AppendUnstructuredTokens(blockBodyLines(src.Body().BuildTokens(nil)))
		refs = append(refs, sym.Type+"."+clone)
		clones = append(clones, clone)
	}
	profile := body.AppendNewBlock("profile", []string{req.Name})
	config.SetIdentList(profile.Body(), "credentials", refs)
	if template.HITLAsyncGrants {
		profile.Body().SetAttributeValue("hitl_async_grants", cty.True)
	}
	return userProfilePlan{snippet: string(hclwrite.Format(out.Bytes())), clones: clones}, nil
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

// blockBodyLines returns a block body's tokens as whole lines: without
// the newline the body starts with (the new block already opens on its
// own line) and ending in one, which a one-line source block lacks.
func blockBodyLines(toks hclwrite.Tokens) hclwrite.Tokens {
	for len(toks) > 0 && toks[0].Type == hclsyntax.TokenNewline {
		toks = toks[1:]
	}
	if len(toks) > 0 && toks[len(toks)-1].Type != hclsyntax.TokenNewline {
		toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")})
	}
	return toks
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
	dir, names := filepath.Dir(cfgPath), []string{filepath.Base(cfgPath)}
	if configIsDir(cfgPath) {
		var err error
		if names, err = config.DirFileNames(cfgPath); err != nil {
			return nil, err
		}
		dir = cfgPath
	}
	var out configBlocks
	for _, name := range names {
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		parsed, diags := hclwrite.ParseConfig(src, name, hcl.InitialPos)
		if diags.HasErrors() {
			return nil, fmt.Errorf("parse %s: %s", name, diags.Error())
		}
		out = append(out, parsed.Body().Blocks()...)
	}
	return out, nil
}

// planUserProfileLocked checks req and returns the config change that
// declares it, without writing anything. g.configMu must be held until
// the change is written, so the plan cannot go stale.
func (g *Gateway) planUserProfileLocked(req newUserProfile) (userProfilePlan, []configChange, error) {
	if !g.cfg.Load().DashboardConfigWrites() {
		return userProfilePlan{}, nil, fmt.Errorf("%w: dashboard config writes are disabled (gateway.dashboard_config_writes)", errUserProfileInvalid)
	}
	plan, err := planUserProfile(g.cfgPath, g.Policy(), req)
	if err != nil {
		return userProfilePlan{}, nil, err
	}
	target, targetPath, err := resolveConfigFile(g.cfgPath, "")
	if err != nil {
		return userProfilePlan{}, nil, err
	}
	current, err := readConfigFileOrEmpty(targetPath)
	if err != nil {
		return userProfilePlan{}, nil, err
	}
	changes, err := planConfigAppend(g.cfgPath, target, current, plan.snippet)
	if err != nil {
		return userProfilePlan{}, nil, err
	}
	return plan, changes, nil
}

// clearOrphanCredentialSecrets drops secrets still stored under names
// the plan is about to declare. Those names are undeclared, so the
// rows are left over from an earlier config; the new credentials must
// start empty, not inherit another person's token.
func clearOrphanCredentialSecrets(db *sql.DB, names []string) error {
	for _, name := range names {
		_, found, err := readCredentialSecrets(db, name)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if err := clearCredentialSecrets(db, name); err != nil {
			return err
		}
		log.Printf("dashboard config: cleared the stored secret left under undeclared credential %q", name)
	}
	return nil
}
