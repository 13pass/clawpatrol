package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// What a rule generated from a request does, and how much of the
// request it matches.
const (
	ruleVerdictDeny    = "deny"
	ruleVerdictAllow   = "allow"
	ruleVerdictApprove = "approve"

	ruleScopeExact     = "exact"      // the request's method and path (or SQL / k8s facets)
	ruleScopeAnyMethod = "any_method" // HTTP: the path, any method
	ruleScopePattern   = "pattern"    // HTTP: the method, path with ID segments generalized
	ruleScopeAnyName   = "any_name"   // k8s: verb, resource and namespace, any object name
)

// Priorities of generated rules. Rules are tried highest first and the
// first match wins. Member rules all sit at memberRulePriority, inside
// the member band (1–99); an admin rule at adminGuardrailPriority or
// above therefore always wins over them.
const (
	memberRulePriority     = 50
	adminGuardrailPriority = 100
)

// dashboardApproverRef routes "require approval" to the dashboard when
// the author has no approver of their own.
const dashboardApproverRef = "builtin.dashboard"

// patternMinHexSegment is the shortest all-hex path segment the
// pattern scope treats as an ID (commit SHAs, hex tokens).
const patternMinHexSegment = 12

var (
	uuidSegmentRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	digitsRe      = regexp.MustCompile(`^[0-9]+$`)
	hexRe         = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// RuleRequest is what a dashboard user asks for when turning a request
// into a rule.
type RuleRequest struct {
	Verdict string `json:"verdict"`
	Scope   string `json:"scope"`
	// Approver names the human_approver of an "approve" rule; "" routes
	// to the dashboard. Ignored for members, whose own approver is used.
	Approver string `json:"approver,omitempty"`
	// PinHeader, when set, limits an HTTP rule to requests carrying the
	// recorded value of this header — e.g. the API service's caller ID.
	PinHeader string `json:"pin_header,omitempty"`
}

// RuleAuthor scopes a generated rule to a member. A nil author is an
// admin, whose rules carry no pins.
type RuleAuthor struct {
	Username string
	// Approver is the member's own approver ("" for the dashboard).
	Approver string
}

// ScopedRule is a generated rule and what it takes to install it.
type ScopedRule struct {
	RuleName     string   `json:"rule_name"`
	EndpointName string   `json:"endpoint_name"`
	Family       string   `json:"family"`
	Condition    string   `json:"condition,omitempty"`
	Credential   string   `json:"credential,omitempty"`
	Profile      string   `json:"profile,omitempty"`
	HCL          string   `json:"hcl"`
	Warnings     []string `json:"warnings,omitempty"`
	// NewEndpoint is set when the request had no endpoint and the HCL
	// declares one, with a passthrough credential that must join
	// ProfileAdditions.
	NewEndpoint      bool     `json:"new_endpoint,omitempty"`
	ProfileAdditions []string `json:"profile_additions,omitempty"`

	// credentialRef is Credential as a typed HCL reference.
	credentialRef string
}

// GenerateScopedRule turns a recorded request into a rule. For a member
// (author != nil) the rule is pinned to the request's profile and
// credential, named under the member's prefix, and held to
// memberRulePriority.
func GenerateScopedRule(policy *config.CompiledPolicy, ev *Event, req RuleRequest, author *RuleAuthor) (*ScopedRule, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy not loaded")
	}
	if ev == nil {
		return nil, fmt.Errorf("event is required")
	}
	switch req.Verdict {
	case ruleVerdictDeny, ruleVerdictAllow, ruleVerdictApprove:
	default:
		return nil, fmt.Errorf("verdict must be deny, allow or approve")
	}
	if req.Scope == "" {
		req.Scope = ruleScopeExact
	}
	if author != nil {
		if ev.Profile == "" {
			return nil, fmt.Errorf("this request has no recorded profile, so no member rule can be scoped to it")
		}
		req.Approver = author.Approver
	}
	if ev.Endpoint == "" {
		return generateScopedHostRule(policy, ev, req, author)
	}
	ep := policy.Endpoints[ev.Endpoint]
	if ep == nil {
		return nil, fmt.Errorf("endpoint %q no longer in policy", ev.Endpoint)
	}
	condition, warnings, err := scopedRuleCondition(ep.Family, ev, req)
	if err != nil {
		return nil, err
	}
	rule := &ScopedRule{
		RuleName:     scopedRuleName(author, req, ev, ep.Name),
		EndpointName: ep.Name,
		Family:       ep.Family,
		Condition:    condition,
		Warnings:     warnings,
	}
	if author != nil {
		rule.Profile = ev.Profile
		if ent := policy.Credentials[ev.Credential]; ev.Credential != "" && ent != nil && ent.Symbol != nil {
			rule.Credential = ev.Credential
			rule.credentialRef = ent.Symbol.Type + "." + ev.Credential
		} else {
			rule.Warnings = append(rule.Warnings, "This request used no credential the config still declares; the rule is pinned to your profile only.")
		}
	}
	f := hclwrite.NewEmptyFile()
	writeScopedRuleBlock(f.Body(), rule, endpointRef(ep), req, author)
	rule.HCL = string(f.Bytes())
	return rule, nil
}

// generateScopedHostRule handles a request no endpoint claimed: it
// declares an endpoint for the host, a passthrough credential that
// claims it for the author's profile (every profile, for an admin),
// and the rule. Such a host already passes through, so only deny and
// approve make sense.
func generateScopedHostRule(policy *config.CompiledPolicy, ev *Event, req RuleRequest, author *RuleAuthor) (*ScopedRule, error) {
	if req.Verdict == ruleVerdictAllow {
		return nil, fmt.Errorf("this host matched no endpoint, so it already passes through; only deny or approve apply")
	}
	if req.Scope != ruleScopeExact {
		return nil, fmt.Errorf("a host with no endpoint can only be ruled as a whole (scope exact)")
	}
	host := canonicalObservedHost(ev.Host)
	if host == "" {
		return nil, fmt.Errorf("action has no endpoint or host")
	}
	endpointName := generatedEndpointName(policy, host)
	if author != nil {
		endpointName = uniqueEndpointName(policy, author.Username+"-"+endpointName)
	}
	credName := generatedPassthroughCredName(policy, endpointName)
	rule := &ScopedRule{
		RuleName:     scopedRuleName(author, req, ev, endpointName),
		EndpointName: endpointName,
		Family:       "http",
		NewEndpoint:  true,
	}
	if author != nil {
		rule.Profile = ev.Profile
		rule.Credential = credName
		rule.credentialRef = "passthrough." + credName
		rule.ProfileAdditions = []string{ev.Profile}
	} else {
		rule.ProfileAdditions = generatedProfileNames(policy)
	}

	f := hclwrite.NewEmptyFile()
	eb := f.Body().AppendNewBlock("endpoint", []string{"https", endpointName}).Body()
	eb.SetAttributeValue("hosts", cty.ListVal([]cty.Value{cty.StringVal(host)}))
	f.Body().AppendNewline()
	cb := f.Body().AppendNewBlock("credential", []string{"passthrough", credName}).Body()
	cb.SetAttributeRaw("endpoint", config.TraversalTokens("https."+endpointName))
	f.Body().AppendNewline()
	writeScopedRuleBlock(f.Body(), rule, "https."+endpointName, req, author)
	for _, profile := range rule.ProfileAdditions {
		f.Body().AppendNewline()
		pb := f.Body().AppendNewBlock("profile", []string{profile}).Body()
		config.SetIdentList(pb, "credentials", []string{"passthrough." + credName})
	}
	rule.HCL = string(f.Bytes())
	rule.Warnings = append(rule.Warnings, "This request matched no endpoint: the rule declares one for "+host+" and a passthrough credential that claims it.")
	return rule, nil
}

func writeScopedRuleBlock(body *hclwrite.Body, rule *ScopedRule, endpoint string, req RuleRequest, author *RuleAuthor) {
	b := body.AppendNewBlock("rule", []string{rule.RuleName}).Body()
	b.SetAttributeRaw("endpoint", config.TraversalTokens(endpoint))
	priority := adminGuardrailPriority
	if author != nil {
		priority = memberRulePriority
	}
	b.SetAttributeValue("priority", cty.NumberIntVal(int64(priority)))
	if rule.credentialRef != "" {
		b.SetAttributeRaw("credential", config.TraversalTokens(rule.credentialRef))
	}
	if rule.Profile != "" {
		b.SetAttributeRaw("profile", config.TraversalTokens("profile."+rule.Profile))
	}
	if rule.Condition != "" {
		setCELCondition(b, rule.Condition)
	}
	by := "an admin"
	if author != nil {
		by = author.Username
	}
	switch req.Verdict {
	case ruleVerdictDeny:
		b.SetAttributeValue("verdict", cty.StringVal("deny"))
		b.SetAttributeValue("reason", cty.StringVal("Blocked from the dashboard by "+by))
	case ruleVerdictAllow:
		b.SetAttributeValue("verdict", cty.StringVal("allow"))
		b.SetAttributeValue("reason", cty.StringVal("Pre-approved from the dashboard by "+by))
	case ruleVerdictApprove:
		approver := dashboardApproverRef
		if req.Approver != "" {
			approver = humanApproverType + "." + req.Approver
		}
		b.SetAttributeRaw("approve", approverListTokens(approver))
	}
}

func approverListTokens(ref string) hclwrite.Tokens {
	tokens := hclwrite.Tokens{{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")}}
	tokens = append(tokens, config.TraversalTokens(ref)...)
	return append(tokens, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
}

func scopedRuleName(author *RuleAuthor, req RuleRequest, ev *Event, endpointName string) string {
	prefix := map[string]string{
		ruleVerdictDeny:    "block",
		ruleVerdictAllow:   "allow",
		ruleVerdictApprove: "approve",
	}[req.Verdict]
	sumInput := strings.Join([]string{ev.ID, ev.Endpoint, ev.Method, ev.Path, req.Verdict, req.Scope, req.PinHeader}, "\x00")
	sum := sha256.Sum256([]byte(sumInput))
	name := fmt.Sprintf("%s_%s_%x", prefix, safeRuleNamePart(endpointName), sum[:3])
	if author != nil {
		name = author.Username + "-" + name
	}
	return name
}

func uniqueEndpointName(policy *config.CompiledPolicy, name string) string {
	if policy.Endpoints[name] == nil {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", name, i)
		if policy.Endpoints[candidate] == nil {
			return candidate
		}
	}
}

func scopedRuleCondition(family string, ev *Event, req RuleRequest) (string, []string, error) {
	if req.PinHeader != "" && family != "http" {
		return "", nil, fmt.Errorf("a header pin applies to HTTP rules only")
	}
	switch family {
	case "http":
		return scopedHTTPCondition(ev, req)
	case "k8s":
		switch req.Scope {
		case ruleScopeExact:
			return k8sRuleCondition(ev)
		case ruleScopeAnyName:
			c, w, err := k8sRuleCondition(&Event{Facets: withoutFacet(ev.Facets, "name")})
			return c, w, err
		}
		return "", nil, fmt.Errorf("Kubernetes rules take scope exact or any_name")
	case "sql":
		if req.Scope != ruleScopeExact {
			return "", nil, fmt.Errorf("SQL rules take scope exact")
		}
		return sqlRuleCondition(ev)
	}
	return "", nil, fmt.Errorf("endpoint family %q is not supported for rule generation", family)
}

func withoutFacet(facets map[string]any, drop string) map[string]any {
	out := make(map[string]any, len(facets))
	for k, v := range facets {
		if k != drop {
			out[k] = v
		}
	}
	return out
}

func scopedHTTPCondition(ev *Event, req RuleRequest) (string, []string, error) {
	method := strings.ToUpper(strings.TrimSpace(ev.Method))
	path, _ := splitPathQuery(ev.Path)
	path = strings.TrimSpace(path)
	var parts, warnings []string
	switch req.Scope {
	case ruleScopeExact:
		c, w, err := httpRuleCondition(ev)
		if err != nil {
			return "", nil, err
		}
		parts, warnings = append(parts, c), w
	case ruleScopeAnyMethod:
		if path == "" {
			return "", nil, fmt.Errorf("no request path was recorded")
		}
		parts = append(parts, "http.path == "+celString(path))
	case ruleScopePattern:
		if path == "" {
			return "", nil, fmt.Errorf("no request path was recorded")
		}
		pattern, generalized := pathPattern(path)
		if method != "" {
			parts = append(parts, "http.method == "+celString(method))
		}
		parts = append(parts, "http.path.matches("+celString(pattern)+")")
		if !generalized {
			warnings = append(warnings, "No segment of this path looks like an ID, so the pattern matches only this path.")
		}
	default:
		return "", nil, fmt.Errorf("HTTP rules take scope exact, any_method or pattern")
	}
	if req.PinHeader != "" {
		name := http.CanonicalHeaderKey(strings.TrimSpace(req.PinHeader))
		if runtime.IsSensitiveHeader(name) {
			return "", nil, fmt.Errorf("header %q may carry a credential and cannot pin a rule", name)
		}
		value, ok := ev.ReqHeaders[name]
		if !ok {
			return "", nil, fmt.Errorf("this request did not carry header %q", name)
		}
		// Guarded with `in`: a request without the header must fall
		// through, not error — an unevaluable condition is a deny.
		parts = append(parts, celString(name)+" in http.headers && http.headers["+celString(name)+"].exists(v, v == "+celString(value)+")")
	}
	return strings.Join(parts, " && "), warnings, nil
}

// pathPattern turns a path into an anchored RE2 pattern where segments
// that look like IDs (numbers, UUIDs, long hex, URL-encoded paths)
// match any single segment.
func pathPattern(path string) (string, bool) {
	segments := strings.Split(path, "/")
	generalized := false
	for i, seg := range segments {
		if isIDSegment(seg) {
			segments[i] = "[^/]+"
			generalized = true
		} else {
			segments[i] = regexp.QuoteMeta(seg)
		}
	}
	return "^" + strings.Join(segments, "/") + "$", generalized
}

func isIDSegment(seg string) bool {
	switch {
	case seg == "":
		return false
	case digitsRe.MatchString(seg), uuidSegmentRe.MatchString(seg), strings.Contains(seg, "%"):
		return true
	case len(seg) >= patternMinHexSegment && hexRe.MatchString(seg):
		return true
	}
	return false
}

// ruleMatchesEvent reports whether a generated rule would have matched
// a recorded request: its pins, then its condition. Families whose
// recorded events cannot be replayed report ok = false.
func ruleMatchesEvent(rule *ScopedRule, ev *Event) (matched, ok bool) {
	if rule.Credential != "" && ev.Credential != rule.Credential {
		return false, true
	}
	if rule.Profile != "" && ev.Profile != rule.Profile {
		return false, true
	}
	req, ok := matchRequestFromEvent(rule.Family, ev)
	if !ok {
		return false, false
	}
	if rule.Condition == "" {
		return true, true
	}
	matcher, err := facet.NewMatcher(rule.Family, rule.Condition)
	if err != nil {
		return false, false
	}
	return matcher.Match(req).Result == match.Matched, true
}

func matchRequestFromEvent(family string, ev *Event) (*match.Request, bool) {
	switch family {
	case "http":
		h := http.Header{}
		for k, v := range ev.ReqHeaders {
			h.Set(k, v)
		}
		path, query := splitPathQuery(ev.Path)
		return &match.Request{
			Family:     "http",
			Method:     ev.Method,
			URL:        &url.URL{Path: path, RawQuery: url.Values(query).Encode()},
			Headers:    h,
			Credential: ev.Credential,
			Profile:    ev.Profile,
			PeerIP:     ev.AgentIP,
		}, true
	case "k8s":
		fx := &Fixture{Action: Action{Host: ev.Host, K8s: exportK8s(ev), Credential: ev.Credential, Profile: ev.Profile, PeerIP: ev.AgentIP}}
		req, err := fx.ToMatchRequest("k8s", nil)
		return req, err == nil
	}
	return nil, false
}
