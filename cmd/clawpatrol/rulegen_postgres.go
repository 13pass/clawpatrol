package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// What a Postgres database turned into an endpoint does with its
// statements. The dashboard offers these four instead of the generic
// verdicts: a relayed connection carries no statement to scope a rule
// on, so the choice is about the database as a whole.
const (
	pgOutcomeLog            = "log"             // inspect and record; no rule
	pgOutcomeApproveChanges = "approve_changes" // reads pass, the rest waits
	pgOutcomeApproveAll     = "approve_all"
	pgOutcomeDeny           = "deny"
)

// postgresPort is the only port the gateway hands to a postgres
// endpoint (main.go's tcpDispatch); anything else is relayed.
const postgresPort = 5432

const postgresDefaultSSLMode = "require"

var postgresSSLModes = map[string]bool{"disable": true, "prefer": true, "require": true, "verify-full": true}

// postgresReadVerbs pass under pgOutcomeApproveChanges: reads, and the
// session and transaction housekeeping every driver sends. A statement
// whose verb is not listed — including one the parser could not name —
// waits for approval. EXPLAIN ANALYZE and data-modifying CTEs are
// matched again on the statement they carry, so their writes still wait.
var postgresReadVerbs = []string{
	"select", "show", "explain", "set", "discard",
	"begin", "commit", "rollback", "savepoint", "release",
	"declare", "fetch", "move", "close", "prepare", "deallocate",
	"listen", "unlisten",
}

// PostgresRuleInput is what the dashboard asks for when a relayed
// Postgres connection becomes an inspected endpoint.
type PostgresRuleInput struct {
	// Name of the endpoint; "" generates one from the address.
	Name string `json:"name,omitempty"`
	// User is the role the gateway logs in as.
	User    string `json:"user,omitempty"`
	SSLMode string `json:"sslmode,omitempty"`
	Outcome string `json:"outcome"`
}

// postgresRelayAddr returns the upstream address of a connection the
// gateway relayed to the Postgres port because no endpoint claimed it.
func postgresRelayAddr(ev *Event) (netip.Addr, bool) {
	if ev.Mode != "relay" || ev.Endpoint != "" {
		return netip.Addr{}, false
	}
	host, port, ok := relayHostPort(ev.Host)
	if !ok || port != postgresPort {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

// relayHostPort splits a relay event's host. wgRelay writes "ip:port"
// without brackets, so an IPv6 address is split at its last colon.
func relayHostPort(host string) (string, int, bool) {
	i := strings.LastIndexByte(host, ':')
	if i <= 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(host[i+1:])
	if err != nil {
		return "", 0, false
	}
	return strings.Trim(host[:i], "[]"), port, true
}

// generateScopedPostgresRule declares an endpoint for a relayed
// Postgres address, a postgres_credential the gateway logs in with, the
// profiles that claim it and, unless the outcome is pgOutcomeLog, the
// rule. The credential's password is set separately, through the
// dashboard's secret store.
func generateScopedPostgresRule(policy *config.CompiledPolicy, ev *Event, ip netip.Addr, req RuleRequest, author *RuleAuthor) (*ScopedRule, error) {
	in := req.Postgres
	if in == nil {
		return nil, fmt.Errorf("a Postgres rule needs the database settings")
	}
	if ev.Action != "allow" {
		return nil, fmt.Errorf("the gateway refused this connection, so there is no database to inspect")
	}
	verdict, condition, err := postgresOutcomeRule(in.Outcome)
	if err != nil {
		return nil, err
	}
	user := strings.TrimSpace(in.User)
	if user == "" && in.Outcome != pgOutcomeDeny {
		return nil, fmt.Errorf("a database user is required: the gateway logs in to the database as that role")
	}
	sslmode := in.SSLMode
	if sslmode == "" {
		sslmode = postgresDefaultSSLMode
	}
	if !postgresSSLModes[sslmode] {
		return nil, fmt.Errorf("sslmode must be disable, prefer, require or verify-full")
	}
	if sslmode == "verify-full" {
		return nil, fmt.Errorf("verify-full checks the server certificate against a host name, and this database is known only by its address; use require")
	}

	profiles := hostRuleProfiles(policy, ev, author)
	var warnings []string
	for _, ep := range postgresEndpointsAt(policy, ip) {
		for _, profile := range profiles {
			if prof := policy.Profiles[profile]; prof != nil && prof.Endpoints[ep.Name] != nil {
				return nil, fmt.Errorf("%s is already inspected through endpoint %q in profile %q; create the rule from a statement recorded since", ip, ep.Name, profile)
			}
		}
		warnings = append(warnings, fmt.Sprintf("Endpoint %q already declares this address for other profiles; this creates a separate endpoint.", ep.Name))
	}

	endpointName, err := postgresEndpointName(policy, ip, in.Name, author)
	if err != nil {
		return nil, err
	}
	credName := uniqueCredentialName(policy, endpointName+"_login")
	credRef := "postgres_credential." + credName

	rule := &ScopedRule{
		EndpointName:     endpointName,
		Family:           "sql",
		Condition:        condition,
		NewEndpoint:      true,
		NewCredential:    credName,
		ProfileAdditions: profiles,
	}
	ruleReq := RuleRequest{Verdict: verdict, Scope: ruleScopeExact, Approver: req.Approver}
	if verdict != "" {
		rule.RuleName = scopedRuleName(author, ruleReq, ev, endpointName)
	}
	if author != nil {
		rule.Profile = ev.Profile
		rule.Credential = credName
		rule.credentialRef = credRef
	}

	f := hclwrite.NewEmptyFile()
	eb := f.Body().AppendNewBlock("endpoint", []string{"postgres", endpointName}).Body()
	eb.SetAttributeValue("host", cty.StringVal(net.JoinHostPort(ip.String(), strconv.Itoa(postgresPort))))
	eb.SetAttributeValue("sslmode", cty.StringVal(sslmode))
	f.Body().AppendNewline()
	cb := f.Body().AppendNewBlock("credential", []string{"postgres_credential", credName}).Body()
	cb.SetAttributeRaw("endpoint", config.TraversalTokens("postgres."+endpointName))
	if user != "" {
		cb.SetAttributeValue("user", cty.StringVal(user))
	}
	if verdict != "" {
		f.Body().AppendNewline()
		writeScopedRuleBlock(f.Body(), rule, "postgres."+endpointName, ruleReq, author)
	}
	for _, profile := range profiles {
		f.Body().AppendNewline()
		pb := f.Body().AppendNewBlock("profile", []string{profile}).Body()
		config.SetIdentList(pb, "credentials", []string{credRef})
	}
	rule.HCL = string(f.Bytes())

	warnings = append(warnings, "Claw Patrol recognises this database by its address. If the server moves to a new address, connections pass through uninspected again until the endpoint is updated.")
	if sslmode == "disable" {
		warnings = append(warnings, "Encryption to the database is off. Hosted Postgres such as Azure refuses unencrypted connections.")
	}
	rule.Warnings = warnings
	return rule, nil
}

func postgresOutcomeRule(outcome string) (verdict, condition string, err error) {
	switch outcome {
	case pgOutcomeLog:
		return "", "", nil
	case pgOutcomeApproveChanges:
		quoted := make([]string, len(postgresReadVerbs))
		for i, v := range postgresReadVerbs {
			quoted[i] = celString(v)
		}
		return ruleVerdictApprove, "!(sql.verb in [" + strings.Join(quoted, ", ") + "])", nil
	case pgOutcomeApproveAll:
		return ruleVerdictApprove, "true", nil
	case pgOutcomeDeny:
		return ruleVerdictDeny, "true", nil
	}
	return "", "", fmt.Errorf("outcome must be log, approve_changes, approve_all or deny")
}

// postgresEndpointsAt lists the postgres endpoints declared with this
// address literally. Endpoints declared by host name are resolved only
// at reload, and a connection one of them claims is not relayed.
func postgresEndpointsAt(policy *config.CompiledPolicy, ip netip.Addr) []*config.CompiledEndpoint {
	var out []*config.CompiledEndpoint
	for _, ep := range policy.Endpoints {
		if ep.Plugin == nil || ep.Plugin.Type != "postgres" {
			continue
		}
		for _, h := range ep.Hosts {
			host, _, err := net.SplitHostPort(h)
			if err != nil {
				host = h
			}
			if addr, err := netip.ParseAddr(host); err == nil && addr.Unmap() == ip.Unmap() {
				out = append(out, ep)
				break
			}
		}
	}
	return out
}

func postgresEndpointName(policy *config.CompiledPolicy, ip netip.Addr, requested string, author *RuleAuthor) (string, error) {
	name := strings.TrimSpace(requested)
	if name == "" {
		name = generatedEndpointName(policy, "pg_"+ip.String())
		if author != nil {
			name = uniqueEndpointName(policy, author.Username+"-"+name)
		}
		return name, nil
	}
	if author != nil && !strings.HasPrefix(name, author.Username+"-") {
		name = author.Username + "-" + name
	}
	if !hclsyntax.ValidIdentifier(name) {
		return "", fmt.Errorf("endpoint name %q may use only letters, digits, - and _, and must start with a letter", name)
	}
	if policy.Endpoints[name] != nil {
		return "", fmt.Errorf("an endpoint named %q already exists", name)
	}
	return name, nil
}

func uniqueCredentialName(policy *config.CompiledPolicy, base string) string {
	if policy.Credentials[base] == nil {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if policy.Credentials[candidate] == nil {
			return candidate
		}
	}
}
