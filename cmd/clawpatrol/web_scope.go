package main

import (
	"github.com/denoland/clawpatrol/internal/config"
)

// What a member may see and change, derived from the profiles they
// own (see doc/multi-user-dashboard.md, phase 4). An admin's viewer
// passes every check.

func (v viewer) ownsProfile(profile string) bool {
	return v.admin || (profile != "" && v.profiles[profile])
}

// visibleCredentials is the set of credentials the viewer's profiles
// use; nil means every credential (an admin).
func (v viewer) visibleCredentials(policy *config.CompiledPolicy) map[string]bool {
	if v.admin {
		return nil
	}
	out := map[string]bool{}
	for p := range v.profiles {
		for name := range credentialsInProfile(policy, p) {
			out[name] = true
		}
	}
	return out
}

// managesCredential reports whether the viewer may set, connect,
// refresh or clear a credential's secret. A member may only when every
// profile using it is theirs: rotating a credential another team
// shares would change that team's access.
func (v viewer) managesCredential(policy *config.CompiledPolicy, name string) bool {
	if v.admin {
		return true
	}
	if policy == nil || policy.Credentials[name] == nil {
		return false
	}
	profiles, _ := credentialBindings(policy, name)
	if len(profiles) == 0 {
		return false
	}
	for _, p := range profiles {
		if !v.profiles[p] {
			return false
		}
	}
	return true
}
