package config

import (
	"strings"
	"testing"
)

func TestEmitRefusesNewEndpointRules(t *testing.T) {
	gw := &Gateway{Defaults: &Defaults{NewEndpointRules: []NewEndpointRule{{Name: "deny"}}}}
	if _, err := Emit(gw); err == nil || !strings.Contains(err.Error(), "new_endpoint_rule") {
		t.Fatalf("Emit error = %v, want a refusal", err)
	}
}
