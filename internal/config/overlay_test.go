package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

const overlayGatewayHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`

const overlayEndpointsHCL = `
endpoint "https" "github" {
  hosts = ["api.github.com"]
}
`

func TestLoadDirOverlayReplacesAddsAndRemovesFiles(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", overlayGatewayHCL)
	writeHCL(t, dir, "10-endpoints.hcl", overlayEndpointsHCL)
	writeHCL(t, dir, "20-rules.hcl", `
rule "github-deny-all" {
  endpoint = https.github
  verdict  = "deny"
}
`)

	gw, diags := config.LoadDirOverlay(dir, map[string][]byte{
		"20-rules.hcl": nil,
		"30-new.hcl": []byte(`
rule "github-reads" {
  endpoint  = https.github
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
`),
	})
	if diags.HasErrors() {
		t.Fatalf("LoadDirOverlay: %s", diags.Error())
	}
	if _, ok := gw.Policy.Rules["github-deny-all"]; ok {
		t.Error("rule from the removed file is still loaded")
	}
	if _, ok := gw.Policy.Rules["github-reads"]; !ok {
		t.Error("rule from the added file is missing")
	}

	// The overlay never touches the disk.
	if _, err := os.Stat(filepath.Join(dir, "30-new.hcl")); !os.IsNotExist(err) {
		t.Errorf("overlay wrote 30-new.hcl to disk (stat err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "20-rules.hcl")); err != nil {
		t.Errorf("overlay removed 20-rules.hcl from disk: %v", err)
	}
}

func TestLoadDirOverlayReportsCandidateErrors(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", overlayGatewayHCL)
	writeHCL(t, dir, "10-endpoints.hcl", overlayEndpointsHCL)

	_, diags := config.LoadDirOverlay(dir, map[string][]byte{
		"20-rules.hcl": []byte(`
rule "bad" {
  endpoint = https.missing
  verdict  = "deny"
}
`),
	})
	if !diags.HasErrors() {
		t.Fatal("reference to an undeclared endpoint was accepted")
	}
	if !strings.Contains(diags.Error(), "20-rules.hcl") {
		t.Errorf("diagnostic does not name the candidate file: %s", diags.Error())
	}
}

func TestLoadDirOverlayResolvesIncludesAgainstDir(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", overlayGatewayHCL)
	k8s := []byte(`
endpoint "kubernetes" "cluster" {
  server  = "k8s.example.test"
  ca_cert = "<<file:cluster-ca.pem>>"
}
`)
	if _, diags := config.LoadDirOverlay(dir, map[string][]byte{"10-k8s.hcl": k8s}); !diags.HasErrors() {
		t.Fatal("include of a missing file was accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.pem"), []byte("ca-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, diags := config.LoadDirOverlay(dir, map[string][]byte{"10-k8s.hcl": k8s}); diags.HasErrors() {
		t.Fatalf("include next to the config files did not resolve: %s", diags.Error())
	}
}

func TestLoadDirOverlayRejectsNonConfigNames(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", overlayGatewayHCL)
	for _, name := range []string{"../escape.hcl", "sub/file.hcl", ".hidden.hcl", "notes.txt"} {
		if _, diags := config.LoadDirOverlay(dir, map[string][]byte{name: []byte("")}); !diags.HasErrors() {
			t.Errorf("override %q was accepted", name)
		}
	}
}

func TestDirFileNamesMatchesLoaderDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "20-b.hcl", "")
	writeHCL(t, dir, "10-a.hcl", "")
	writeHCL(t, dir, ".swap.hcl", "")
	writeHCL(t, dir, "README.md", "")
	if err := os.Mkdir(filepath.Join(dir, "sub.hcl"), 0o755); err != nil {
		t.Fatal(err)
	}
	names, err := config.DirFileNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names, ","); got != "10-a.hcl,20-b.hcl" {
		t.Fatalf("DirFileNames = %q", got)
	}
}

func TestRuleProfilePinMustNameADeclaredProfile(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", overlayGatewayHCL)
	writeHCL(t, dir, "10-endpoints.hcl", overlayEndpointsHCL)
	writeHCL(t, dir, "15-profiles.hcl", `
credential "bearer_token" "gh" {
  endpoint = https.github
}
profile "team-a" {
  credentials = [bearer_token.gh]
}
`)
	_, diags := config.LoadDirOverlay(dir, map[string][]byte{"20-rules.hcl": []byte(`
rule "pinned" {
  endpoint = https.github
  profile  = profile.nobody
  verdict  = "deny"
}
`)})
	if !diags.HasErrors() || !strings.Contains(diags.Error(), "nobody") {
		t.Fatalf("pin to an undeclared profile: diags = %v", diags)
	}
}

func TestReadSourcesRejectsRemovingANonConfigName(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", overlayGatewayHCL)
	for _, name := range []string{"../x.hcl", "notes.txt"} {
		if _, diags := config.ReadSources(dir, map[string][]byte{name: nil}); !diags.HasErrors() {
			t.Errorf("removing %q was accepted", name)
		}
	}
}

func TestReadSourcesReportsEveryUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", overlayGatewayHCL)
	writeHCL(t, dir, "10-a.hcl", overlayEndpointsHCL)
	writeHCL(t, dir, "20-b.hcl", "")
	for _, name := range []string{"10-a.hcl", "20-b.hcl"} {
		if err := os.Chmod(filepath.Join(dir, name), 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.ReadFile(filepath.Join(dir, "10-a.hcl")); err == nil {
		t.Skip("this user reads files with no permissions")
	}
	_, diags := config.ReadSources(dir, nil)
	if len(diags) != 2 {
		t.Errorf("diagnostics = %s, want one per unreadable file", diags.Error())
	}
}

func TestReadSourcesSingleFileTakesNoOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.hcl")
	if err := os.WriteFile(path, []byte(overlayGatewayHCL), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, diags := config.ReadSources(path, map[string][]byte{"x.hcl": nil}); !diags.HasErrors() {
		t.Error("a single-file config accepted overrides")
	}
	sources, diags := config.ReadSources(path, nil)
	if diags.HasErrors() || string(sources["gateway.hcl"]) != overlayGatewayHCL {
		t.Errorf("sources = %q, %s", sources, diags.Error())
	}
}
