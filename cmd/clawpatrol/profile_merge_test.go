package main

import (
	"strings"
	"testing"
)

const profileMergeSource = `# Alice
credential "header_token" "a" {
  header   = "X"
  endpoint = https.x
}

profile "alice" {
  credentials = [header_token.a]
}

# Bob
profile "bob" {
  credentials = [header_token.a]
}
`

func TestMergeProfileCredentialRefsKeepsTheLayout(t *testing.T) {
	got, ok := mergeProfileCredentialRefs(profileMergeSource, "alice", []string{"passthrough.p"})
	if !ok {
		t.Fatal("not merged")
	}
	want := strings.Replace(profileMergeSource, "credentials = [header_token.a]\n}\n\n# Bob",
		"credentials = [header_token.a, passthrough.p]\n}\n\n# Bob", 1)
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMergeProfileCredentialRefsOneLineBlock(t *testing.T) {
	src := "profile \"alice\" { credentials = [header_token.a] }\n\n# next\n"
	got, ok := mergeProfileCredentialRefs(src, "alice", []string{"passthrough.p"})
	if !ok || !strings.Contains(got, "credentials = [header_token.a, passthrough.p]") || !strings.HasSuffix(got, "}\n\n# next\n") {
		t.Errorf("ok=%v got:\n%s", ok, got)
	}
}
