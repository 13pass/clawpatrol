package main

import "testing"

func TestMergeProfileCredentialRefs(t *testing.T) {
	const add = "passthrough.p"
	cases := []struct {
		name, src, want string
	}{
		{"multi-line, blank line after",
			"profile \"alice\" {\n  credentials = [header_token.a]\n}\n\n# Bob\nprofile \"bob\" {\n  credentials = [header_token.a]\n}\n",
			"profile \"alice\" {\n  credentials = [header_token.a, passthrough.p]\n}\n\n# Bob\nprofile \"bob\" {\n  credentials = [header_token.a]\n}\n"},
		{"one-line block",
			"profile \"alice\" { credentials = [a.a] }\n\n# x\n",
			"profile \"alice\" { credentials = [a.a, passthrough.p] }\n\n# x\n"},
		{"CRLF",
			"profile \"alice\" {\r\n  credentials = [a.a]\r\n}\r\n\r\n# x\r\n",
			"profile \"alice\" {\r\n  credentials = [a.a, passthrough.p]\r\n}\r\n\r\n# x\r\n"},
		{"empty block",
			"profile \"alice\" {\n}\n\n# x\n",
			"profile \"alice\" {\n  credentials = [passthrough.p]\n}\n\n# x\n"},
		{"other attribute, no list",
			"profile \"alice\" {\n  hitl_async_grants = true\n}\n",
			"profile \"alice\" {\n  hitl_async_grants = true\n  credentials = [passthrough.p]\n}\n"},
		{"indented block",
			"  profile \"alice\" {\n    credentials = [a.a]\n  }\n\n  # x\n",
			"  profile \"alice\" {\n    credentials = [a.a, passthrough.p]\n  }\n\n  # x\n"},
		{"indented block, no list",
			"  profile \"alice\" {\n  }\n",
			"  profile \"alice\" {\n    credentials = [passthrough.p]\n  }\n"},
		{"comment and blank line in the body",
			"profile \"alice\" {\n  # owners\n\n  credentials = [a.a]\n}\n",
			"profile \"alice\" {\n  # owners\n\n  credentials = [a.a, passthrough.p]\n}\n"},
		{"blanks after the brace",
			"profile \"alice\" {  \n  credentials = [a.a]\n}\n",
			"profile \"alice\" {  \n  credentials = [a.a, passthrough.p]\n}\n"},
		{"object entry",
			"profile \"alice\" {\n  credentials = [{ credential = a.a, placeholder = \"PH\" }]\n}\n",
			"profile \"alice\" {\n  credentials = [{ credential = a.a, placeholder = \"PH\" }, passthrough.p]\n}\n"},
		{"multi-line list",
			"profile \"alice\" {\n  credentials = [\n    a.a,\n  ]\n}\n",
			"profile \"alice\" {\n  credentials = [\n    a.a,\n    passthrough.p,\n  ]\n}\n"},
		{"one-line block, no list",
			"profile \"alice\" { hitl_async_grants = true }\n\n# x\n",
			"profile \"alice\" {\n  hitl_async_grants = true\n  credentials = [passthrough.p]\n}\n\n# x\n"},
		{"empty one-line block",
			"  profile \"alice\" {}\n",
			"  profile \"alice\" {\n    credentials = [passthrough.p]\n  }\n"},
		{"already listed",
			"profile \"alice\" {\n  credentials = [passthrough.p]\n}\n",
			"profile \"alice\" {\n  credentials = [passthrough.p]\n}\n"},
	}
	for _, c := range cases {
		got, ok := mergeProfileCredentialRefs(c.src, "alice", []string{add})
		if !ok || got != c.want {
			t.Errorf("%s: ok=%v\ngot:  %q\nwant: %q", c.name, ok, got, c.want)
		}
	}
}

func TestMergeProfileCredentialRefsRefuses(t *testing.T) {
	for name, src := range map[string]string{
		"no such profile":          "profile \"bob\" {\n  credentials = [a.a]\n}\n",
		"text that does not parse": "profile \"alice\" {\n  credentials = [a.a\n",
		"brace after an attribute": "profile \"alice\" {\n  hitl_async_grants = true }\n",
	} {
		if got, ok := mergeProfileCredentialRefs(src, "alice", []string{"passthrough.p"}); ok || got != src {
			t.Errorf("%s: ok=%v got %q", name, ok, got)
		}
	}
}
