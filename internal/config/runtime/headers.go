package runtime

import (
	"net/http"
	"regexp"
	"strings"
)

// sensitiveHeaderRe matches header names that may carry a credential
// or a credential placeholder.
var sensitiveHeaderRe = regexp.MustCompile(
	`(?i)auth|token|secret|key|password|cookie`,
)

// IsSensitiveHeader reports whether the header must be masked before
// it reaches a human: the request log, the dashboard, or an approval
// card.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaderRe.MatchString(name)
}

// MaskedValue replaces the value of every sensitive header shown to a
// human.
const MaskedValue = "***"

// MaskedHeaders flattens h for display, joining repeated values with
// ", " and replacing sensitive values with MaskedValue.
func MaskedHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		if IsSensitiveHeader(name) {
			out[name] = MaskedValue
		} else {
			out[name] = strings.Join(values, ", ")
		}
	}
	return out
}
