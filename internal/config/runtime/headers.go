package runtime

import "regexp"

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
