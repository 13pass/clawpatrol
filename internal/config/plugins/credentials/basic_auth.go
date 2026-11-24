package credentials

// basic_auth: Authorization: Basic <base64(username:password)>.

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// BasicAuth injects `Authorization: Basic <base64(username:password)>`.
//
// The credential secret is the raw password. `username` is set in
// config or, when it is left out, entered on the dashboard next to the
// password (from the environment: CLAWPATROL_SECRET_<NAME>_USERNAME),
// which keeps a per-person account such as an email out of the config
// files. Common credential binding fields apply: use `endpoint` or
// `endpoints` to bind the credential to upstreams.
//
// When a profile has multiple Basic Auth credentials for the same HTTPS
// endpoint, use the `placeholder` disambiguator on the profile entry or
// credential block. The HTTPS placeholder detector matches that value
// inside decoded `Authorization: Basic <base64(username:placeholder)>`
// request headers.
type BasicAuth struct {
	// Username is the upstream HTTP Basic Auth username. Leave it out
	// to have the dashboard ask for it with the password.
	Username string `hcl:"username,optional"`
}

const basicAuthUsernameSlot = "username"

// InjectHTTP is part of the clawpatrol plugin API.
func (b *BasicAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	username := b.Username
	if username == "" {
		username = sec.Extras[basicAuthUsernameSlot]
		if (username == "") != (len(sec.Bytes) == 0) {
			return fmt.Errorf("basic_auth: missing %s", strings.Join(b.MissingSecretSlots(map[string]bool{
				basicAuthUsernameSlot: username != "",
				"":                    len(sec.Bytes) > 0,
			}), ", "))
		}
	}
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.SetBasicAuth(username, string(sec.Bytes))
	return nil
}

// MissingSecretSlots is part of the clawpatrol plugin API.
func (b *BasicAuth) MissingSecretSlots(stored map[string]bool) []string {
	var missing []string
	for _, s := range b.SecretSlots() {
		if !stored[s.Name] {
			missing = append(missing, s.Label)
		}
	}
	return missing
}

// SecretSlots is part of the clawpatrol plugin API.
func (b *BasicAuth) SecretSlots() []config.SecretSlot {
	if b.Username != "" {
		return []config.SecretSlot{{Label: "Password", Description: "Stamped as `Authorization: Basic …` with the configured username."}}
	}
	return []config.SecretSlot{
		{Name: basicAuthUsernameSlot, Label: "Username", Visible: true, Description: "The account name, often an email address."},
		{Label: "Password", Description: "Stamped with the username as `Authorization: Basic …`; the gateway does the encoding."},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*BasicAuth)(nil)
	var _ config.SecretCompleteness = (*BasicAuth)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "basic_auth",
		Disambiguators: []string{"placeholder"},
		New:            newer[BasicAuth](),
		Runtime:        (*BasicAuth)(nil),
		Build:          passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*BasicAuth)
			if v.Username != "" {
				b.SetAttributeValue("username", cty.StringVal(v.Username))
			}
		},
	})
}
