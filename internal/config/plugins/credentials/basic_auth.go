package credentials

// basic_auth: Authorization: Basic <base64(username:password)>.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// BasicAuth injects `Authorization: Basic <base64(username:password)>`.
//
// The credential secret is the raw password. `username` is set in
// config, or, when it is left out, entered on the dashboard next to the
// password, which keeps a per-person account (an email) out of the
// config files. Common credential binding fields apply: use `endpoint`
// or `endpoints` to bind the credential to upstreams.
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

// basicAuthUsernameSlot is the secret slot holding the username when
// the config sets none.
const basicAuthUsernameSlot = "username"

// InjectHTTP is part of the clawpatrol plugin API. Until both the
// username and the password are known it leaves the request as is.
func (b *BasicAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	username := b.Username
	if username == "" {
		username = sec.Extras[basicAuthUsernameSlot]
	}
	if len(sec.Bytes) == 0 || username == "" {
		return nil
	}
	req.SetBasicAuth(username, string(sec.Bytes))
	return nil
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
