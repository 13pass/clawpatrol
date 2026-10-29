package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

// TeamsWorkflow delivers approval prompts to Microsoft Teams through a
// Workflows webhook ("When a Teams webhook request is received") that
// each user creates and pastes on the dashboard's Account page. It
// serves per-user channels only: the webhook URL is the user's channel
// secret, so the credential has no secret slots and no settings.
//
// Notification-only, like signal_cli: the card's "Approve or deny"
// button opens the dashboard, where the user decides. Office 365
// connector URLs (webhook.office.com) are refused; Microsoft disabled
// connectors in May 2026.
type TeamsWorkflow struct{}

var (
	teamsHTTPClient   = &http.Client{Timeout: 10 * time.Second}
	teamsRetryBackoff = 500 * time.Millisecond
	// teamsWebhookHosts are the hosts Workflows webhook URLs live on.
	teamsWebhookHosts = []string{".environment.api.powerplatform.com", ".logic.azure.com"}
)

const (
	teamsTextMax  = 3000
	teamsLabelMax = 64
	// teamsMarkdown are the characters that open a link or emphasis in
	// Teams card markdown; request values are escaped so they cannot.
	teamsMarkdown = "\\`*[]<>"
)

// ValidateChannel checks a Workflows webhook URL and the label the
// dashboard shows for it.
func (*TeamsWorkflow) ValidateChannel(ch runtime.UserChannel) error {
	if l := strings.TrimSpace(ch.Target); l == "" || len(l) > teamsLabelMax {
		return fmt.Errorf("give the channel a name of 1 to %d characters", teamsLabelMax)
	}
	return teamsCheckURL(ch.Secret)
}

func teamsCheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return errors.New("paste the HTTPS URL of a Teams Workflows webhook")
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasSuffix(host, ".webhook.office.com") {
		return errors.New("this is an Office 365 connector URL; Microsoft retired those, create a Workflows webhook instead")
	}
	for _, suffix := range teamsWebhookHosts {
		if strings.HasSuffix(host, suffix) {
			if !strings.Contains(u.Path, "/workflows/") || u.Query().Get("sig") == "" {
				return errors.New("this URL is not a Workflows webhook trigger URL")
			}
			return nil
		}
	}
	return errors.New("the URL must be on a Power Automate host (*.environment.api.powerplatform.com or *.logic.azure.com)")
}

// NotifyHITL posts the approval card to the user's webhook.
func (*TeamsWorkflow) NotifyHITL(ctx context.Context, req runtime.ApproveRequest, target runtime.HITLTarget) error {
	if err := teamsCheckURL(target.Secret); err != nil {
		return err
	}
	return teamsPost(ctx, target.Secret, teamsHITLCard(req, target))
}

// SendChannelText posts a verification code or test message.
func (*TeamsWorkflow) SendChannelText(ctx context.Context, _ runtime.SecretStore, _ string, ch runtime.UserChannel, text string) error {
	if err := teamsCheckURL(ch.Secret); err != nil {
		return err
	}
	return teamsPost(ctx, ch.Secret, teamsCard([]map[string]any{teamsText(text, false)}, nil))
}

// EscapeHITLMessageValue keeps template values from adding markdown.
func (*TeamsWorkflow) EscapeHITLMessageValue(s string) string {
	return teamsEscape(s)
}

func teamsEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(teamsMarkdown, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func teamsText(s string, bold bool) map[string]any {
	block := map[string]any{"type": "TextBlock", "text": s, "wrap": true}
	if bold {
		block["weight"] = "Bolder"
	}
	return block
}

func teamsCard(body []map[string]any, actions []map[string]any) map[string]any {
	content := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
	}
	if len(actions) > 0 {
		content["actions"] = actions
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     content,
		}},
	}
}

// teamsHITLCard renders the prompt. Every value from the request is
// escaped; the approver's message template was escaped value by value.
func teamsHITLCard(req runtime.ApproveRequest, target runtime.HITLTarget) map[string]any {
	title := runtime.HITLTitle(req.Method, runtime.HITLEndpointLabel(req))
	body := []map[string]any{teamsText("clawpatrol: "+teamsEscape(slackTrunc(title, 200)), true)}
	switch {
	case strings.TrimSpace(target.Message) != "":
		body = append(body, teamsText(slackTrunc(target.Message, teamsTextMax), false))
	case target.Summary != nil && target.Summary.Summary != "":
		body = append(body, teamsText(teamsEscape(slackTrunc(target.Summary.Summary, 500)), false))
	case req.Path != "":
		body = append(body, teamsText(teamsEscape(runtime.HITLQueryLabel(req.Endpoint)+": "+slackTrunc(req.Path, 800)), false))
	}
	var facts []map[string]any
	if req.Profile != "" {
		facts = append(facts, map[string]any{"title": "agent", "value": teamsEscape(slackTrunc(req.Profile, 80))})
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		facts = append(facts, map[string]any{"title": "reason", "value": teamsEscape(slackTrunc(r, 200))})
	}
	if len(facts) > 0 {
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	if bs := strings.TrimSpace(req.BodySample); bs != "" {
		body = append(body, teamsText(teamsEscape(slackTrunc(bs, 800)), false))
	}
	if g := slackHITLApprovalGuidance(target); g != "" {
		body = append(body, teamsText(teamsEscape(slackTrunc(g, 1000)), false))
	}
	link := strings.TrimRight(target.DashboardURL, "/") + "/#hitl/" + target.PendingID
	return teamsCard(body, []map[string]any{{"type": "Action.OpenUrl", "title": "Approve or deny", "url": link}})
}

// teamsPost sends the card, retrying once on a transient failure. The
// webhook URL carries its signature, so it never appears in an error.
func teamsPost(ctx context.Context, webhook string, card map[string]any) error {
	buf, err := json.Marshal(card)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(buf))
		if err != nil {
			return errors.New("teams webhook: bad URL")
		}
		req.Header.Set("Content-Type", "application/json")
		c := *teamsHTTPClient
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := c.Do(req)
		retry := true
		if err != nil {
			var uerr *url.Error
			if errors.As(err, &uerr) {
				err = uerr.Err
			}
			lastErr = fmt.Errorf("teams webhook: %v", err)
		} else {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("teams webhook: HTTP %d: %s", resp.StatusCode, slackTrunc(string(msg), 200))
			retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		}
		if attempt == 2 || !retry {
			break
		}
		log.Printf("teams notify: attempt %d failed, retrying once: %v", attempt, lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(teamsRetryBackoff):
		}
	}
	return lastErr
}

func init() {
	var _ runtime.HITLChannelSender = (*TeamsWorkflow)(nil)
	var _ runtime.HITLMessageValueEscaper = (*TeamsWorkflow)(nil)
	config.Register(&config.Plugin{
		Kind:  config.KindCredential,
		Type:  "teams_workflow",
		New:   newer[TeamsWorkflow](),
		Build: passthrough,
		Emit:  func(any, string, *hclwrite.Body) {},
	})
}
