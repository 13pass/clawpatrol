# Per-user notification channels: plan

Status: draft (2026-10-29). Goal: every user has their own channel,
set in the web app, and the approval prompts for their profile's
requests go there and nowhere else. First a Signal number or group,
later Microsoft Teams. Today the operator gets every prompt, a pilot
member's included (Simon's on 2026-10-29).

## Today

- An approver's channel is fixed in HCL: `human_approver "operator"
  { channel = "<number or group.id>", credential = signal_cli.ops }`.
  `signal_cli.ops` is the one sender (api_url, number, auth in its
  secret slots).
- Rules pick the approver: `approve = [human_approver.operator]`. Every
  approval raised by the shared rules goes to the operator's channel,
  whichever profile made the request. Only an admin may decide them
  (`decidesPending`).
- A user has an admin-assigned `approver` (`dashboard_users.approver`),
  used only for the rules a member writes from the dashboard. Member
  rule writes need a directory-mode config, which we don't run yet.
- An agent can redirect a prompt: the `X-HITL-Channel` request header
  overrides the approver's channel (`main.go`, `NotifyChannel`). The
  header is stripped before the request goes upstream, but it is read
  first.
- Notifiers are credential plugins implementing `HITLNotifier`. A new
  channel kind is a new plugin; `human_approver` doesn't change.

## Decisions (proposed)

1. **The channel belongs to the dashboard user**, is stored in the
   gateway database and edited in the web app. It isn't HCL: no config
   write and no restart, and it works with our single-file config.
2. **A prompt goes to the owner of the requesting profile, by
   default.** Every approval raised for a profile is sent to its
   owner's channel only, and the owner decides it. The operator isn't
   notified; they still see every pending approval in the dashboard and
   can decide any of them. Channels are never shared: one per user.
   Two cases still go to the approver block's own `channel`:
   - **The profile has no owner** (`default`, or a profile no user is
     assigned to), or its owner hasn't verified a channel yet. Only
     admins decide these.
   - **Admin-only rules:** `route = "operator"` on an approver keeps its
     prompts with the operator for every profile (e.g. writes on shared
     credentials). The admin chooses which rules use it.
3. **One sender, many recipients.** Signal prompts still go out from
   `signal_cli.ops`; a user only sets the recipient (E.164 number or
   `group.<id>`). A channel becomes active only after a verification
   code sent there is typed back in the web app. Otherwise anyone could
   point prompts, which carry request paths, at a number they don't own.
4. **Teams comes as a notifier plugin**, first notification-only like
   Signal: a card with an "Open dashboard" link, sent to a Teams
   Workflows webhook the user creates and pastes. Approve buttons in
   Teams need a bot; that is a separate, optional phase.

## Phases

### 0. Ignore `X-HITL-Channel` from agents (security, independent)

Drop the header before the approval runs, not only before forwarding.
Nothing in our setup uses it. A one-commit PR with a test showing that
the header no longer changes the target.

### 1. Channel per user: storage, API, page

- Migration `0031_dashboard_user_channels.sql`: `username`, `kind`
  (`signal`, later `teams`), `target` (number / group id), `secret`
  (Teams webhook URL; never returned to the browser), `verified_at`,
  `code_hash`, `code_expires_at`, `updated_at`. One channel per user to
  start.
- Routes, scoped to the signed-in user: `GET /api/my/channel`, `POST
  /api/my/channel` (save it; it stays unverified and a code is sent),
  `POST /api/my/channel/verify`, `POST /api/my/channel/test`, `POST
  /api/my/channel/delete`. Code sends are rate-limited. Every change goes
  into the dashboard audit log.
- Admins: the Users page shows each user's channel and whether it is
  verified, and can clear it. Admins can't set a member's channel.
- Dashboard: a "Notifications" page where users enter the target,
  verify it and send a test.

### 2. Route approvals to profile owners

- `human_approver` gets `route` (`"profile_owner"`, the default once
  this ships, or `"operator"`) and `credentials = [...]` (one notifier
  per channel kind, e.g. `[signal_cli.ops, teams_workflow.users]`).
  `channel` / `credential` stay as the fallback.
- `Approve()` resolves the owners of `req.Profile`
  (`dashboard_user_profiles`), takes their verified channels, and
  notifies each through the notifier matching its kind. Several owners:
  everyone is notified, and the first decision wins.
- `HITLTarget` gets the per-channel secret (the Teams webhook URL), so
  a notifier doesn't look it up itself.
- `decidesPending`: a member also decides a pending approval for a
  profile they own, unless its approver is `route = "operator"`. The
  `delete_on_decision` and message-update hooks must handle several
  messages per prompt.
- Tests: an owner with a verified channel is notified and can decide;
  a member who doesn't own the profile can't see the prompt; a profile
  with no verified channel falls back to the operator.
- Our config: `human_approver "operator"` routes to profile owners, so
  every member's prompts (their GitLab and Fabric writes, with their own
  tokens) go to their own channel, and the operator's to `vincenth`'s.
  A second approver with `route = "operator"` is only for rules the
  operator must keep for everyone (see open question 1).

### 3. Teams, notification-only

- Credential plugin `teams_workflow`: posts an Adaptive Card (summary,
  masked headers via the message template, "Open dashboard" button)
  to the user's Workflows webhook URL. It escapes template values
  (`HITLMessageValueEscaper`). It has no secret slots of its own: the
  URL is per user.
- The page accepts a Teams channel by its webhook URL, checked to be
  HTTPS on a Microsoft host. Verification posts the code to that
  channel.
- To confirm with the UN tenant admins: users may create Workflows
  webhooks ("When a Teams webhook request is received"). Microsoft is
  retiring the older Office 365 connector webhooks, so we don't build
  on those.

### 4. Optional: approve from Teams

A Teams bot (Azure Bot + Entra app registration) posts the card with
Approve / Deny buttons to the gateway's webhook route, as the Slack
plugin does. The Teams user maps to a dashboard user through the Entra
ID sign-in link, and the decision goes through the same
`decidesPending` check. Needs a tenant-approved bot. Do it only if the
dashboard link turns out to be too slow in practice.

## Security notes

- Prompts carry request details (method, path, masked headers), so a
  channel is used only once verified, and only an admin assigns profiles.
- A Teams webhook URL is a bearer secret: write-only in the API, stored
  in the state DB like credential secrets (covered by the planned
  encrypted backups of the state dir).
- Routing to owners widens who decides: a member approves their own
  agent's writes. That is the point (their tokens, their accountability),
  and decisions are audited (`actions.approver_by`). Rules that must
  stay with the operator use `route = "operator"`.
- Migrations stay numbered above ours (0031+): see the rename plan on
  cherry-picks.

## Open questions

1. Which rules stay with the operator for everyone (`route =
   "operator"`)? Candidates: MR merges, CI/CD variable reads, and
   anything on a shared credential (Kubernetes, Sentry).
2. Can users create Teams Workflows webhooks in the UN tenant?
