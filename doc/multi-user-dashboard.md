# Multi-user dashboard — design

Today the dashboard has exactly one operator: every password session
is `root`, and every authenticated request can read and change the
whole gateway. This document proposes letting several people log in,
each managing the credentials and rules of their own profiles, while
gateway-wide configuration stays with administrators.

The target workflow: a user opens any request one of their agents
made — allowed or denied — and turns it into a rule with one click:
**deny**, **pre-approve**, or **require human approval**. The rule is
authored by a human from a real request, so it applies immediately;
the audit log records who wrote it.

## TL;DR

- Two roles: `admin` (today's root powers) and `member`. Members are
  denied every existing API by default; each phase opens scoped
  endpoints to them explicitly.
- A user owns one or more **profiles** (the existing tenancy unit).
  Everything a member sees or changes is reached through their
  profiles: devices, requests, credentials, rules, pending approvals.
- Member rules live in a per-user file, `50-user-<name>.hcl`, of a
  directory-mode config. The server generates the HCL from a request;
  members never send raw HCL.
- Every generated rule is pinned with `credential = <the credential
  the request used>` and held to a priority band below admin
  guardrails, so it only touches the author's own traffic and can never
  override an admin deny.
- A `dashboard_audit` table records who did what for every
  state-changing dashboard call.

## Current state

Single tenant by design. `migrations/sqlite/0001_initial.sql` says the
owner concept is "intentionally absent … Profile is the tenancy unit";
`0011_credentials_global.sql` removed per-profile secrets.

- **Identity.** `dashboardAuthGate` (`cmd/clawpatrol/web.go`) reads the
  session's username, then discards it and injects
  `dashboardPasswordPrincipal()`, hardcoded to `root`. `/__login` has
  no username field. The `dashboard_users` / `dashboard_sessions`
  tables already carry a username column "for future operators".
- **Authorization.** None beyond authentication. Every `authDashboard`
  route accepts any session: credentials, OAuth, devices, profiles,
  HITL decisions, config, plugins.
- **Rule generation.** `GenerateRuleFromEvent` (`rulegen.go`) supports
  only `deny` on an exact method + path. A request with no endpoint
  generates a new endpoint plus a passthrough credential added to
  *every* profile.
- **Config writes.** `/api/config/apply` appends arbitrary
  client-supplied HCL to a single file; it fails in directory mode
  (`os.ReadFile` on a directory), and `watchConfig` polls only the
  path's mtime, which misses in-place edits inside a directory.
- **Audit.** No record of dashboard actions. HITL decisions store the
  deciding principal (`actions.approver_by`), which is always `root`
  for password sessions.

Relevant rule semantics (`site/doc/rules.md`): rules attach to
endpoints and are shared by every profile reaching that endpoint;
they are sorted by `priority` (descending), first match wins, and a
rule's `credential = X` predicate restricts it to requests dispatched
against credential X.

## Model

| Concept | Owner | Where |
|---|---|---|
| Dashboard user, role | admin | `dashboard_users` |
| User → profiles | admin | `dashboard_user_profiles` (phase 3) |
| `gateway`, `defaults`, `plugin`, `tunnel`, shared endpoints/approvers, guardrail rules | admin | `00-*.hcl`, Git-managed |
| Credentials and endpoints of a profile (declaration) | admin | `00-*.hcl` (v1); forms later |
| Credential secrets (values, OAuth) of an owned profile | member | DB, existing screens, scoped |
| Rules generated from owned requests | member | `50-user-<name>.hcl`, dashboard-managed |
| Devices bound to an owned profile | member | `devices`, scoped |
| Pending approvals of owned profiles | member | HITL pool, scoped |

Usernames are `^[a-z][a-z0-9-]{1,31}$` because they become the
`<user>-` prefix of every block name the user's file declares (names
are global per kind across a directory config).

## Phases

### Phase 1 — identity, roles, audit (done)

- Migration: `dashboard_users.role` (`admin` | `member`, root forced
  to `admin`; an unrecognised stored role reads as `member`) and a
  `dashboard_audit` table.
- Login takes a username (empty means `root`, so existing scripts and
  the first-run flow keep working). Unknown usernames cost the same
  bcrypt work as a wrong password and get the same error.
- The principal carries the real username and role. Tailnet operators
  (the `operators` allowlist) are admins.
- **Deny by default for members**: a role gate after authentication
  refuses a member any `/api/` route and any registered operator
  route not on an explicit member allowlist. In this phase the
  allowlist is only `/api/me`, `/api/me/password` and `/__logout`, so
  adding a member is safe before any scoping exists.
- Admin API: `GET /api/users`, `POST /api/users/create`,
  `POST /api/users/update` (role and/or a member's password),
  `POST /api/users/delete`. Invariants: `root` cannot be deleted or
  demoted (the first-run check keys on its row), an admin cannot
  change their own role, and an admin's password is never reset by
  another admin — that would let one admin act under another's
  name in the audit log.
- Self-service: `GET /api/me`, `POST /api/me/password` (requires the
  current password; rotating revokes all sessions, then re-mints the
  caller's).
- Login rate limiting: failures per username (unknown names share
  one bucket) and per client address; see the security model.
- Audit middleware: every state-changing request to an operator route
  records time, username, auth kind, method, path, status and remote
  address; handlers may attach a target (e.g. the username created).
  Requests the role gate refuses and login attempts are recorded too.
  Bodies are never stored. `GET /api/audit` (admin) pages through it;
  `gateway.dashboard_audit_keep` (default 365 days) bounds it.
- UI: username field on the login page; Users admin page and
  change-password on the Account page.

### Phase 2 — directory-mode config writes (done)

Built on its own branch off `main` (`feat/config-dir-writes`) so it
can go upstream alone; details in `doc/multi-file-config.md`.

- `GET /api/config/files` lists the files with a revision each;
  `GET /api/config?file=` reads one.
- `/api/config/apply` targets one file (default `90-dashboard.hcl`
  in directory mode) with a per-file revision, and merges generated
  profile credential lists into the file declaring the profile.
- Validation loads the directory with the changed files swapped in
  memory (`config.LoadDirOverlay`), so includes still resolve; then
  each file is renamed into place and the config reloads.
- The watcher fingerprints every file, catching in-place edits.
- The plugin lockfile stays in the parent directory: its name ends
  in `.hcl`, so inside the config directory it would be loaded as
  config.

### Phase 3 — rules from requests (done)

Built as planned, with three changes found on the way:

- **Rules can be pinned to a profile** (`profile = profile.X`, a
  predicate checked like `credential`). Credentials are global and
  several profiles can list one, so the planned `credential =` pin
  alone would have let a member's rule reach other profiles sharing
  that credential. Every member rule carries both pins.
- **Each action records its profile** (`actions.profile`, stamped by
  the event sink from the peer IP), so a member's view does not follow
  later profile reassignments.
- **Members see their own requests** — `GET /api/my/actions` and
  `GET /api/actions/<id>` (404 outside their profiles) were pulled
  forward from phase 4, since a rule is made from a request.

Routes: `POST /api/rules/preview`, `POST /api/rules/create` (admins:
`90-dashboard.hcl`, unpinned, priority 100), `GET /api/my/rules`,
`POST /api/my/rules/update` (disable / enable), `POST
/api/my/rules/delete`. Admins assign profiles and the approver on the
Users page.

A review of phase 3 changed one design point: member rules sit at
priority 50, above admin rules at the default 0, so a plain member
`allow` would have undone admin denies — catch-alls included. Member
pre-approvals now carry `yield_to_deny` (a rule attribute the engine
honours in `MatchRequest`): they skip admin approvals but never an
admin deny. Rule edits need the member to still own the rule's
profile, and a deleted user's file is renamed to
`50-former-user-<name>-<time>.hcl` so it keeps applying, unowned.

- `dashboard_user_profiles(username, profile)`, admin-managed.
- Rule dialog on the request page: verdict (`deny`, `allow`,
  `approve = [<user's approver>]`) × scope (exact method + path; any
  method on the path; path pattern with ID segments generalized; and,
  with the `{{http.headers.*}}` work, "only this caller" on a
  caller-ID header).
- Preview shows the generated HCL and how many recent actions it would
  have matched, evaluated against the request log.
- The server generates the rule and writes it to `50-user-<name>.hcl`.
  Guardrails added unconditionally:
  - `credential = <credential the request used>` — the rule only
    matches the author's traffic, even on a shared endpoint;
  - `priority` clamped to the member band (1–99); admin guardrails
    use ≥ 100, so an admin deny always wins under first-match;
  - for a request with no endpoint, only `deny` / `approve`, and the
    generated endpoint + passthrough credential join the author's
    profiles only.
- "My rules": list, disable (`disabled = true`), delete.
- Each user has a default approver (own Slack / Signal channel, or
  dashboard-only), set by an admin.
- The client sends `{action_id, verdict, scope, approver}`; raw-HCL
  `/api/config/apply` stays admin-only.

### Phase 4 — scope every API (done)

Built as listed below, with these decisions:

- A member manages a credential's secret only when every profile
  using it is theirs (`viewer.managesCredential`); a shared credential
  is visible but admin-managed. OAuth sessions record who started
  them.
- A member decides only approvals raised by rules of their own file
  (`HITLPending` now carries `profile` and `rule`).
- The live stream re-reads the member's profiles on every keepalive.
- Clearing a credential's secrets when it leaves the HCL was dropped:
  doing it on reload would wipe the secret of a credential commented
  out for a moment. Orphans stay; a re-declared name reuses them.

Original plan:

The security-critical phase. Each route gets an ownership check or a
filter, and a cross-tenant test (user A against user B's resource must
get 403/404):

- credentials, OAuth (sessions remember who started them), Tailscale
  credential flows: own profiles' credentials only;
- devices: list/delete/profile-assign within own profiles; onboarding
  approval only into an own profile;
- HITL: pending list and decide filtered by profile — needs the
  profile on `HITLPending`;
- `/api/state`, `/api/events`, `/api/actions/`, `/api/analytics`,
  `/api/rules`: filtered — needs a `profile` column on `actions`;
- `/api/config`, `/api/plugins*`, `/api/profiles` writes,
  `/api/config/apply`: admin only.

Deleting a credential from HCL also clears its stored secrets;
declaring a credential refuses when orphaned secrets with that name
exist, so a new name never inherits old secret material.

### Phase 5 — frontend

Role-aware navigation, rule dialog, "My rules", users and
user-profile administration, filtered credential cards.

### Single sign-on (done)

Each `gateway.dashboard_oidc "<name>"` block adds sign-in through an
OpenID Connect provider — GitLab.com by default, Entra ID, Google,
Keycloak, a self-managed GitLab — side by side, with per-provider
`scopes`, `username_claim`, `groups_claim`, `groups_source` and
`group_match` (defaults suit GitLab.com, any GitLab with
`kind = "gitlab"`, and the common convention elsewhere; an `email`
username needs `email_verified`). Accounts are admin-linked, one link per user and provider
(`dashboard_user_oidc`): the first sign-in binds the provider's
permanent subject id, and only a bound subject decides afterwards; an
admin can reset the binding for a recreated provider account. Links at
a removed provider are kept and can be unlinked; no change may leave a
user with no way to sign in. Migration 0030 moved the earlier
single-provider links to the provider name `gitlab`.
Optional `allowed_groups` refuses non-members first. Sessions record
their method (`password` / `oidc`); a linked user may have no
password. Setup: `site/doc/configure-gateway.md`.

### Notification channels (done)

Each user sets one channel on the Account page (a Signal number or
`group.<id>`) and verifies it with a code sent there
(`dashboard_user_channels`, migration 0031). A `human_approver` with
`route = "profile_owner"` sends each prompt to the verified channels of
the requesting profile's owners, and those owners may decide it from
the dashboard, whichever rule raised it. Its own `channel` and
`credential` are the fallback, used when no owner has a verified
channel; admins still see and decide everything. The sender for a
channel kind is the first declared credential of that type
(`signal_cli`). Plan: `doc/notification-channels.md`.

### Later

TOTP, Git export of user
files, a form to declare new credentials and endpoints.

## Risks

- **Fork drift.** Upstream is single-tenant on purpose and moves
  quickly. Phases 1–2 and the audit log are generic; propose them
  upstream as separate PRs. Open an upstream issue before phases 3–4.
- **Global names.** Secret rows, OAuth tokens and the
  `CLAWPATROL_SECRET_<NAME>` env fallback are keyed by bare name; the
  `<user>-` prefix and orphan check above are what keep tenants apart.
- **Shared endpoints.** Without the forced `credential =` predicate a
  member rule would apply to every profile reaching the endpoint.
- **Dashboard-managed files.** `50-user-*.hcl` lives on the gateway's
  persistent volume, not in Git; it must be in the backup set, and
  the admin deploy must never overwrite it.
- **Fallback.** If this proves too costly, one gateway per team needs
  no code.
