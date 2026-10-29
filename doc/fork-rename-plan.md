# Rename plan: from a Claw Patrol fork to a project of its own

Status: draft (2026-10-25). Decision: hard fork of
[denoland/clawpatrol](https://github.com/denoland/clawpatrol); upstream
changes are no longer merged wholesale. Done so far: telemetry off in
our gateway config (uninfo-agent-ops #59), and phase 1 step 2.

Constraint: the running gateway (`gateway.13pass.com`), the
uninfo-agent-ops scripts and the joined agent hosts keep working at every
step. Nothing in phases 1–3 changes the config format, state
location, environment variables or binary name they rely on.

## Phase 0: before anything public-facing

1. **Ownership and licence.** Confirm who owns the fork's own code and
   whether an employer open-source policy applies before publishing it
   under a new name and organisation. Upstream is MIT (Copyright 2026
   Deno Land Inc): any release keeps that notice.
2. **Pick a name** that is free as a GitHub repo, a domain and a Go
   module path, and does not include "Claw Patrol" or "clawpatrol":
   MIT grants the code, not the name, and the name is how users and bug
   reports find upstream.

## Phase 1: independence, no rename yet

Nothing user-visible changes; the fork stops depending on Deno's
infrastructure.

1. **Telemetry out.** Remove the update-check / usage ping
   (`cmd/clawpatrol/telemetry.go`, endpoint
   `https://clawpatrol.dev/api/telemetry/v1/check`) and its dashboard
   banner. Keep accepting `telemetry = …` in HCL and the
   `CLAWPATROL_TELEMETRY` / `DO_NOT_TRACK` variables as no-ops, so
   existing configs still validate. Until then, fork builds stay silent
   because they report version `dev`, and our gateway config sets
   `telemetry = false` (uninfo-agent-ops PR #59). This must land before
   phase 1 step 4: a version-stamped build pings by default.
2. **`integration` is what we run** (done). Feature branches start
   from it and merge back into it; the gateway host builds it. `main`
   mirrors upstream's `main`, the base for cherry-picks.
3. **Upstream fixes by cherry-pick.** Security fixes (like upstream
   #862) are picked one by one. Upstream's new migrations are renumbered
   above ours: the migrator applies only files numbered above the
   highest applied version, so an upstream `0025_*` would be skipped
   silently on our database (already at `0030`). Add a test that fails
   when two migration files share a number, so a careless pick fails
   the build.
4. **Our own releases.** Replace upstream's workflows:
   - `deploy-demo.yml` and `pr-preview.yml` deploy to
     `demo.clawpatrol.dev` with Deno's token: delete them.
   - `release.yml` signs and notarises a macOS app with Deno's Apple
     credentials: replace it with a Linux release (gateway and client,
     amd64 and arm64, checksums), version-stamped.
   - Keep `ci.yml`.
5. **Our own client.** Agent hosts install the official client from
   `clawpatrol.dev/install.sh` today (`upgrade-agent.sh`), so client
   fixes such as `fix/daemon-retires-after-rejoin` never reach them.
   Point `upgrade-agent.sh` (and `install.sh`) at our releases, and the
   reinstall hints in `setup.go` and `run_darwin.go`.

Gate: `deploy-gateway.sh` deploys unchanged, an agent host upgrades to
the fork client and `clawpatrol run -- claude` works, policy tests pass.

## Phase 2: rename what people read

No runtime identifier changes.

1. **Repository.** Rename the GitHub repo (GitHub redirects the old
   URL, so existing clones and the gateway host's remote keep working;
   update them anyway). Optionally detach it from the fork network.
2. **README and attribution.** New name, one paragraph stating it is a
   fork of Claw Patrol by Deno Land Inc under MIT, what it adds
   (multi-user dashboard, OIDC sign-in, directory-mode writes, member
   scoping), and that it is not affiliated with or supported by Deno.
   `LICENSE.md` keeps Deno's notice and adds ours.
3. **Dashboard and CLI text.** Product name in the dashboard (8 files
   under `dashboard/src`) and in CLI help and messages.
4. **Docs site.** Drop the telemetry receiver (`site/worker/`,
   `site/migrations/`, `site/sql/telemetry/`) and anything that
   publishes to clawpatrol.dev; host the docs elsewhere or keep them in
   the repo only.

## Phase 3: the Go module path

`module github.com/denoland/clawpatrol` → the new repo path:
`go mod edit -module …` plus a rewrite of the imports (253 files), in a
commit that contains nothing else. No runtime effect.

Trade-off: after it, every upstream cherry-pick needs its imports
rewritten (a one-line `sed`, worth scripting). Do it once phase 1's
release flow is stable.

## Kept as they are (compatibility)

Renaming any of these would break our config, scripts, joined devices
or stored state, for no user benefit:

| Identifier | Why it stays |
|---|---|
| The `clawpatrol` binary and its subcommands | uninfo-agent-ops scripts, the systemd unit, `clawpatrol run -- claude` on agent hosts. If a new binary name ships, `clawpatrol` stays as an alias. |
| HCL syntax and `schema_version` | `gateway.example.hcl`, policy tests. |
| `CLAWPATROL_*` environment variables (38 names, incl. `CLAWPATROL_SECRET_*`) | Secrets and run-time switches already set on hosts. New-prefix aliases can be added later; the old names never go. |
| `~/.clawpatrol` (state, CA, `clawpatrol.db`), `/etc/clawpatrol`, unit `clawpatrol-gateway.service` | The live gateway's state and secrets. |
| SQLite schema and migration numbering | The live database. |
| Plugin protocol package `clawpatrol.plugin.v1` | Wire compatibility with external plugins. |
| Kubernetes label keys `clawpatrol.dev/*` | Cleanup of tunnel resources created under the old keys. |
| macOS bundle ids `dev.clawpatrol.app*` | We don't ship the macOS app; untouched. |
