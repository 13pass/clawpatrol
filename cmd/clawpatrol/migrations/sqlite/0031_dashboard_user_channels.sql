-- 0031_dashboard_user_channels — where each user gets approval prompts.
--
-- One channel per user, set by the user in the dashboard. kind is the
-- notifier credential plugin type (signal_cli, later teams_workflow);
-- target is what the dashboard may show (a number, a group id), secret
-- what it never shows (a webhook URL). A channel receives prompts only
-- once verified_ns is set: the user typed back a code sent there.
-- code_hash is sha256 of that code; sent_ns throttles code and test
-- sends.

CREATE TABLE dashboard_user_channels (
  username         TEXT PRIMARY KEY,
  kind             TEXT NOT NULL,
  target           TEXT NOT NULL,
  secret           TEXT NOT NULL DEFAULT '',
  verified_ns      INTEGER NOT NULL DEFAULT 0,
  code_hash        TEXT NOT NULL DEFAULT '',
  code_expires_ns  INTEGER NOT NULL DEFAULT 0,
  code_attempts    INTEGER NOT NULL DEFAULT 0,
  sent_ns          INTEGER NOT NULL DEFAULT 0,
  updated_ns       INTEGER NOT NULL
);
