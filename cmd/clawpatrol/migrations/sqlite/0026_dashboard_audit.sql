-- 0026_dashboard_audit — who did what on the dashboard.
--
-- One row per state-changing request to an operator route, plus login
-- attempts. Request bodies are never stored: credential values travel
-- in them. `target` is an optional handler-supplied identifier such as
-- the username an admin created.

CREATE TABLE dashboard_audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ns       INTEGER NOT NULL,
  username    TEXT NOT NULL,
  auth_kind   TEXT NOT NULL,
  method      TEXT NOT NULL,
  path        TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  status      INTEGER NOT NULL,
  remote_addr TEXT NOT NULL DEFAULT ''
);

CREATE INDEX dashboard_audit_ts ON dashboard_audit (ts_ns);
