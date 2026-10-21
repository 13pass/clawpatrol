-- 0025_dashboard_user_roles — a role per dashboard operator account.
--
-- `admin` keeps every power the single root operator has today.
-- `member` is denied every operator route unless the route is opened
-- to members explicitly (see doc/multi-user-dashboard.md). New rows
-- default to the least privilege; the bootstrap root row is an admin,
-- and the code refuses to demote it.

ALTER TABLE dashboard_users ADD COLUMN role TEXT NOT NULL DEFAULT 'member';
UPDATE dashboard_users SET role = 'admin' WHERE username = 'root';
