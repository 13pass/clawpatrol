-- 0028_dashboard_user_profiles — which profiles a dashboard user owns,
-- and the approver their "require approval" rules route to.
--
-- A member sees, and writes rules for, only the requests of profiles
-- they own. Several users may own one profile (a team). Profile and
-- approver names refer to the HCL config; a name the config no longer
-- declares is ignored where it is used.

CREATE TABLE dashboard_user_profiles (
  username TEXT NOT NULL,
  profile  TEXT NOT NULL,
  PRIMARY KEY (username, profile)
);

ALTER TABLE dashboard_users ADD COLUMN approver TEXT NOT NULL DEFAULT '';
