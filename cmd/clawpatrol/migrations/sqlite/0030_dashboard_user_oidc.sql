-- 0030_dashboard_user_oidc — links to several sign-in providers.
--
-- gateway.dashboard_oidc became a repeatable, named block, so a user
-- may be linked at several providers: one row per user and provider
-- (provider = the block's name). account is the provider's username
-- claim as an admin linked it; subject ("<issuer>|<sub>") is bound at
-- the first sign-in and decides from then on.
--
-- Links made under 0029's single provider (dashboard_users.oidc_*)
-- move here under the provider name "gitlab", the name the setup guide
-- gives that block. Those columns stay, unused.

CREATE TABLE dashboard_user_oidc (
  provider TEXT NOT NULL,
  username TEXT NOT NULL,
  account  TEXT NOT NULL,
  subject  TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (provider, username)
);
-- Account names compare case-insensitively; one account links one user.
CREATE UNIQUE INDEX dashboard_user_oidc_account ON dashboard_user_oidc (provider, lower(account));
-- Per provider: two blocks may share an issuer (two apps at GitLab.com).
CREATE UNIQUE INDEX dashboard_user_oidc_subject ON dashboard_user_oidc (provider, subject) WHERE subject != '';

INSERT INTO dashboard_user_oidc (provider, username, account, subject)
SELECT 'gitlab', username, oidc_username, oidc_subject
FROM dashboard_users WHERE oidc_username != '';
