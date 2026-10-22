-- 0029_dashboard_oidc — sign in through OpenID Connect providers
-- (gateway.dashboard_oidc "<provider>" blocks) as an admin-linked
-- dashboard user.
--
-- An admin links a user to an account at a provider (account: the
-- provider's username claim, e.g. a GitLab username or an Entra ID
-- UPN). The first sign-in as that account binds the provider's
-- permanent user id (subject, "<issuer>|<sub>"); from then on the
-- subject alone identifies the user, so a renamed or recycled account
-- name cannot take the user over. One link per user and provider; a
-- user may be linked at several providers. A user with an empty
-- password_hash has no password and signs in only through a provider.
--
-- dashboard_sessions.method records how a session was opened
-- ("password" or "oidc").

CREATE TABLE dashboard_user_oidc (
  provider TEXT NOT NULL,
  username TEXT NOT NULL,
  account  TEXT NOT NULL,
  subject  TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (provider, username)
);
-- Account names compare case-insensitively; one account links one user.
CREATE UNIQUE INDEX dashboard_user_oidc_account ON dashboard_user_oidc (provider, lower(account));
CREATE UNIQUE INDEX dashboard_user_oidc_subject ON dashboard_user_oidc (subject) WHERE subject != '';

ALTER TABLE dashboard_sessions ADD COLUMN method TEXT NOT NULL DEFAULT 'password';
