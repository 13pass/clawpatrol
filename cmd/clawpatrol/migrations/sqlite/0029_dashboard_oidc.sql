-- 0029_dashboard_oidc — sign in through an OpenID Connect provider
-- (GitLab.com) as an admin-linked dashboard user.
--
-- An admin links a user to a provider username (oidc_username). The
-- first sign-in as that username binds the provider's permanent user
-- id (oidc_subject, "<issuer>|<sub>"); from then on the subject alone
-- identifies the user, so a renamed or recycled provider username
-- cannot take the account over. A user with an empty password_hash has
-- no password and can only sign in through the provider.
--
-- dashboard_sessions.method records how a session was opened
-- ("password" or "oidc"), for display and for the password-change
-- check.

ALTER TABLE dashboard_users ADD COLUMN oidc_username TEXT NOT NULL DEFAULT '';
ALTER TABLE dashboard_users ADD COLUMN oidc_subject TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX dashboard_users_oidc_subject ON dashboard_users (oidc_subject) WHERE oidc_subject != '';

ALTER TABLE dashboard_sessions ADD COLUMN method TEXT NOT NULL DEFAULT 'password';
