-- 0033_device_os_hostname — the OS hostname the CLI reported when the
-- device joined. Several devices can share one machine (one per OS
-- account, each on its own profile), and their names alone do not say
-- which machine they are on. The dashboard's Add device window uses it
-- to list a joining device's neighbours. Self-asserted by the client:
-- shown to the operator, never used to authorize anything. Rows that
-- predate this column carry NULL.

ALTER TABLE devices ADD COLUMN os_hostname TEXT;
