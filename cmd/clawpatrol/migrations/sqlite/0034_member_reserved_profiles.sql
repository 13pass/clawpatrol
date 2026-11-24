-- 0034_member_reserved_profiles — drop member assignments of the
-- gateway's reserved profiles.
--
-- Names starting with a NUL byte are reserved for the compiler
-- (config.IsReservedProfile: the defaults.unknown_peer = "no_profile"
-- profile, which also serves devices whose profile was removed). The
-- users API accepted them until it checked for them, and a member who
-- holds one sees the events of unknown peers and cut-off devices across
-- every team. No operator-declared profile name can start with NUL.
-- Matched on hex() because SQLite's text functions stop at a NUL.

DELETE FROM dashboard_user_profiles WHERE hex(profile) LIKE '00%';
