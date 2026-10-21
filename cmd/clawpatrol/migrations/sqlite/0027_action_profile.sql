-- 0027_action_profile — record the profile the requesting peer was
-- bound to when each action happened.
--
-- A dashboard member may only see, and write rules from, the actions
-- of their own profiles. Resolving that from agent_ip at read time
-- would follow later profile reassignments; the column freezes the
-- answer the gateway used when it dispatched the request. NULL for
-- pre-existing rows and for events with no peer, which no member can
-- see.

ALTER TABLE actions ADD COLUMN profile TEXT;
CREATE INDEX actions_profile_id ON actions (profile, id);
