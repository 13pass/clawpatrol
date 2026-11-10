-- 0032_rule_requests — member rule changes waiting for an admin.
--
-- A member's change that could loosen their profile (a new pre-approval
-- or required approval, disabling or deleting a deny) is not written to
-- their rules file: it waits here until an admin approves, edits and
-- approves, or rejects it, or the member withdraws it. kind is create,
-- disable, enable or delete. hcl is the rule snippet of a create,
-- replaced by the admin's version when they edit it (edited = 1).
-- status is pending, approved, rejected or withdrawn.

CREATE TABLE rule_requests (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  username       TEXT NOT NULL,
  kind           TEXT NOT NULL,
  rule_name      TEXT NOT NULL,
  profile        TEXT NOT NULL DEFAULT '',
  summary        TEXT NOT NULL DEFAULT '',
  hcl            TEXT NOT NULL DEFAULT '',
  reason         TEXT NOT NULL DEFAULT '',
  status         TEXT NOT NULL DEFAULT 'pending',
  created_ns     INTEGER NOT NULL,
  decided_by     TEXT NOT NULL DEFAULT '',
  decided_ns     INTEGER NOT NULL DEFAULT 0,
  decision_note  TEXT NOT NULL DEFAULT '',
  edited         INTEGER NOT NULL DEFAULT 0
);

-- One pending request per member and rule.
CREATE UNIQUE INDEX rule_requests_one_pending
  ON rule_requests (username, rule_name) WHERE status = 'pending';
CREATE INDEX rule_requests_status ON rule_requests (status, id);
