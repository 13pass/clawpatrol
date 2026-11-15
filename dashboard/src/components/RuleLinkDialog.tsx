import { useEffect, useMemo, useState } from "react";
import { getMyRules, type RuleEndpoint, type RuleVerdict } from "../lib/api";
import { EndpointRuleModal } from "./EndpointRuleModal";
import { Modal } from "./Modal";

// A link's note is shown to the human; past this it is cut.
const NOTE_MAX_CHARS = 500;
const LINK_VERDICTS: RuleVerdict[] = ["deny", "allow", "approve"];

export type RuleLink = {
  endpoint: string;
  verdict: RuleVerdict;
  condition: string;
  approver: string;
  profile: string;
  note: string;
  // prepared is false for a bare link, such as the one the gateway puts
  // on a refused request: it opens the dialog without filling it in.
  prepared: boolean;
  // problems are what the link asked for and the dialog could not take.
  problems: string[];
};

export function parseRuleLink(query: string): RuleLink {
  const q = new URLSearchParams(query);
  const problems: string[] = [];
  const asked = q.get("verdict") ?? "";
  let verdict: RuleVerdict = "deny";
  if (LINK_VERDICTS.includes(asked as RuleVerdict)) {
    verdict = asked as RuleVerdict;
  } else {
    problems.push(
      asked
        ? `The link asks for verdict "${asked}", which is not deny, allow or approve: Deny is selected.`
        : "The link names no verdict: Deny is selected.",
    );
  }
  let approver = q.get("approver") ?? "";
  if (approver && verdict !== "approve") {
    problems.push(
      `The link names reviewer "${approver}", but a reviewer only applies to Require approval: it is ignored.`,
    );
    approver = "";
  }
  const condition = q.get("condition") ?? "";
  const lines = condition.split("\n").length;
  if (lines > 1) {
    problems.push(`The condition spans ${lines} lines: read all of it before creating the rule.`);
  }
  return {
    endpoint: q.get("endpoint") ?? "",
    verdict,
    condition,
    approver,
    profile: q.get("profile") ?? "",
    note: (q.get("note") ?? "").trim().slice(0, NOTE_MAX_CHARS),
    prepared: [...q.keys()].some((k) => k !== "rule"),
    problems,
  };
}

// RuleLinkDialog opens the endpoint rule dialog filled in from a link an
// agent prepared. Nothing is written until the admin creates the rule.
export function RuleLinkDialog({
  query,
  isMember,
  roleKnown,
  onDone,
  onCreated,
}: {
  query: string;
  isMember: boolean;
  // roleKnown is false until the viewer's role has loaded.
  roleKnown: boolean;
  onDone: () => void;
  onCreated: () => void;
}) {
  const link = useMemo(() => parseRuleLink(query), [query]);
  const [endpoints, setEndpoints] = useState<RuleEndpoint[] | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!roleKnown || isMember) return;
    getMyRules()
      .then((r) => {
        if (r.unavailable) setErr(r.unavailable);
        else setEndpoints(r.endpoints ?? []);
      })
      .catch((e) => setErr(String(e instanceof Error ? e.message : e)));
  }, [roleKnown, isMember]);

  if (!roleKnown) return null;
  const message = isMember
    ? "This link opens the rule dialog for an admin. Send it to an admin of the dashboard, or ask the agent for the link to the request it was refused, which you can open."
    : err ||
      (endpoints && !endpoints.some((e) => e.name === link.endpoint)
        ? `The link names endpoint "${link.endpoint}", which this gateway does not declare.`
        : "");
  if (message) {
    return (
      <Modal title="Rule link" size="md" onClose={onDone}>
        <p className="p-5 text-sm text-text">{message}</p>
      </Modal>
    );
  }
  const ep = endpoints?.find((e) => e.name === link.endpoint);
  if (!ep) return null;
  const initial = { ...link, problems: [...link.problems] };
  if (link.profile && !ep.profiles.includes(link.profile)) {
    initial.problems.push(
      `The link limits the rule to profile "${link.profile}", which does not reach ${ep.name}: the rule is not limited.`,
    );
    initial.profile = "";
  }
  return (
    <EndpointRuleModal
      key={query}
      endpoint={ep.name}
      family={ep.family}
      profile={initial.profile || undefined}
      initial={initial}
      onClose={onDone}
      onCreated={onCreated}
    />
  );
}
