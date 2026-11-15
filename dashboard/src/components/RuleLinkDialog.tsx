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
  return {
    endpoint: q.get("endpoint") ?? "",
    verdict,
    condition: q.get("condition") ?? "",
    approver: q.get("approver") ?? "",
    profile: q.get("profile") ?? "",
    note: (q.get("note") ?? "").trim().slice(0, NOTE_MAX_CHARS),
    problems,
  };
}

// RuleLinkDialog opens the endpoint rule dialog filled in from a link an
// agent prepared. Nothing is written until the admin creates the rule.
export function RuleLinkDialog({
  query,
  isMember,
  onDone,
  onCreated,
}: {
  query: string;
  isMember: boolean;
  onDone: () => void;
  onCreated: () => void;
}) {
  const link = useMemo(() => parseRuleLink(query), [query]);
  const [endpoints, setEndpoints] = useState<RuleEndpoint[] | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (isMember) return;
    getMyRules()
      .then((r) => setEndpoints(r.endpoints ?? []))
      .catch((e) => setErr(String(e instanceof Error ? e.message : e)));
  }, [isMember]);

  const message = isMember
    ? "This link opens the rule dialog for an admin. Send it to an admin of the dashboard, or create the rule from your request on the Requests page."
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
  return (
    <EndpointRuleModal
      endpoint={ep.name}
      family={ep.family}
      profile={link.profile || undefined}
      initial={link}
      onClose={onDone}
      onCreated={onCreated}
    />
  );
}
