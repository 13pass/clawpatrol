import { useEffect, useMemo, useState } from "react";
import {
  createRule,
  listUsers,
  previewRule,
  type EventRecord,
  type RuleChangeResult,
  type RulePreviewResp,
  type RuleRequest,
  type RuleScope,
  type RuleVerdict,
  type Whoami,
} from "../lib/api";
import { Button } from "./Button";
import { Modal } from "./Modal";

// Recorded values the gateway masked; a rule cannot pin them.
const MASKED_HEADER_VALUE = "***";
const PREVIEW_DEBOUNCE_MS = 250;

const VERDICTS: { value: RuleVerdict; label: string; help: string }[] = [
  { value: "deny", label: "Deny", help: "Block matching requests." },
  { value: "allow", label: "Pre-approve", help: "Let matching requests through without review." },
  {
    value: "approve",
    label: "Require approval",
    help: "Hold matching requests until a human approves.",
  },
];

// scopesFor lists the scopes the server accepts for a request: a host
// with no endpoint can only be ruled as a whole.
function scopesFor(ev: EventRecord): { value: RuleScope; label: string }[] {
  if (!ev.endpoint) return [{ value: "exact", label: "This host" }];
  switch (ev.family) {
    case "http":
      return [
        { value: "exact", label: "This method and path" },
        { value: "any_method", label: "This path, any method" },
        { value: "any_path", label: "This method, any path" },
        { value: "pattern", label: "This method, same path shape (IDs generalized)" },
      ];
    case "k8s":
      return [
        { value: "exact", label: "This object" },
        { value: "any_name", label: "Any object of this resource and namespace" },
      ];
    default:
      return [{ value: "exact", label: "This statement" }];
  }
}

// RuleBuilderModal turns one recorded request into a rule. The server
// generates the HCL: for a member it is pinned to the request's
// profile and credential and written to the member's own file.
export function RuleBuilderModal({
  ev,
  whoami,
  onClose,
}: {
  ev: EventRecord;
  whoami: Whoami | null;
  onClose: () => void;
}) {
  const isAdmin = whoami?.role !== "member";
  const scopes = scopesFor(ev);
  const [verdict, setVerdict] = useState<RuleVerdict>("deny");
  const [scope, setScope] = useState<RuleScope>(scopes[0].value);
  const [pinHeader, setPinHeader] = useState("");
  const [approver, setApprover] = useState("");
  const [approvers, setApprovers] = useState<string[]>([]);
  // preview answers the request whose JSON is key; a preview for an
  // older request stays on screen but cannot be acted on.
  const [previewed, setPreviewed] = useState<{ key: string; resp: RulePreviewResp } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<RuleChangeResult | null>(null);
  const [reason, setReason] = useState("");
  // conditionText is null while the editor is closed. Blank, the rule
  // uses the generated condition and Matching applies again.
  const [conditionText, setConditionText] = useState<string | null>(null);
  const condition = conditionText?.trim() ? conditionText : undefined;

  const pinnable =
    ev.family === "http" && ev.endpoint
      ? Object.entries(ev.req_headers ?? {})
          .filter(([, v]) => v !== MASKED_HEADER_VALUE)
          .map(([k]) => k)
          .sort()
      : [];

  useEffect(() => {
    if (isAdmin) {
      listUsers()
        .then((u) => setApprovers(u.human_approvers))
        .catch(() => setApprovers([]));
    }
  }, [isAdmin]);

  // scope and pin_header go along with a condition: the server ignores
  // them then, but uses them to tell an unedited condition from one
  // written by hand.
  const request = useMemo<RuleRequest>(
    () => ({ verdict, scope, approver, pin_header: pinHeader || undefined, condition }),
    [verdict, scope, approver, pinHeader, condition],
  );
  const requestKey = JSON.stringify(request);
  const preview = previewed?.resp ?? null;
  const fresh = previewed?.key === requestKey;

  useEffect(() => {
    if (!ev.id || created) return;
    const id = ev.id;
    const key = JSON.stringify(request);
    const ctl = { cancelled: false };
    const t = setTimeout(() => {
      previewRule(id, request)
        .then((p) => {
          if (ctl.cancelled) return;
          setPreviewed({ key, resp: p });
          setErr(null);
        })
        .catch((e: Error) => {
          if (ctl.cancelled) return;
          setPreviewed(null);
          setErr(e.message || "preview failed");
        });
    }, PREVIEW_DEBOUNCE_MS);
    return () => {
      ctl.cancelled = true;
      clearTimeout(t);
    };
  }, [ev.id, request, created]);

  async function create() {
    if (!ev.id || !fresh) return;
    setBusy(true);
    try {
      setCreated(await createRule(ev.id, request, preview?.needs_review ? reason : undefined));
      setErr(null);
    } catch (e) {
      setErr((e as Error).message || "create failed");
    } finally {
      setBusy(false);
    }
  }

  const labelClass = "font-mono text-xs uppercase tracking-wider text-text-muted";
  const selectClass =
    "border border-canvas-dark rounded px-2 py-1.5 text-xs bg-canvas focus:outline-none focus:border-text";

  return (
    <Modal title="Create a rule from this request" size="lg" onClose={onClose}>
      <div className="p-4 space-y-4 overflow-auto">
        {created?.pending ? (
          <div className="space-y-2">
            <p className="text-sm text-text">
              Rule <code className="font-bold">{created.rule_name}</code> was sent to the admins for
              review. It applies once one approves it; you get their answer on your notification
              channel.
            </p>
            <p className="text-xs text-text-muted">
              Follow it on the{" "}
              <a href="#/rules" className="underline">
                Rules
              </a>{" "}
              page.
            </p>
          </div>
        ) : created ? (
          <div className="space-y-2">
            <p className="text-sm text-text">
              Rule <code className="font-bold">{created.rule_name}</code> was validated, written to{" "}
              <code>{created.file}</code> and loaded by the gateway.
            </p>
            <p className="text-xs text-text-muted">
              Manage it on the{" "}
              <a href="#/rules" className="underline">
                Rules
              </a>{" "}
              page.
            </p>
          </div>
        ) : (
          <>
            <fieldset className="space-y-2">
              <legend className={labelClass}>What should happen</legend>
              <div className="flex flex-wrap gap-2">
                {VERDICTS.map((v) => (
                  <label
                    key={v.value}
                    className={
                      "flex-1 min-w-[10rem] cursor-pointer border-1.5 px-3 py-2 text-xs " +
                      (verdict === v.value ? "border-navy bg-navy-100" : "border-canvas-dark")
                    }
                  >
                    <input
                      type="radio"
                      name="verdict"
                      value={v.value}
                      checked={verdict === v.value}
                      onChange={() => setVerdict(v.value)}
                      className="mr-2"
                    />
                    <span className="font-bold">{v.label}</span>
                    <span className="block text-text-muted mt-0.5">{v.help}</span>
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="flex flex-wrap gap-4">
              <label className="flex flex-col gap-1">
                <span className={labelClass}>Matching</span>
                <select
                  value={scope}
                  disabled={condition !== undefined}
                  onChange={(e) => setScope(e.target.value as RuleScope)}
                  className={selectClass + " disabled:opacity-60"}
                >
                  {scopes.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </label>
              {pinnable.length > 0 && (
                <label className="flex flex-col gap-1">
                  <span className={labelClass}>Only when header</span>
                  <select
                    value={pinHeader}
                    disabled={condition !== undefined}
                    onChange={(e) => setPinHeader(e.target.value)}
                    className={selectClass + " disabled:opacity-60"}
                  >
                    <option value="">— any request —</option>
                    {pinnable.map((h) => (
                      <option key={h} value={h}>
                        {h} = {ev.req_headers?.[h]}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {verdict === "approve" && isAdmin && (
                <label className="flex flex-col gap-1">
                  <span className={labelClass}>Reviewed by</span>
                  <select
                    value={approver}
                    onChange={(e) => setApprover(e.target.value)}
                    className={selectClass}
                  >
                    <option value="">the dashboard</option>
                    {approvers.map((a) => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {verdict === "approve" && !isAdmin && (
                <div className="flex flex-col gap-1">
                  <span className={labelClass}>Reviewed by</span>
                  <span className="text-xs py-1.5">
                    {whoami?.approver || "the dashboard"}{" "}
                    <span className="text-text-muted">(set by an admin)</span>
                  </span>
                </div>
              )}
            </div>

            {ev.endpoint && conditionText !== null && (
              <label className="block space-y-1">
                <span className="flex items-baseline justify-between gap-2">
                  <span className={labelClass}>Condition (CEL)</span>
                  <button
                    type="button"
                    onClick={() => setConditionText(null)}
                    className="text-2xs underline text-text-muted"
                  >
                    Use the generated condition
                  </button>
                </span>
                <textarea
                  value={conditionText}
                  onChange={(e) => setConditionText(e.target.value)}
                  rows={4}
                  spellCheck={false}
                  className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
                />
                <span className="block text-2xs text-text-subtle">
                  {pinnable.length > 0
                    ? "Replaces what Matching and Only when header generate; they apply again while it is empty."
                    : "Replaces what Matching generates; it applies again while this is empty."}{" "}
                  The rule keeps its endpoint{isAdmin ? "" : ", your profile and its credential"}.
                </span>
              </label>
            )}
            {ev.endpoint && conditionText === null && (
              <button
                type="button"
                disabled={previewed !== null && !fresh}
                onClick={() => setConditionText(fresh ? (preview?.rule.condition ?? "") : "")}
                className="text-xs underline text-text-muted disabled:opacity-60"
              >
                Edit the condition
              </button>
            )}

            {err && <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>}
            {preview && (
              <div className={"space-y-2" + (fresh ? "" : " opacity-60")}>
                <p className="text-xs text-text">
                  Would have matched{" "}
                  <span className="font-bold">
                    {preview.recent_matches} of the last {preview.recent_sampled}
                  </span>{" "}
                  {isAdmin ? "requests" : "requests of your profile"} to this{" "}
                  {preview.rule.new_endpoint ? "host" : "endpoint"}. Written to{" "}
                  <code>{preview.file}</code>.
                </p>
                {preview.rule.warnings?.map((w) => (
                  <div key={w} className="border border-butter-600 bg-butter-100 px-3 py-2 text-xs">
                    {w}
                  </div>
                ))}
                {!preview.writes_enabled && preview.writes_unavailable && (
                  <div className="border border-butter-600 bg-butter-100 px-3 py-2 text-xs">
                    This rule can't be saved from the dashboard: {preview.writes_unavailable}.
                  </div>
                )}
                <pre className="border-1.5 border-navy bg-canvas p-3 font-mono text-xs text-text overflow-auto max-h-[22rem]">
                  {preview.rule.hcl}
                </pre>

                {preview.needs_review && (
                  <div className="space-y-2 border border-navy bg-navy-100 px-3 py-2 text-xs">
                    <p>
                      This rule could let through requests your profile's other rules stop, so an
                      admin reviews it first. They may approve it, narrow it or reject it.
                    </p>
                    <label className="block space-y-1">
                      <span className="text-text-muted">Why do you need it? (optional)</span>
                      <textarea
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        rows={2}
                        className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
                      />
                    </label>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
      <div className="flex items-center gap-2 justify-end px-4 py-3 border-t border-navy bg-navy-100">
        {created ? (
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        ) : (
          <>
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button disabled={!fresh || !preview?.writes_enabled || busy} onClick={create}>
              {busy ? "Sending…" : preview?.needs_review ? "Send for review" : "Create rule"}
            </Button>
          </>
        )}
      </div>
    </Modal>
  );
}
