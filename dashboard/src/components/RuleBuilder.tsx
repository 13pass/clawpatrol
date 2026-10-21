import { useEffect, useState } from "react";
import {
  createRule,
  listUsers,
  previewRule,
  type EventRecord,
  type RulePreviewResp,
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
  const [preview, setPreview] = useState<RulePreviewResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ rule_name: string; file: string } | null>(null);

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

  useEffect(() => {
    if (!ev.id || created) return;
    let cancelled = false;
    const t = setTimeout(() => {
      previewRule(ev.id!, { verdict, scope, approver, pin_header: pinHeader || undefined })
        .then((p) => {
          if (cancelled) return;
          setPreview(p);
          setErr(null);
        })
        .catch((e: Error) => {
          if (cancelled) return;
          setPreview(null);
          setErr(e.message || "preview failed");
        });
    }, PREVIEW_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [ev.id, verdict, scope, pinHeader, approver, created]);

  async function create() {
    if (!ev.id) return;
    setBusy(true);
    try {
      setCreated(
        await createRule(ev.id, { verdict, scope, approver, pin_header: pinHeader || undefined }),
      );
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
        {created ? (
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
                  onChange={(e) => setScope(e.target.value as RuleScope)}
                  className={selectClass}
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
                    onChange={(e) => setPinHeader(e.target.value)}
                    className={selectClass}
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

            {err && <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>}
            {preview && (
              <div className="space-y-2">
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
            <Button disabled={!preview?.writes_enabled || busy} onClick={create}>
              {busy ? "Creating…" : "Create rule"}
            </Button>
          </>
        )}
      </div>
    </Modal>
  );
}
