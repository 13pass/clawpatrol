import { useId, useMemo, useRef, useState } from "react";
import {
  createRule,
  previewRule,
  type EventRecord,
  type RuleChangeResult,
  type RulePreviewResp,
  type RuleRequest,
  type RuleScope,
  type RuleVerdict,
  type Whoami,
} from "../lib/api";
import { Modal } from "./Modal";
import {
  RULE_LABEL_CLASS,
  RULE_SELECT_CLASS,
  ReviewerSelect,
  RuleDialogFooter,
  RulePreviewPane,
  VerdictPicker,
  useApprovers,
  useRulePreview,
} from "./RuleDialogParts";

// Recorded values the gateway masked; a rule cannot pin them.
const MASKED_HEADER_VALUE = "***";

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
  const newHost = !ev.endpoint;
  const scopes = scopesFor(ev);
  // A host no endpoint claimed already passes through, so allowing it
  // means nothing; only an admin adds one without a rule.
  const verdicts: RuleVerdict[] = newHost
    ? isAdmin
      ? ["none", "deny", "approve"]
      : ["deny", "approve"]
    : ["deny", "allow", "approve"];
  const [verdict, setVerdict] = useState<RuleVerdict>(verdicts[0]);
  const [scope, setScope] = useState<RuleScope>(scopes[0].value);
  const [pinHeader, setPinHeader] = useState("");
  const [approver, setApprover] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<RuleChangeResult | null>(null);
  const [reason, setReason] = useState("");
  // null while the editor is closed.
  const [conditionText, setConditionText] = useState<string | null>(null);
  const condition = conditionText?.trim() ? conditionText : undefined;
  const prefillOnPreview = useRef(false);
  const conditionId = useId();

  const pinnable =
    ev.family === "http" && ev.endpoint
      ? Object.entries(ev.req_headers ?? {})
          .filter(([, v]) => v !== MASKED_HEADER_VALUE)
          .map(([k]) => k)
          .sort()
      : [];

  // scope and pin_header go along with a condition: the server ignores
  // them then, but uses them to tell an unedited condition from one
  // written by hand.
  const request = useMemo<RuleRequest>(
    () => ({ verdict, scope, approver, pin_header: pinHeader || undefined, condition }),
    [verdict, scope, approver, pinHeader, condition],
  );
  const approvers = useApprovers(isAdmin);
  const { preview, fresh, canCreate, err, setErr } = useRulePreview({
    inputs: { id: ev.id ?? "", request },
    enabled: !!ev.id && !created,
    load: (i) => previewRule(i.id, i.request),
    onPreview: (p: RulePreviewResp) => {
      if (prefillOnPreview.current) {
        prefillOnPreview.current = false;
        setConditionText((text) => (text === "" ? (p.rule.condition ?? "") : text));
      }
    },
    onError: () => {
      prefillOnPreview.current = false;
    },
  });

  // While a preview is on its way, the editor opens empty and that preview fills it.
  function editCondition() {
    prefillOnPreview.current = !fresh && !err;
    setConditionText(fresh ? (preview?.rule.condition ?? "") : "");
  }

  function closeConditionEditor() {
    prefillOnPreview.current = false;
    setConditionText(null);
  }

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

  return (
    <Modal
      title={newHost && isAdmin ? "Add this host" : "Create a rule from this request"}
      size="lg"
      onClose={onClose}
    >
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
        ) : created?.endpoint_name && isAdmin ? (
          <div className="space-y-2">
            <p className="text-sm text-text">
              Endpoint <code className="font-bold">{created.endpoint_name}</code> for{" "}
              <code>{ev.host}</code> was written to <code>{created.file}</code> and loaded by the
              gateway
              {created.default_rules?.length || created.rule_name
                ? `, with the rules ${[...(created.default_rules ?? []), created.rule_name].filter(Boolean).join(", ")}`
                : ", with no rules"}
              .
            </p>
            <p className="text-xs text-text-muted">
              Next, add its credential on a device's Credentials panel: pick endpoint{" "}
              <code>{created.endpoint_name}</code>.
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
            <VerdictPicker verdicts={verdicts} value={verdict} onChange={setVerdict} />

            <div className="flex flex-wrap gap-4">
              <label className="flex flex-col gap-1">
                <span className={RULE_LABEL_CLASS}>Matching</span>
                <select
                  value={scope}
                  disabled={condition !== undefined}
                  onChange={(e) => setScope(e.target.value as RuleScope)}
                  className={RULE_SELECT_CLASS + " disabled:opacity-60"}
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
                  <span className={RULE_LABEL_CLASS}>Only when header</span>
                  <select
                    value={pinHeader}
                    disabled={condition !== undefined}
                    onChange={(e) => setPinHeader(e.target.value)}
                    className={RULE_SELECT_CLASS + " disabled:opacity-60"}
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
                <ReviewerSelect approvers={approvers} value={approver} onChange={setApprover} />
              )}
              {verdict === "approve" && !isAdmin && (
                <div className="flex flex-col gap-1">
                  <span className={RULE_LABEL_CLASS}>Reviewed by</span>
                  <span className="text-xs py-1.5">
                    {whoami?.approver || "the dashboard"}{" "}
                    <span className="text-text-muted">(set by an admin)</span>
                  </span>
                </div>
              )}
            </div>

            {ev.endpoint && conditionText !== null && (
              <div className="space-y-1">
                <div className="flex items-baseline justify-between gap-2">
                  <label htmlFor={conditionId} className={RULE_LABEL_CLASS}>
                    Condition (CEL)
                  </label>
                  <button
                    type="button"
                    onClick={closeConditionEditor}
                    className="text-2xs underline text-text-muted"
                  >
                    Use the generated condition
                  </button>
                </div>
                <textarea
                  id={conditionId}
                  value={conditionText}
                  onChange={(e) => {
                    prefillOnPreview.current = false;
                    setConditionText(e.target.value);
                  }}
                  rows={4}
                  spellCheck={false}
                  className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
                />
                <span className="block text-2xs text-text-subtle">
                  {pinnable.length > 0
                    ? "Replaces what Matching and Only when header generate; they apply again while it is empty."
                    : "Replaces what Matching generates; it applies again while this is empty."}{" "}
                  The rule keeps its endpoint{isAdmin ? "" : ", your profile and its credential"}.
                  {fresh && condition && !preview?.rule.hand_written
                    ? " This is the generated condition, so the generated rule is created."
                    : ""}
                </span>
              </div>
            )}
            {ev.endpoint && conditionText === null && (
              <button
                type="button"
                onClick={editCondition}
                className="text-xs underline text-text-muted"
              >
                Edit the condition
              </button>
            )}

            {err && <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>}
            {preview && (
              <RulePreviewPane
                preview={preview}
                fresh={fresh}
                matched={`${isAdmin ? "requests" : "requests of your profile"} to this ${preview.rule.new_endpoint ? "host" : "endpoint"}`}
              >
                {preview.needs_review && (
                  <div className="space-y-2 border border-navy bg-navy-100 px-3 py-2 text-xs">
                    <p>
                      {preview.rule.hand_written
                        ? "A condition written by hand runs on every request, so an admin reviews it first."
                        : "This rule could let through requests your profile's other rules stop, so an admin reviews it first."}{" "}
                      They may approve it, narrow it or reject it.
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
              </RulePreviewPane>
            )}
          </>
        )}
      </div>
      <RuleDialogFooter
        done={!!created}
        canCreate={canCreate}
        busy={busy}
        createLabel={
          preview?.needs_review
            ? "Send for review"
            : verdict === "none"
              ? "Add host"
              : "Create rule"
        }
        onCreate={create}
        onClose={onClose}
      />
    </Modal>
  );
}
