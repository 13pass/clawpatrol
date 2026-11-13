import { useEffect, useId, useMemo, useState } from "react";
import {
  createEndpointRule,
  listUsers,
  previewEndpointRule,
  type RuleChangeResult,
  type RulePreviewResp,
  type RuleRequest,
  type RuleVerdict,
} from "../lib/api";
import { Button } from "./Button";
import { Modal } from "./Modal";

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

const CONDITION_VARIABLES: Record<string, string> = {
  http: "http.method, http.path, http.query, http.headers, http.body_json",
  k8s: "k8s.verb, k8s.resource, k8s.namespace, k8s.name, k8s.params",
  sql: "sql.verb, sql.tables, sql.function, sql.statement",
};

export function EndpointRuleModal({
  endpoint,
  family,
  onClose,
  onCreated,
}: {
  endpoint: string;
  family: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [verdict, setVerdict] = useState<RuleVerdict>("deny");
  const [approver, setApprover] = useState("");
  const [approvers, setApprovers] = useState<string[]>([]);
  const [condition, setCondition] = useState("");
  const [previewed, setPreviewed] = useState<{ key: string; resp: RulePreviewResp } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<RuleChangeResult | null>(null);
  const conditionId = useId();

  useEffect(() => {
    listUsers()
      .then((u) => setApprovers(u.human_approvers))
      .catch(() => setApprovers([]));
  }, []);

  const request = useMemo<RuleRequest>(
    () => ({ verdict, scope: "exact", approver, condition: condition.trim() || undefined }),
    [verdict, approver, condition],
  );
  const requestKey = JSON.stringify(request);
  const preview = previewed?.resp ?? null;
  const fresh = previewed?.key === requestKey;

  useEffect(() => {
    if (created) return;
    // An object, not a let: the linter forbids reassigning a local after render.
    const ctl = { cancelled: false };
    const t = setTimeout(() => {
      previewEndpointRule(endpoint, request)
        .then((p) => {
          if (ctl.cancelled) return;
          setPreviewed({ key: requestKey, resp: p });
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
  }, [endpoint, request, requestKey, created]);

  async function create() {
    if (!fresh) return;
    setBusy(true);
    try {
      setCreated(await createEndpointRule(endpoint, request));
      setErr(null);
      onCreated();
    } catch (e) {
      setErr((e as Error).message || "create failed");
    } finally {
      setBusy(false);
    }
  }

  const labelClass = "font-mono text-xs uppercase tracking-wider text-text-muted";

  return (
    <Modal title={`Add a rule to ${endpoint}`} size="lg" onClose={onClose}>
      <div className="p-4 space-y-4 overflow-auto">
        {created ? (
          <p className="text-sm text-text">
            Rule <code className="font-bold">{created.rule_name}</code> was validated, written to{" "}
            <code>{created.file}</code> and loaded by the gateway.
          </p>
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

            {verdict === "approve" && (
              <label className="flex flex-col gap-1 w-fit">
                <span className={labelClass}>Reviewed by</span>
                <select
                  value={approver}
                  onChange={(e) => setApprover(e.target.value)}
                  className="border border-canvas-dark rounded px-2 py-1.5 text-xs bg-canvas focus:outline-none focus:border-text"
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

            <div className="space-y-1">
              <label htmlFor={conditionId} className={labelClass}>
                Condition (CEL)
              </label>
              <textarea
                id={conditionId}
                value={condition}
                onChange={(e) => setCondition(e.target.value)}
                rows={3}
                spellCheck={false}
                placeholder={family === "http" ? "http.method == 'DELETE'" : ""}
                className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
              />
              <span className="block text-2xs text-text-subtle">
                Empty, the rule applies to every request to {endpoint}.
                {CONDITION_VARIABLES[family] && ` Variables: ${CONDITION_VARIABLES[family]}.`}
              </span>
            </div>

            {err && <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>}
            {preview && (
              <div className={"space-y-2" + (fresh ? "" : " opacity-60")}>
                <p className="text-xs text-text">
                  Would have matched{" "}
                  <span className="font-bold">
                    {preview.recent_matches} of the last {preview.recent_sampled}
                  </span>{" "}
                  requests to this endpoint. Written to <code>{preview.file}</code>.
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
            <Button disabled={!fresh || !preview?.writes_enabled || busy} onClick={create}>
              {busy ? "Sending…" : "Create rule"}
            </Button>
          </>
        )}
      </div>
    </Modal>
  );
}
