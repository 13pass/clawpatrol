import { useId, useMemo, useState } from "react";
import {
  createEndpointRule,
  previewEndpointRule,
  type RuleChangeResult,
  type RuleRequest,
  type RuleVerdict,
} from "../lib/api";
import { Modal } from "./Modal";
import {
  RULE_LABEL_CLASS,
  ReviewerSelect,
  RuleDialogFooter,
  RulePreviewPane,
  VerdictPicker,
  useRulePreview,
} from "./RuleDialogParts";

const CONDITION_VARIABLES: Record<string, string> = {
  http: "http.method, http.path, http.query, http.headers, http.body_json",
  k8s: "k8s.verb, k8s.resource, k8s.namespace, k8s.name, k8s.params",
  sql: "sql.verb, sql.tables, sql.function, sql.statement",
};

export function EndpointRuleModal({
  endpoint,
  family,
  profile,
  onClose,
  onCreated,
}: {
  endpoint: string;
  family: string;
  // profile is the device page's: the rule may be limited to it.
  profile?: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [verdict, setVerdict] = useState<RuleVerdict>("deny");
  const [approver, setApprover] = useState("");
  const [condition, setCondition] = useState("");
  const [onlyProfile, setOnlyProfile] = useState(!!profile);
  const pinned = onlyProfile && profile ? profile : "";
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<RuleChangeResult | null>(null);
  const conditionId = useId();

  const request = useMemo<RuleRequest>(
    () => ({ verdict, scope: "exact", approver, condition: condition.trim() || undefined }),
    [verdict, approver, condition],
  );
  const { preview, fresh, err, setErr } = useRulePreview({
    key: JSON.stringify({ ...request, pinned }),
    enabled: !created,
    load: () => previewEndpointRule(endpoint, pinned, request),
  });

  async function create() {
    if (!fresh) return;
    setBusy(true);
    try {
      setCreated(await createEndpointRule(endpoint, pinned, request));
      setErr(null);
      onCreated();
    } catch (e) {
      setErr((e as Error).message || "create failed");
    } finally {
      setBusy(false);
    }
  }

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
            <VerdictPicker
              verdicts={["deny", "allow", "approve"]}
              value={verdict}
              onChange={setVerdict}
            />

            {verdict === "approve" && (
              <div className="w-fit">
                <ReviewerSelect value={approver} onChange={setApprover} />
              </div>
            )}

            {profile ? (
              <label className="flex items-center gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={onlyProfile}
                  onChange={(e) => setOnlyProfile(e.target.checked)}
                />
                Only profile <code>{profile}</code>; unticked, every profile reaching {endpoint}
              </label>
            ) : (
              <p className="text-xs text-text-muted">
                It applies to every profile reaching {endpoint}.
              </p>
            )}

            <div className="space-y-1">
              <label htmlFor={conditionId} className={RULE_LABEL_CLASS}>
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
              <RulePreviewPane
                preview={preview}
                fresh={fresh}
                matched="requests to this endpoint"
              />
            )}
          </>
        )}
      </div>
      <RuleDialogFooter
        done={!!created}
        canCreate={fresh && !!preview?.writes_enabled}
        busy={busy}
        createLabel="Create rule"
        onCreate={create}
        onClose={onClose}
      />
    </Modal>
  );
}
