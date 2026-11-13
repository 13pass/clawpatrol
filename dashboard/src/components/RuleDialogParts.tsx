import { useEffect, useRef, useState, type ReactNode } from "react";
import { listUsers, type RulePreviewResp, type RuleVerdict } from "../lib/api";
import { Button } from "./Button";

const PREVIEW_DEBOUNCE_MS = 250;

export const RULE_LABEL_CLASS = "font-mono text-xs uppercase tracking-wider text-text-muted";
export const RULE_SELECT_CLASS =
  "border border-canvas-dark rounded px-2 py-1.5 text-xs bg-canvas focus:outline-none focus:border-text";

const VERDICTS: { value: RuleVerdict; label: string; help: string }[] = [
  {
    value: "none",
    label: "Only the default rules",
    help: "Add the host with the rules every host added here gets.",
  },
  { value: "deny", label: "Deny", help: "Block matching requests." },
  { value: "allow", label: "Pre-approve", help: "Let matching requests through without review." },
  {
    value: "approve",
    label: "Require approval",
    help: "Hold matching requests until a human approves.",
  },
];

export function VerdictPicker({
  verdicts,
  value,
  onChange,
}: {
  verdicts: RuleVerdict[];
  value: RuleVerdict;
  onChange: (v: RuleVerdict) => void;
}) {
  return (
    <fieldset className="space-y-2">
      <legend className={RULE_LABEL_CLASS}>What should happen</legend>
      <div className="flex flex-wrap gap-2">
        {VERDICTS.filter((v) => verdicts.includes(v.value)).map((v) => (
          <label
            key={v.value}
            className={
              "flex-1 min-w-[10rem] cursor-pointer border-1.5 px-3 py-2 text-xs " +
              (value === v.value ? "border-navy bg-navy-100" : "border-canvas-dark")
            }
          >
            <input
              type="radio"
              name="verdict"
              value={v.value}
              checked={value === v.value}
              onChange={() => onChange(v.value)}
              className="mr-2"
            />
            <span className="font-bold">{v.label}</span>
            <span className="block text-text-muted mt-0.5">{v.help}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

// useApprovers loads the human approvers once per dialog, for
// ReviewerSelect.
export function useApprovers(enabled: boolean) {
  const [approvers, setApprovers] = useState<string[]>([]);
  useEffect(() => {
    if (!enabled) return;
    const ctl = { cancelled: false };
    listUsers()
      .then((u) => {
        if (!ctl.cancelled) setApprovers(u.human_approvers);
      })
      .catch(() => {});
    return () => {
      ctl.cancelled = true;
    };
  }, [enabled]);
  return approvers;
}

export function ReviewerSelect({
  approvers,
  value,
  onChange,
  className = "",
}: {
  approvers: string[];
  value: string;
  onChange: (approver: string) => void;
  className?: string;
}) {
  return (
    <label className={"flex flex-col gap-1 " + className}>
      <span className={RULE_LABEL_CLASS}>Reviewed by</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={RULE_SELECT_CLASS}
      >
        <option value="">the dashboard</option>
        {value && !approvers.includes(value) && <option value={value}>{value}</option>}
        {approvers.map((a) => (
          <option key={a} value={a}>
            {a}
          </option>
        ))}
      </select>
    </label>
  );
}

// useRulePreview previews the rule a dialog describes, debounced.
// inputs is everything the preview depends on, and load reads only
// them: a preview for older inputs stays shown but is not fresh, so it
// cannot be created.
export function useRulePreview<T>({
  inputs,
  enabled,
  load,
  onPreview,
  onError,
}: {
  inputs: T;
  enabled: boolean;
  load: (inputs: T) => Promise<RulePreviewResp>;
  onPreview?: (p: RulePreviewResp) => void;
  onError?: () => void;
}) {
  const key = JSON.stringify(inputs);
  const [previewed, setPreviewed] = useState<{ key: string; resp: RulePreviewResp } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // The callbacks change every render; key decides when to preview.
  const latest = useRef({ inputs, load, onPreview, onError });
  useEffect(() => {
    latest.current = { inputs, load, onPreview, onError };
  });

  useEffect(() => {
    if (!enabled) return;
    // An object, not a let: the linter forbids reassigning a local after render.
    const ctl = { cancelled: false };
    const t = setTimeout(() => {
      const { inputs, load } = latest.current;
      load(inputs)
        .then((p) => {
          if (ctl.cancelled) return;
          setPreviewed({ key, resp: p });
          setErr(null);
          latest.current.onPreview?.(p);
        })
        .catch((e: Error) => {
          if (ctl.cancelled) return;
          latest.current.onError?.();
          setPreviewed(null);
          setErr(e.message || "preview failed");
        });
    }, PREVIEW_DEBOUNCE_MS);
    return () => {
      ctl.cancelled = true;
      clearTimeout(t);
    };
  }, [key, enabled]);

  const preview = previewed?.resp ?? null;
  const fresh = previewed?.key === key;
  return { preview, fresh, canCreate: fresh && !!preview?.writes_enabled, err, setErr };
}

export function RulePreviewPane({
  preview,
  fresh,
  matched,
  children,
}: {
  preview: RulePreviewResp;
  fresh: boolean;
  // matched completes "Would have matched N of the last M …".
  matched: string;
  children?: ReactNode;
}) {
  return (
    <div className={"space-y-2" + (fresh ? "" : " opacity-60")}>
      <p className="text-xs text-text">
        {preview.rule.rule_name && (
          <>
            Would have matched{" "}
            <span className="font-bold">
              {preview.recent_matches} of the last {preview.recent_sampled}
            </span>{" "}
            {matched}.{" "}
          </>
        )}
        Written to <code>{preview.file}</code>.
      </p>
      {!!preview.rule.default_rules?.length && (
        <p className="text-xs text-text">
          With the default rules{" "}
          {preview.rule.default_rules.map((r, i) => (
            <span key={r}>
              {i > 0 && ", "}
              <code>{r}</code>
            </span>
          ))}{" "}
          from <code>defaults.new_endpoint_rule</code>.
        </p>
      )}
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
      {children}
    </div>
  );
}

export function RuleDialogFooter({
  done,
  canCreate,
  busy,
  createLabel,
  onCreate,
  onClose,
}: {
  done: boolean;
  canCreate: boolean;
  busy: boolean;
  createLabel: string;
  onCreate: () => void;
  onClose: () => void;
}) {
  return (
    <div className="flex items-center gap-2 justify-end px-4 py-3 border-t border-navy bg-navy-100">
      {done ? (
        <Button variant="outline" onClick={onClose}>
          Close
        </Button>
      ) : (
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={!canCreate || busy} onClick={onCreate}>
            {busy ? "Sending…" : createLabel}
          </Button>
        </>
      )}
    </div>
  );
}
