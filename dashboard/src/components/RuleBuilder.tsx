import { useEffect, useState, type ReactNode } from "react";
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
import { copyText } from "../lib/clipboard";
import { Button } from "./Button";
import { Modal } from "./Modal";
import { Tag } from "./Tag";

// Recorded values the gateway masked; a rule cannot pin them.
const MASKED_HEADER_VALUE = "***";
export const PREVIEW_DEBOUNCE_MS = 250;
// The only port the gateway hands to a postgres endpoint.
const POSTGRES_PORT = 5432;
const COPY_FEEDBACK_MS = 1500;

export const labelClass = "font-mono text-xs uppercase tracking-wider text-text-muted";
export const inputClass =
  "border border-canvas-dark rounded px-2 py-1.5 text-xs bg-canvas focus:outline-none focus:border-text";
export const calloutClass = "border border-butter-600 bg-butter-100 px-3 py-2 text-xs";

const VERDICTS: { value: RuleVerdict; label: string; help: string }[] = [
  { value: "deny", label: "Deny", help: "Block matching requests." },
  { value: "allow", label: "Pre-approve", help: "Let matching requests through without review." },
  {
    value: "approve",
    label: "Require approval",
    help: "Hold matching requests until a human approves.",
  },
  {
    value: "log",
    label: "Inspect and log",
    help: "Record every request to this host in the history; hold nothing.",
  },
];

// RuleTarget is what "Create a rule…" can do with a recorded request:
// rule an endpoint that already inspects it, declare an endpoint for a
// host or database that passed through uninspected, or nothing.
export type RuleTarget =
  | { kind: "endpoint" }
  | { kind: "https-host"; host: string }
  | { kind: "postgres"; host: string }
  | { kind: "unsupported"; reason: string }
  | { kind: "none" };

export function ruleTarget(ev: EventRecord): RuleTarget {
  if (!ev.id || ev.action === "in_flight") return { kind: "none" };
  if (ev.endpoint) return { kind: "endpoint" };
  if (ev.mode === "splice") return { kind: "https-host", host: ev.host };
  if (ev.mode !== "relay") return { kind: "none" };
  const port = Number(ev.host.slice(ev.host.lastIndexOf(":") + 1));
  if (ev.action !== "allow") {
    return {
      kind: "unsupported",
      reason: "The gateway refused this connection, so there is nothing to inspect.",
    };
  }
  if (port === POSTGRES_PORT) return { kind: "postgres", host: ev.host };
  return {
    kind: "unsupported",
    reason: `Claw Patrol can't inspect this protocol (port ${port}). Only HTTPS (443) and Postgres (${POSTGRES_PORT}) connections can become rules.`,
  };
}

// RuleKindHeader names what kind of traffic a rule is being made for,
// so the HTTPS and Postgres flows are never mistaken for each other.
export function RuleKindHeader({ kind, host, note }: { kind: string; host: string; note: string }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <Tag tone="info">{kind}</Tag>
      <code className="font-bold">{host}</code>
      <span className="text-text-muted">{note}</span>
    </div>
  );
}

// ChoiceCards is the radio-card group both rule modals use for "what
// should happen".
export function ChoiceCards<T extends string>({
  name,
  choices,
  value,
  onChange,
}: {
  name: string;
  choices: { value: T; label: string; help: ReactNode; badge?: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {choices.map((c) => (
        <label
          key={c.value}
          className={
            "flex-1 min-w-[10rem] cursor-pointer border-1.5 px-3 py-2 text-xs " +
            (value === c.value ? "border-navy bg-navy-100" : "border-canvas-dark")
          }
        >
          <input
            type="radio"
            name={name}
            value={c.value}
            checked={value === c.value}
            onChange={() => onChange(c.value)}
            className="mr-2"
          />
          <span className="font-bold">{c.label}</span>
          {c.badge && (
            <Tag tone="success" className="ml-2">
              {c.badge}
            </Tag>
          )}
          <span className="block text-text-muted mt-0.5">{c.help}</span>
        </label>
      ))}
    </div>
  );
}

// CopyHCLButton copies generated HCL, for when the dashboard may not
// write the config itself.
export function CopyHCLButton({ hcl, primary }: { hcl?: string; primary?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant={primary ? "normal" : "outline"}
      disabled={!hcl}
      onClick={async () => {
        if (hcl && (await copyText(hcl))) {
          setCopied(true);
          setTimeout(() => setCopied(false), COPY_FEEDBACK_MS);
        }
      }}
    >
      {copied ? "Copied" : "Copy HCL"}
    </Button>
  );
}

export function HCLPreview({ hcl }: { hcl: string }) {
  return (
    <pre className="border-1.5 border-navy bg-canvas p-3 font-mono text-xs text-text overflow-auto max-h-[22rem]">
      {hcl}
    </pre>
  );
}

// ReviewerField is "Reviewed by" for a rule that requires approval: an
// admin picks the approver, a member's is set by an admin.
export function ReviewerField({
  whoami,
  approver,
  onChange,
}: {
  whoami: Whoami | null;
  approver: string;
  onChange: (approver: string) => void;
}) {
  const isAdmin = whoami?.role !== "member";
  const [approvers, setApprovers] = useState<string[]>([]);
  useEffect(() => {
    if (isAdmin) {
      listUsers()
        .then((u) => setApprovers(u.human_approvers))
        .catch(() => setApprovers([]));
    }
  }, [isAdmin]);
  if (!isAdmin) {
    return (
      <div className="flex flex-col gap-1">
        <span className={labelClass}>Reviewed by</span>
        <span className="text-xs py-1.5">
          {whoami?.approver || "the dashboard"}{" "}
          <span className="text-text-muted">(set by an admin)</span>
        </span>
      </div>
    );
  }
  return (
    <label className="flex flex-col gap-1">
      <span className={labelClass}>Reviewed by</span>
      <select value={approver} onChange={(e) => onChange(e.target.value)} className={inputClass}>
        <option value="">the dashboard</option>
        {approvers.map((a) => (
          <option key={a} value={a}>
            {a}
          </option>
        ))}
      </select>
    </label>
  );
}

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
  const newHost = !ev.endpoint;
  const scopes = scopesFor(ev);
  // A host with no endpoint already passes through: pre-approving it
  // would change nothing, and the server refuses it. Logging applies
  // only there, since an endpoint already records what it inspects.
  const verdicts = VERDICTS.filter((v) => v.value !== (newHost ? "allow" : "log"));
  const [verdict, setVerdict] = useState<RuleVerdict>("deny");
  const [scope, setScope] = useState<RuleScope>(scopes[0].value);
  const [pinHeader, setPinHeader] = useState("");
  const [approver, setApprover] = useState("");
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

  return (
    <Modal title="Create a rule from this request" size="lg" onClose={onClose}>
      <div className="p-4 space-y-4 overflow-auto">
        {created ? (
          <div className="space-y-2">
            <p className="text-sm text-text">
              {created.rule_name ? (
                <>
                  Rule <code className="font-bold">{created.rule_name}</code> was
                </>
              ) : (
                <>
                  The endpoint for <code className="font-bold">{ev.host}</code> was
                </>
              )}{" "}
              validated, written to <code>{created.file}</code> and loaded by the gateway.
              {!created.rule_name && " New requests to this host appear in the request history."}
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
            {newHost && (
              <RuleKindHeader
                kind="New HTTPS host"
                host={ev.host}
                note="No endpoint inspects this host yet; the rule declares one."
              />
            )}
            <fieldset className="space-y-2">
              <legend className={labelClass}>What should happen</legend>
              <ChoiceCards
                name="verdict"
                choices={verdicts}
                value={verdict}
                onChange={setVerdict}
              />
            </fieldset>

            <div className="flex flex-wrap gap-4">
              <label className="flex flex-col gap-1">
                <span className={labelClass}>Matching</span>
                <select
                  value={scope}
                  onChange={(e) => setScope(e.target.value as RuleScope)}
                  className={inputClass}
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
                    className={inputClass}
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
              {verdict === "approve" && (
                <ReviewerField whoami={whoami} approver={approver} onChange={setApprover} />
              )}
            </div>

            {err && <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>}
            {preview && (
              <div className="space-y-2">
                <p className="text-xs text-text">
                  {verdict === "log" ? "Would have inspected" : "Would have matched"}{" "}
                  <span className="font-bold">
                    {preview.recent_matches} of the last {preview.recent_sampled}
                  </span>{" "}
                  {isAdmin ? "requests" : "requests of your profile"} to this{" "}
                  {preview.rule.new_endpoint ? "host" : "endpoint"}. Written to{" "}
                  <code>{preview.file}</code>.
                </p>
                {preview.rule.warnings?.map((w) => (
                  <div key={w} className={calloutClass}>
                    {w}
                  </div>
                ))}
                {!preview.writes_enabled && preview.writes_unavailable && (
                  <div className={calloutClass}>
                    This rule can't be saved from the dashboard: {preview.writes_unavailable}. Copy
                    the HCL into your config and deploy it the usual way.
                  </div>
                )}
                <HCLPreview hcl={preview.rule.hcl} />
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
            {preview && !preview.writes_enabled ? (
              <CopyHCLButton hcl={preview.rule.hcl} primary />
            ) : (
              <Button disabled={!preview?.writes_enabled || busy} onClick={create}>
                {busy ? "Creating…" : verdict === "log" ? "Start inspecting" : "Create rule"}
              </Button>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}
