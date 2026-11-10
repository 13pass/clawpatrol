import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type ReactNode,
  type SetStateAction,
} from "react";
import { decideHITL, getHITLPending, type HITLPending, type HITLResolveResult } from "../lib/api";
import { headersToJSON } from "../lib/clipboard";
import { fmtDateTime } from "../lib/format";
import { Button } from "./Button";
import { CopyButton } from "./CopyButton";
import { Modal } from "./Modal";
import { Headers, Section } from "./RequestDetailPage";

const POLL_MS = 1000;
// How long a card stays up after its request leaves the pool.
const FLASH_MS = 2500;

type Outcome = "approved" | "denied" | "gone";
type Resolved = { item: HITLPending; outcome: Outcome; key: number };
type DecideFn = (item: HITLPending, allow: boolean) => void;

// agentIP, when set, scopes the bar to a single device's pending
// approvals (used on the device page); unset shows every device's
// (the home page). A new scope remounts the bar, so no dialog or
// resolved card carries over from the previous device.
export function HITLBar({ agentIP }: { agentIP?: string } = {}) {
  return <ScopedHITLBar key={agentIP ?? ""} agentIP={agentIP} />;
}

function ScopedHITLBar({ agentIP }: { agentIP?: string }) {
  const [pending, setPending] = useState<HITLPending[]>([]);
  const [resolved, setResolved] = useState<Resolved[]>([]);
  const [notice, setNotice] = useState("");
  // The request open in the details dialog. It is kept after the
  // request leaves the pool so the dialog can say so instead of
  // vanishing under the reader.
  const [details, setDetails] = useState<HITLPending | null>(null);
  // The poller compares against the last list it showed to spot
  // requests decided elsewhere, timed out or abandoned, and skips the
  // ones decided here so an in-flight poll cannot bring them back.
  const shown = useRef<HITLPending[]>([]);
  const decided = useRef(new Set<string>());

  useEffect(() => {
    const stopped = new AbortController();
    // Each poll is scheduled when the previous one ends, so polls never
    // overlap and their responses arrive in order.
    async function tick() {
      if (stopped.signal.aborted) return;
      try {
        const r = await getHITLPending(stopped.signal);
        if (stopped.signal.aborted) return;
        const scoped = (r ?? []).filter((p) => !agentIP || p.agent_ip === agentIP);
        const live = new Set(scoped.map((p) => p.id));
        for (const id of decided.current) if (!live.has(id)) decided.current.delete(id);
        const incoming = scoped.filter((p) => !decided.current.has(p.id));
        const ids = new Set(incoming.map((p) => p.id));
        const gone = shown.current.filter((p) => !ids.has(p.id));
        shown.current = incoming;
        setPending(incoming);
        flash(setResolved, gone, "gone");
      } catch {
        /* ignore transient */
      }
      if (!stopped.signal.aborted) setTimeout(tick, POLL_MS);
    }
    tick();
    return () => stopped.abort();
  }, [agentIP]);

  async function decide(item: HITLPending, allow: boolean) {
    const label = approveLabel(item);
    const question = allow
      ? `${label.charAt(0).toUpperCase() + label.slice(1)}?`
      : "Deny this request?";
    if (!confirm(`${question}\n\n${item.method} ${hitlTarget(item)}`)) return;
    setDetails((d) => (d?.id === item.id ? null : d));
    setNotice("");
    decided.current.add(item.id);
    shown.current = shown.current.filter((x) => x.id !== item.id);
    setPending((p) => p.filter((x) => x.id !== item.id));
    try {
      const result = await decideHITL(item.id, allow);
      if (result.ok) {
        flash(setResolved, [item], allow ? "approved" : "denied");
      } else {
        // The server may keep a request it refused to decide; let the
        // next poll show it again.
        decided.current.delete(item.id);
        setNotice(hitlDecisionNotice(result));
      }
    } catch (e: any) {
      decided.current.delete(item.id);
      setNotice("HITL decision failed: " + (e?.message ?? e));
    }
  }

  if (pending.length === 0 && resolved.length === 0 && !notice && !details) return null;

  const liveDetails = details && pending.find((p) => p.id === details.id);

  return (
    <div className="space-y-1.5">
      {notice && (
        <div className="px-4 py-2 text-xs text-rust-700 bg-canvas border-1.5 border-rust-200">
          {notice}
        </div>
      )}
      {resolved.map((r) => (
        <ResolvedCard key={r.key} item={r.item} outcome={r.outcome} />
      ))}
      {pending.map((p) => (
        <PendingCard key={p.id} item={p} onDecide={decide} onDetails={() => setDetails(p)} />
      ))}
      {details && (
        <HITLDetailsModal
          item={liveDetails ?? details}
          decidable={!!liveDetails}
          onDecide={decide}
          onClose={() => setDetails(null)}
        />
      )}
    </div>
  );
}

let flashSeq = 0;

// flash shows items as resolved cards for FLASH_MS, replacing any card
// already up for the same request. Each card has its own key, so an
// older card's timer cannot remove a newer one.
function flash(
  setResolved: Dispatch<SetStateAction<Resolved[]>>,
  items: HITLPending[],
  outcome: Outcome,
) {
  if (items.length === 0) return;
  const added = items.map((item) => ({ item, outcome, key: ++flashSeq }));
  const ids = new Set(items.map((i) => i.id));
  const keys = new Set(added.map((a) => a.key));
  setResolved((r) => [...r.filter((x) => !ids.has(x.item.id)), ...added]);
  setTimeout(() => setResolved((r) => r.filter((x) => !keys.has(x.key))), FLASH_MS);
}

// hitlTarget labels a request the same way on the card, in the dialog
// and on the resolved card: the endpoint (the host when unnamed), then
// the path, or the query / resource for SQL and k8s.
function hitlTarget(item: HITLPending): string {
  const ep = item.endpoint || item.host;
  const sep = item.path && !item.path.startsWith("/") ? " " : "";
  return `${ep}${sep}${item.path}`;
}

function isRetryApproval(item: HITLPending): boolean {
  return (
    item.approval_effect === "create_retry_grant" || item.operation_state === "pending_approval"
  );
}

// Verb matches the Slack "Approve" button and the "approved" status
// badge — the dashboard previously said "allow" here, which read as
// a different action from the same decision shown elsewhere.
function approveLabel(item: HITLPending): string {
  return isRetryApproval(item) ? "approve retry" : "approve";
}

function PendingCard({
  item,
  onDecide,
  onDetails,
}: {
  item: HITLPending;
  onDecide: DecideFn;
  onDetails: () => void;
}) {
  const target = hitlTarget(item);

  return (
    <div className="border-l-4 border-butter-400 bg-canvas border-y border-r border-navy overflow-hidden">
      <div className="px-4 py-3 flex flex-wrap items-center gap-3 min-w-0">
        {/* status badge */}
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="w-2 h-2 rounded-full bg-butter-400 animate-pulse" />
          <span className="font-mono text-2xs font-bold uppercase tracking-wider text-butter-700 whitespace-nowrap">
            awaiting approval
          </span>
        </div>
        {/* request */}
        <span className="font-mono text-xs font-semibold text-text-muted shrink-0">
          {item.method}
        </span>
        <span
          className="font-mono text-xs text-text truncate flex-1 min-w-0"
          title={`${item.method} ${target}`}
        >
          {target}
        </span>
        {/* actions */}
        <div className="flex gap-1.5 shrink-0 ml-auto">
          <Button variant="outline" onClick={onDetails}>
            check details
          </Button>
          <Button variant="outline" onClick={() => onDecide(item, false)}>
            deny
          </Button>
          <Button onClick={() => onDecide(item, true)}>{approveLabel(item)}</Button>
        </div>
      </div>
      {(item.body_sample || item.ua || item.reason) && (
        <div className="px-4 pb-2.5 pt-1.5 border-t border-canvas-muted space-y-0.5">
          {item.body_sample && (
            <div className="font-mono text-2xs text-text truncate">{item.body_sample}</div>
          )}
          <div className="text-2xs text-text-muted truncate">
            {item.ua && (
              <span>
                requested by <span className="font-mono text-text">{item.ua}</span>
              </span>
            )}
            {item.ua && item.reason && <span className="mx-1.5">·</span>}
            {item.reason && <span>{item.reason}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

// HITLDetailsModal shows the full request behind a pending approval:
// what is called, who asked and why, the headers as the agent sent
// them (credentials masked server-side) and the body. Once the request
// leaves the pool it says so and offers no decision.
function HITLDetailsModal({
  item,
  decidable,
  onDecide,
  onClose,
}: {
  item: HITLPending;
  decidable: boolean;
  onDecide: DecideFn;
  onClose: () => void;
}) {
  const isHTTP = !item.family || item.family === "http" || item.family === "https";
  const showHost = isHTTP && !!item.host && item.host !== item.endpoint;
  const headers = item.headers ?? {};
  const hasHeaders = Object.keys(headers).length > 0;
  const hasBody = !!item.body_sample || !!item.body_truncated || !!item.body_not_captured;
  // Go's zero time: the approval has no enforced deadline.
  const hasExpiry = !!item.expires_at && !item.expires_at.startsWith("0001-");

  return (
    <Modal title="Request awaiting approval" subtitle={item.reason} size="lg" onClose={onClose}>
      <div className="flex-1 min-h-0 overflow-y-auto divide-y divide-canvas-dark">
        {!decidable && (
          <div className="px-4 py-2 text-xs text-rust-700 bg-canvas">
            This request is no longer pending. It was decided elsewhere, it timed out, or the agent
            stopped waiting.
          </div>
        )}
        <div className="px-4 py-3 space-y-2">
          <div className="font-mono text-sm text-text break-all">
            <span className="font-semibold text-text-muted mr-2">{item.method}</span>
            {hitlTarget(item)}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
            {showHost && (
              <span>
                host <span className="font-mono text-text">{item.host}</span>
              </span>
            )}
            {item.profile && (
              <span>
                profile <span className="font-mono text-text">{item.profile}</span>
              </span>
            )}
            {item.agent_ip && (
              <span>
                device <span className="font-mono text-text">{item.agent_ip}</span>
              </span>
            )}
            {item.rule && (
              <span>
                rule <span className="font-mono text-text">{item.rule}</span>
              </span>
            )}
            <span>requested {fmtDateTime(item.created_at)}</span>
            {hasExpiry && <span>expires {fmtDateTime(item.expires_at)}</span>}
          </div>
          {item.approval_message && (
            <div className="text-xs text-text-muted">{item.approval_message}</div>
          )}
        </div>
        {hasHeaders && (
          <Section
            title="Request headers"
            action={<CopyButton label="request headers" text={() => headersToJSON(headers)} />}
          >
            {isRetryApproval(item) && (
              <DetailsNote>
                Approving lets the agent send this request again once. The gateway checks that the
                retry has the same method, URL and body. It does not check these headers.
              </DetailsNote>
            )}
            <Headers obj={headers} />
          </Section>
        )}
        {hasBody && (
          <Section
            title="Request body"
            action={
              item.body_sample ? (
                <CopyButton label="request body" text={() => item.body_sample ?? ""} />
              ) : undefined
            }
          >
            {item.body_truncated && (
              <DetailsNote>
                Only part of the body was captured (size limit or read error). The rest is not shown
                here.
              </DetailsNote>
            )}
            {item.body_not_captured && (
              <DetailsNote>
                The gateway does not capture {item.method} bodies, and this request declares one.
                Whatever it holds goes upstream without being shown here.
              </DetailsNote>
            )}
            {item.body_sample && <ApprovalBody text={item.body_sample} />}
          </Section>
        )}
        {!hasHeaders && !hasBody && (
          <div className="px-4 py-3 text-xs text-text-subtle">No headers or body captured</div>
        )}
      </div>
      <div className="flex justify-end gap-1.5 px-4 py-3 border-t border-navy">
        {decidable ? (
          <>
            <Button variant="outline" onClick={() => onDecide(item, false)}>
              deny
            </Button>
            <Button onClick={() => onDecide(item, true)}>{approveLabel(item)}</Button>
          </>
        ) : (
          <Button variant="outline" onClick={onClose}>
            close
          </Button>
        )}
      </div>
    </Modal>
  );
}

function DetailsNote({ children }: { children: ReactNode }) {
  return <div className="px-4 pt-2 text-xs text-rust-700">{children}</div>;
}

// ApprovalBody shows the body exactly as sent. Formatting is opt-in and
// labelled: re-serializing JSON keeps only the last of duplicate keys,
// rounds large numbers and reorders integer-like keys, so the formatted
// view can differ from the bytes that go upstream. Bytes that are not
// valid UTF-8 reach the browser as U+FFFD, so the view says when it
// holds any.
function ApprovalBody({ text }: { text: string }) {
  const hasNonText = text.includes("\uFFFD");
  const [formatted, setFormatted] = useState(false);
  const pretty = useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      return null;
    }
  }, [text]);

  return (
    <div>
      {hasNonText && (
        <DetailsNote>
          The body contains bytes that are not text. They are shown as replacement characters (�),
          and a copy holds those characters, not the original bytes.
        </DetailsNote>
      )}
      {pretty !== null && (
        <div className="flex flex-wrap items-center gap-2 px-4 pt-2 text-2xs text-text-muted">
          <Button variant="outline" size="xs" onClick={() => setFormatted((f) => !f)}>
            {formatted ? "show as sent" : "format JSON"}
          </Button>
          {formatted && (
            <span>
              Formatted view: duplicate keys and large numbers may differ from what is sent.
            </span>
          )}
        </div>
      )}
      <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs text-text-muted">
        {formatted && pretty !== null ? pretty : text}
      </pre>
    </div>
  );
}

const OUTCOME_STYLE: Record<Outcome, { label: string; border: string; dot: string; text: string }> =
  {
    approved: {
      label: "approved",
      border: "border-success-500",
      dot: "bg-success-500",
      text: "text-success-700",
    },
    denied: {
      label: "denied",
      border: "border-rust-400",
      dot: "bg-rust-400",
      text: "text-rust-700",
    },
    gone: {
      label: "no longer pending",
      border: "border-navy-200",
      dot: "bg-navy-200",
      text: "text-text-muted",
    },
  };

function ResolvedCard({ item, outcome }: { item: HITLPending; outcome: Outcome }) {
  const style = OUTCOME_STYLE[outcome];
  return (
    <div
      className={`border-l-4 ${style.border} bg-canvas border-y border-r border-navy px-4 py-3 flex items-center gap-3 min-w-0`}
    >
      <div className="flex items-center gap-1.5 shrink-0">
        <span className={`w-2 h-2 rounded-full ${style.dot}`} />
        <span
          className={`font-mono text-2xs font-bold uppercase tracking-wider ${style.text} whitespace-nowrap`}
        >
          {style.label}
        </span>
      </div>
      <span className="font-mono text-xs font-semibold text-text-muted shrink-0">
        {item.method}
      </span>
      <span className="font-mono text-xs text-text truncate flex-1 min-w-0">
        {hitlTarget(item)}
      </span>
    </div>
  );
}

function hitlDecisionNotice(result: HITLResolveResult): string {
  const detail = result.reason || result.state || "unknown";
  return `HITL request is no longer active: ${detail}`;
}
