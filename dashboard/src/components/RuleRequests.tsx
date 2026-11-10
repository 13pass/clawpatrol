import { useEffect, useState, type ReactNode } from "react";
import {
  decideRuleRequest,
  listRuleRequests,
  withdrawRuleRequest,
  type RuleChangeRequest,
} from "../lib/api";
import { fmtDateTime } from "../lib/format";
import { Button } from "./Button";
import { HCLEditor } from "./HCLEditor";

const NS_PER_MS = 1e6;
const EDITOR_MIN_HEIGHT = 160;

const STATUS_LABEL: Record<RuleChangeRequest["status"], string> = {
  pending: "waiting for an admin",
  approved: "approved",
  rejected: "rejected",
  withdrawn: "withdrawn",
};

// RuleRequests lists member rule changes that could loosen a profile.
// An admin approves (as asked or edited) or rejects each pending one;
// a member follows their own and may withdraw a pending one. version
// changes when the page knows the list moved.
export function RuleRequests({
  isMember,
  version,
  onDecided,
}: {
  isMember: boolean;
  version: number;
  onDecided: () => void;
}) {
  const [requests, setRequests] = useState<RuleChangeRequest[]>([]);
  const [err, setErr] = useState("");
  const [reloads, setReloads] = useState(0);
  const refresh = () => setReloads((n) => n + 1);

  useEffect(() => {
    let cancelled = false;
    listRuleRequests()
      .then((r) => {
        if (cancelled) return;
        setRequests(r);
        setErr("");
      })
      .catch((e: Error) => {
        if (!cancelled) setErr(e.message || "could not load rule requests");
      });
    return () => {
      cancelled = true;
    };
  }, [version, reloads]);

  const pending = requests.filter((r) => r.status === "pending");
  const decided = requests.filter((r) => r.status !== "pending");
  if (!err && requests.length === 0) return null;

  return (
    <section className="space-y-3">
      <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">
        {isMember ? "Your rule requests" : "Rule requests from members"}
      </h2>
      {err && <div className="text-xs text-danger-500">{err}</div>}
      {pending.length === 0 && (
        <p className="text-xs text-text-muted">Nothing is waiting for review.</p>
      )}
      {pending.map((r) =>
        isMember ? (
          <PendingForMember key={r.id} request={r} onChanged={refresh} />
        ) : (
          <PendingForAdmin
            key={r.id}
            request={r}
            onDecided={() => {
              refresh();
              onDecided();
            }}
          />
        ),
      )}
      {decided.length > 0 && (
        <details className="text-xs">
          <summary className="cursor-pointer text-text-muted">
            Decided ({decided.length} most recent)
          </summary>
          <table className="w-full border-collapse mt-2">
            <tbody>
              {decided.map((r) => (
                <tr key={r.id} className="border-b border-canvas-muted last:border-b-0">
                  <Td>{fmtDateTime((r.decided_ns || r.created_ns) / NS_PER_MS)}</Td>
                  <Td>
                    {!isMember && <span className="font-bold">{r.username}: </span>}
                    {r.summary}
                  </Td>
                  <Td>
                    {STATUS_LABEL[r.status]}
                    {r.decided_by && r.status !== "withdrawn" && <> by {r.decided_by}</>}
                    {r.edited && <> (edited)</>}
                    {r.decision_note && <div className="text-text-muted">“{r.decision_note}”</div>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </section>
  );
}

function RequestHeader({ request, showUser }: { request: RuleChangeRequest; showUser: boolean }) {
  return (
    <div className="space-y-1">
      <p className="text-sm text-text">
        {showUser && <span className="font-bold">{request.username} asks to </span>}
        {!showUser && <span className="font-bold">You asked to </span>}
        {request.summary}
      </p>
      <p className="text-xs text-text-muted">
        Rule <code>{request.rule_name}</code>
        {request.profile && <> on profile {request.profile}</>}, asked{" "}
        {fmtDateTime(request.created_ns / NS_PER_MS)}
      </p>
      {request.reason && <p className="text-xs">Reason: “{request.reason}”</p>}
    </div>
  );
}

function PendingForMember({
  request,
  onChanged,
}: {
  request: RuleChangeRequest;
  onChanged: () => void;
}) {
  const [err, setErr] = useState("");
  async function withdraw() {
    try {
      await withdrawRuleRequest(request.id);
      onChanged();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }
  return (
    <Card>
      <RequestHeader request={request} showUser={false} />
      {request.hcl && <Pre>{request.hcl}</Pre>}
      {err && <div className="text-xs text-danger-500">{err}</div>}
      <div className="flex items-center gap-2">
        <span className="text-xs text-text-muted">Waiting for an admin.</span>
        <Button size="xs" variant="outline" onClick={withdraw}>
          Withdraw
        </Button>
      </div>
    </Card>
  );
}

function PendingForAdmin({
  request,
  onDecided,
}: {
  request: RuleChangeRequest;
  onDecided: () => void;
}) {
  const [hcl, setHcl] = useState(request.hcl ?? "");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const isCreate = request.kind === "create";
  const edited = isCreate && hcl.trim() !== (request.hcl ?? "").trim();

  async function decide(decision: "approve" | "reject") {
    setBusy(true);
    try {
      await decideRuleRequest(request.id, decision, note, edited ? hcl : undefined);
      onDecided();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <RequestHeader request={request} showUser />
      {isCreate && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-xs text-text-muted">
            <span>
              Rule to add to the member's file{edited ? " (edited)" : ""}. Edit it before approving
              if it should be narrower.
            </span>
            {edited && (
              <Button size="xs" variant="outline" onClick={() => setHcl(request.hcl ?? "")}>
                Reset
              </Button>
            )}
          </div>
          <div className="border-1.5 border-navy">
            <HCLEditor value={hcl} onChange={setHcl} minHeight={EDITOR_MIN_HEIGHT} />
          </div>
        </div>
      )}
      <label className="block space-y-1">
        <span className="text-xs text-text-muted">Note to {request.username} (optional)</span>
        <input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
        />
      </label>
      {err && <div className="text-xs text-danger-500 whitespace-pre-wrap">{err}</div>}
      <div className="flex gap-2">
        <Button
          size="sm"
          disabled={busy || (edited && !hcl.trim())}
          onClick={() => decide("approve")}
        >
          {edited ? "Approve edited rule" : "Approve"}
        </Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => decide("reject")}>
          Reject
        </Button>
      </div>
    </Card>
  );
}

function Card({ children }: { children: ReactNode }) {
  return <div className="bg-canvas border-1.5 border-navy p-4 space-y-3">{children}</div>;
}

function Pre({ children }: { children: ReactNode }) {
  return (
    <pre className="border-1.5 border-navy bg-canvas p-3 font-mono text-xs text-text overflow-auto max-h-[16rem]">
      {children}
    </pre>
  );
}

function Td({ children }: { children: ReactNode }) {
  return <td className="px-2 py-1.5 align-top">{children}</td>;
}
