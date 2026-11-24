import { useEffect, useState, type ReactNode } from "react";
import {
  approveJoin,
  createJoinIntent,
  getJoinIntentStatus,
  rejectJoinIntent,
  releaseJoinIntent,
  type JoinIntent,
  type JoinIntentState,
  type JoinIntentStatus,
} from "../lib/api";
import { buildAgentJoinPrompt } from "../lib/agentJoinPrompt";
import { copyText } from "../lib/clipboard";
import { Button } from "./Button";

// Each poll keeps an unused prompt alive; the gateway lets it lapse ten
// minutes after the last one (joinIntentIdle).
const POLL_INTERVAL_MS = 2000;
const COPIED_FLASH_MS = 1500;
const LIVE_STATES: JoinIntentState[] = ["waiting", "pending", "approved"];

// "gone": the gateway no longer knows the intent (it restarted, or the
// intent outlived its retention).
type JoinState = JoinIntentState | "gone";

export type JoinIntentHandle = ReturnType<typeof useJoinIntent>;

// useJoinIntent makes a join intent for profile as soon as it is known
// (null while the profiles load) and follows it. A new profile, reset(),
// closing the window or leaving the page revokes the intent unless a
// device already used it.
export function useJoinIntent(profile: string | null) {
  const [generation, setGeneration] = useState(0);
  const [made, setMade] = useState<{ key: string; intent?: JoinIntent; err?: string } | null>(null);
  const [polled, setPolled] = useState<{
    id: string;
    status?: JoinIntentStatus;
    gone?: boolean;
    err?: string;
  } | null>(null);
  const key = profile === null ? null : `${generation}:${profile}`;

  useEffect(() => {
    if (key === null || profile === null) return;
    const run: { stopped: boolean; id?: string } = { stopped: false };
    createJoinIntent(profile).then(
      (intent) => {
        if (run.stopped) {
          releaseJoinIntent(intent.id);
          return;
        }
        run.id = intent.id;
        setMade({ key, intent });
      },
      (e) => {
        if (!run.stopped) setMade({ key, err: String(e) });
      },
    );
    return () => {
      run.stopped = true;
      if (run.id) releaseJoinIntent(run.id);
    };
  }, [key, profile]);

  const mine = made?.key === key ? made : null;
  const intent = mine?.intent ?? null;
  const id = intent?.id;

  useEffect(() => {
    if (!id) return;
    const loop: { stopped: boolean; timer?: ReturnType<typeof setTimeout> } = { stopped: false };
    async function poll(intentID: string) {
      try {
        const s = await getJoinIntentStatus(intentID);
        if (loop.stopped) return;
        setPolled({ id: intentID, status: s ?? undefined, gone: !s });
        if (!s || !LIVE_STATES.includes(s.state)) return;
      } catch (e) {
        if (loop.stopped) return;
        setPolled((p) => ({ ...(p?.id === intentID ? p : {}), id: intentID, err: String(e) }));
      }
      loop.timer = setTimeout(() => poll(intentID), POLL_INTERVAL_MS);
    }
    loop.timer = setTimeout(() => poll(id), 0);
    // Unmounting does not run on a closed tab or a reload.
    const leave = () => releaseJoinIntent(id);
    window.addEventListener("pagehide", leave);
    return () => {
      loop.stopped = true;
      clearTimeout(loop.timer);
      window.removeEventListener("pagehide", leave);
    };
  }, [id]);

  const followed = polled?.id === id ? polled : null;
  const status = followed?.status ?? null;
  const state: JoinState | null = !intent
    ? null
    : followed?.gone
      ? "gone"
      : (status?.state ?? "waiting");

  return {
    intent,
    status,
    state,
    err: mine?.err ?? followed?.err ?? "",
    setStatus(s: JoinIntentStatus) {
      setPolled({ id: s.id, status: s });
    },
    reset() {
      setGeneration((g) => g + 1);
    },
  };
}

// AgentJoinPanel is the Add device window's "Agent prompt" tab: the
// prompt to give an agent on the new device, then the join it starts,
// approved here.
// blocked explains why no prompt can be made.
export function AgentJoinPanel({
  gatewayURL,
  join,
  blocked,
}: {
  gatewayURL: string;
  join: JoinIntentHandle;
  blocked: string;
}) {
  const { intent } = join;
  if (blocked) return <p className="text-sm text-text-muted font-sans">{blocked}</p>;
  if (!intent) {
    return join.err ? (
      <div className="space-y-2">
        <ErrorLine err={join.err} />
        <Button variant="outline" onClick={join.reset}>
          try again
        </Button>
      </div>
    ) : (
      <p className="text-sm text-text-muted font-sans">Preparing the prompt…</p>
    );
  }
  const prompt = buildAgentJoinPrompt({
    gatewayURL,
    caFingerprint: intent.ca_fingerprint,
    profile: intent.profile,
    intent: intent.id,
  });
  return (
    <div className="space-y-4">
      <PromptBlock prompt={prompt} />
      <StatusPanel key={intent.id} join={join} />
    </div>
  );
}

function ErrorLine({ err }: { err: string }) {
  return <p className="text-xs text-danger-500 font-mono break-words">{err}</p>;
}

function PromptBlock({ prompt }: { prompt: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    if (await copyText(prompt)) {
      setCopied(true);
      setTimeout(() => setCopied(false), COPIED_FLASH_MS);
    }
  }
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-text-muted font-sans">
          Give this to the AI agent on the new device:
        </span>
        <Button onClick={copy} className="shrink-0">
          {copied ? "copied" : "copy"}
        </Button>
      </div>
      <pre className="bg-navy rounded px-4 py-4 text-xs font-mono text-canvas overflow-auto max-h-64 whitespace-pre">
        {prompt}
      </pre>
    </div>
  );
}

function StatusPanel({ join }: { join: JoinIntentHandle }) {
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState("");
  const { intent, status, state } = join;

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setActionErr("");
    try {
      await fn();
    } catch (e) {
      setActionErr(String(e));
    } finally {
      setBusy(false);
    }
  }
  const reject = () =>
    act(async () => {
      if (intent) join.setStatus(await rejectJoinIntent(intent.id));
    });

  const d = status?.device;
  const ended: Partial<Record<JoinState, string>> = {
    joined: `${d?.name} joined profile ${status?.profile}. Ask the agent for its report.`,
    rejected: "Rejected. Nothing joined.",
    conflict:
      "A second device used this prompt, so both joins were cancelled. The prompt may have leaked.",
    expired: d
      ? "The join waited too long for approval."
      : "The prompt lapsed while this window was inactive.",
    failed: `Setting the device up failed after approval: ${status?.error ?? "unknown error"}`,
    gone: "The gateway no longer knows this prompt (it restarted, or the prompt is too old).",
  };
  const message = state ? ended[state] : undefined;

  if (state === "waiting") {
    return (
      <Box>
        <p>Waiting for the agent… The prompt works once, while this window stays open.</p>
        <Button variant="outline" onClick={join.reset}>
          new prompt
        </Button>
        {join.err && <ErrorLine err={join.err} />}
      </Box>
    );
  }

  return (
    <Box>
      {d && state !== "gone" && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs font-mono">
          <dt className="text-text-muted">Device</dt>
          <dd>
            {d.name}{" "}
            {status.replaces ? (
              <span className="text-amber-600">♻ replaces the existing device</span>
            ) : (
              <span className="text-success-600">➕ new device</span>
            )}
          </dd>
          <dt className="text-text-muted">Profile</dt>
          <dd>{status.profile || "gateway default"}</dd>
          <dt className="text-text-muted">Code</dt>
          <dd className="font-semibold">{d.user_code}</dd>
        </dl>
      )}
      {state === "pending" && d && (
        <div className="space-y-2">
          <p className="text-xs text-text-muted font-sans">
            Approve only if the agent reports the code {d.user_code}.
          </p>
          {status.replaces && (
            <label className="flex items-center gap-2 text-xs font-sans">
              <input
                type="checkbox"
                checked={replace}
                onChange={(e) => setReplace(e.target.checked)}
              />
              Replace {status.replaces.name}: its current key stops working
            </label>
          )}
          <div className="flex gap-2">
            <Button
              disabled={busy || (!!status.replaces && !replace)}
              onClick={() => act(() => approveJoin(d.user_code, status.profile, replace))}
            >
              approve
            </Button>
            <Button variant="outline" disabled={busy} onClick={reject}>
              reject
            </Button>
          </div>
        </div>
      )}
      {state === "approved" && (
        <p className="text-xs font-sans">Approved; the agent is finishing the setup…</p>
      )}
      {message && (
        <div className="space-y-2">
          <p className="text-xs font-sans">{message}</p>
          {state !== "joined" && (
            <Button variant="outline" onClick={join.reset}>
              new prompt
            </Button>
          )}
        </div>
      )}
      {(actionErr || join.err) && <ErrorLine err={actionErr || join.err} />}
    </Box>
  );
}

function Box({ children }: { children: ReactNode }) {
  return (
    <div className="border-1.5 border-navy px-3 py-3 space-y-3 text-sm font-sans text-text">
      {children}
    </div>
  );
}
