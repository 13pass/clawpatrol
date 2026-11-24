import { useEffect, useState, type ReactNode } from "react";
import {
  approveJoin,
  createJoinIntent,
  getJoinIntentStatus,
  rejectJoinIntent,
  type JoinIntent,
  type JoinIntentState,
  type JoinIntentStatus,
} from "../lib/api";
import { buildAgentJoinPrompt } from "../lib/agentJoinPrompt";
import { copyText } from "../lib/clipboard";
import { fmtTime } from "../lib/format";
import { Button } from "./Button";

const POLL_INTERVAL_MS = 2000;
const COPIED_FLASH_MS = 1500;
const MS_PER_SECOND = 1000;
const LIVE_STATES: JoinIntentState[] = ["waiting", "pending", "approved"];

// "gone": the gateway no longer knows the intent (it restarted, or the
// intent outlived its retention).
type JoinState = JoinIntentState | "gone";

export type JoinIntentHandle = ReturnType<typeof useJoinIntent>;

// useJoinIntent owns the Add device window's join intent and follows it
// while it is live. It lives in the window, not the tab, so switching
// tabs keeps the join; closing the window cancels it (cancelIfLive).
export function useJoinIntent() {
  const [intent, setIntent] = useState<JoinIntent | null>(null);
  const [status, setStatus] = useState<JoinIntentStatus | null>(null);
  const [gone, setGone] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!intent) return;
    const id = intent.id;
    const loop: { stopped: boolean; timer?: ReturnType<typeof setTimeout> } = { stopped: false };
    async function poll() {
      try {
        const s = await getJoinIntentStatus(id);
        if (loop.stopped) return;
        if (!s) {
          setGone(true);
          return;
        }
        setStatus(s);
        setErr("");
        if (!LIVE_STATES.includes(s.state)) return;
      } catch (e) {
        if (!loop.stopped) setErr(String(e));
      }
      if (!loop.stopped) loop.timer = setTimeout(poll, POLL_INTERVAL_MS);
    }
    loop.timer = setTimeout(poll, 0);
    return () => {
      loop.stopped = true;
      clearTimeout(loop.timer);
    };
  }, [intent]);

  const state: JoinState | null = gone ? "gone" : (status?.state ?? (intent ? "waiting" : null));
  const live = state !== null && (LIVE_STATES as JoinState[]).includes(state);

  return {
    intent,
    status,
    state,
    live,
    err,
    setErr,
    setStatus,
    async create(profile: string, deviceName: string) {
      setErr("");
      try {
        setIntent(await createJoinIntent(profile, deviceName));
        setStatus(null);
        setGone(false);
      } catch (e) {
        setErr(String(e));
      }
    },
    // cancelIfLive rejects the intent unless it already ended, so a
    // prompt the operator walked away from stops working.
    cancelIfLive() {
      if (intent && live) rejectJoinIntent(intent.id).catch(() => {});
    },
    reset() {
      if (intent && live) rejectJoinIntent(intent.id).catch(() => {});
      setIntent(null);
      setStatus(null);
      setGone(false);
      setErr("");
    },
  };
}

// AgentJoinPanel is the Add device window's "Agent prompt" tab: it
// creates a join intent, shows the prompt to give an agent on the new
// device, then follows the join so the operator approves it here.
export function AgentJoinPanel({
  gatewayURL,
  profile,
  profileRequired,
  join,
}: {
  gatewayURL: string;
  profile: string;
  profileRequired: boolean;
  join: JoinIntentHandle;
}) {
  const [deviceName, setDeviceName] = useState("");
  const [busy, setBusy] = useState(false);
  const { intent } = join;

  if (!intent) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-text-muted font-sans">
          Creates a single-use prompt for an AI agent on the new device. The agent runs the join;
          you approve it here after checking the code it reports. The prompt contains no secret.
          Closing this window cancels the prompt.
        </p>
        <label className="block space-y-1">
          <span className="text-xs text-text-muted font-sans">
            Device name (optional; default &lt;machine&gt;-&lt;OS account&gt;)
          </span>
          <input
            value={deviceName}
            onChange={(e) => setDeviceName(e.target.value)}
            placeholder="hz-2025-fsn-gemma"
            className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
          />
        </label>
        {join.err && <p className="text-xs text-danger-500 font-mono break-words">{join.err}</p>}
        <Button
          onClick={async () => {
            setBusy(true);
            await join.create(profile, deviceName.trim());
            setBusy(false);
          }}
          disabled={busy || (profileRequired && !profile)}
        >
          {busy ? "creating…" : "create prompt"}
        </Button>
      </div>
    );
  }

  const prompt = buildAgentJoinPrompt({
    gatewayURL,
    caFingerprint: intent.ca_fingerprint,
    profile: intent.profile,
    deviceName: intent.device_name,
    intent: intent.id,
    expiresAt: intent.expires_at,
  });

  return (
    <div className="space-y-4">
      <PromptBlock prompt={prompt} />
      <StatusPanel join={join} />
      {join.err && <p className="text-xs text-danger-500 font-mono break-words">{join.err}</p>}
    </div>
  );
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
          Give this to the agent on the new device
        </span>
        <Button variant="outline" onClick={copy} className="shrink-0">
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
  const { intent, status, state } = join;

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    join.setErr("");
    try {
      await fn();
    } catch (e) {
      join.setErr(String(e));
    } finally {
      setBusy(false);
    }
  }
  const reject = () =>
    act(async () => {
      if (intent) join.setStatus(await rejectJoinIntent(intent.id));
    });

  const ended: Partial<Record<JoinState, string>> = {
    joined: `${status?.device?.name} joined profile ${status?.profile}. Ask the agent for its report.`,
    rejected: "Cancelled. Nothing joined.",
    conflict:
      "A second device used this prompt, so both joins were cancelled. The prompt may have leaked; make a new one.",
    expired: "The prompt expired before the join finished.",
    failed: `Setting the device up failed after approval: ${status?.error ?? "unknown error"}`,
    gone: "The gateway no longer knows this prompt (it restarted, or the prompt is too old).",
  };
  const message = state ? ended[state] : undefined;

  if (state === "waiting") {
    return (
      <Box>
        <p>
          Waiting for the agent to start the join (prompt expires{" "}
          {fmtTime((status?.expires_at ?? intent!.expires_at) * MS_PER_SECOND)})…
        </p>
        <Button variant="outline" disabled={busy} onClick={reject}>
          cancel prompt
        </Button>
      </Box>
    );
  }
  const d = status?.device;

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
          <dt className="text-text-muted">OS account</dt>
          <dd>
            {d.os_user || "?"}@{d.os_hostname || "?"} · {d.os || "?"}
          </dd>
          <dt className="text-text-muted">Profile</dt>
          <dd>{status.profile || "gateway default"}</dd>
          <dt className="text-text-muted">Code</dt>
          <dd className="font-semibold">{d.user_code}</dd>
          {status.on_machine && status.on_machine.length > 0 && (
            <>
              <dt className="text-text-muted">Same machine</dt>
              <dd>
                {status.on_machine
                  .map(
                    (x) =>
                      `${x.name} (${x.profile || "no profile"})${x.by_name ? " [by name only]" : ""}`,
                  )
                  .join(", ")}
              </dd>
            </>
          )}
        </dl>
      )}
      {state !== "gone" &&
        status?.warnings?.map((w) => (
          <p key={w} className="text-xs text-amber-600 font-sans">
            ⚠ {w}
          </p>
        ))}
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
