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
import { buildAgentJoinPrompt, formatExpiry } from "../lib/agentJoinPrompt";
import { copyText } from "../lib/clipboard";
import { Button } from "./Button";

const POLL_INTERVAL_MS = 2000;
const COPIED_FLASH_MS = 1500;
const LIVE_STATES: JoinIntentState[] = ["waiting", "pending", "approved"];

// AgentJoinPanel is the Add device window's "Agent prompt" tab: it
// creates a join intent, shows the prompt to give an agent on the new
// device, then follows the join so the operator approves it here. The
// intent carries the profile, so the caller keys this panel by profile.
export function AgentJoinPanel({ gatewayURL, profile }: { gatewayURL: string; profile: string }) {
  const [deviceName, setDeviceName] = useState("");
  const [intent, setIntent] = useState<JoinIntent | null>(null);
  const [status, setStatus] = useState<JoinIntentStatus | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!intent) return;
    const id = intent.id;
    const loop: { stopped: boolean; timer?: ReturnType<typeof setTimeout> } = { stopped: false };
    async function poll() {
      try {
        const s = await getJoinIntentStatus(id);
        if (loop.stopped) return;
        setStatus(s);
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

  async function create() {
    setBusy(true);
    setErr("");
    try {
      setIntent(await createJoinIntent(profile, deviceName.trim()));
      setStatus(null);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!intent) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-text-muted font-sans">
          Creates a single-use prompt for an AI agent on the new device. The agent runs the join;
          you approve it here after checking the code it reports. The prompt contains no secret.
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
        {err && <p className="text-xs text-danger-500 font-mono break-words">{err}</p>}
        <Button onClick={create} disabled={busy || !profile}>
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
      <StatusPanel
        status={status}
        onChange={setStatus}
        onError={setErr}
        onRestart={() => {
          setIntent(null);
          setStatus(null);
        }}
      />
      {err && <p className="text-xs text-danger-500 font-mono break-words">{err}</p>}
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

function StatusPanel({
  status,
  onChange,
  onError,
  onRestart,
}: {
  status: JoinIntentStatus | null;
  onChange: (s: JoinIntentStatus) => void;
  onError: (e: string) => void;
  onRestart: () => void;
}) {
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!status || status.state === "waiting") {
    return (
      <Box>
        Waiting for the agent to start the join
        {status ? ` (prompt expires ${formatExpiry(status.expires_at)})` : ""}…
      </Box>
    );
  }
  const d = status.device;

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    onError("");
    try {
      await fn();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const ended: Partial<Record<JoinIntentState, string>> = {
    joined: `${d?.name} joined profile ${status.profile}. Ask the agent for its report.`,
    rejected: "Rejected. Nothing joined.",
    conflict:
      "A second device used this prompt, so both joins were cancelled. The prompt may have leaked; make a new one.",
    expired: "The prompt expired before the join finished.",
  };
  const message = ended[status.state];

  return (
    <Box>
      {d && (
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
          <dd>{status.profile}</dd>
          <dt className="text-text-muted">Code</dt>
          <dd className="font-semibold">{d.user_code}</dd>
          {status.on_machine && status.on_machine.length > 0 && (
            <>
              <dt className="text-text-muted">Same machine</dt>
              <dd>
                {status.on_machine
                  .map((x) => `${x.name} (${x.profile || "no profile"})`)
                  .join(", ")}
              </dd>
            </>
          )}
        </dl>
      )}
      {status.warnings?.map((w) => (
        <p key={w} className="text-xs text-amber-600 font-sans">
          ⚠ {w}
        </p>
      ))}
      {status.state === "pending" && (
        <div className="space-y-2">
          <p className="text-xs text-text-muted font-sans">
            Approve only if the agent reports the code {d?.user_code}.
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
              onClick={() => act(() => approveJoin(d!.user_code, status.profile, replace))}
            >
              approve
            </Button>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => act(async () => onChange(await rejectJoinIntent(status.id)))}
            >
              reject
            </Button>
          </div>
        </div>
      )}
      {status.state === "approved" && (
        <p className="text-xs font-sans">Approved; the agent is finishing the setup…</p>
      )}
      {message && (
        <div className="space-y-2">
          <p className="text-xs font-sans">{message}</p>
          {status.state !== "joined" && (
            <Button variant="outline" onClick={onRestart}>
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
