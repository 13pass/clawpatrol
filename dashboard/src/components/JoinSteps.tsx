import { useState } from "react";
import { Button } from "./Button";
import { copyText } from "../lib/clipboard";

const INSTALL_CMD = "curl -fsSL https://clawpatrol.dev/install.sh | sh";
const COPIED_FEEDBACK_MS = 1500;

// shellArg quotes s for copy-paste into a POSIX shell when it
// contains anything beyond plain word characters.
function shellArg(s: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s)) return s;
  return "'" + s.replaceAll("'", "'\\''") + "'";
}

export type JoinMode = "run" | "whole-machine";

export function joinCommand(opts: {
  url: string;
  profile?: string;
  hostname?: string;
  mode?: JoinMode;
  login?: boolean;
}): string {
  const hostname = opts.hostname?.trim();
  return [
    "clawpatrol",
    "join",
    ...(opts.login ? ["--login"] : []),
    ...(opts.mode === "whole-machine" ? ["--whole-machine"] : []),
    ...(hostname ? ["--hostname", shellArg(hostname)] : []),
    ...(opts.profile ? ["--profile", shellArg(opts.profile)] : []),
    opts.url,
  ].join(" ");
}

// JoinSteps shows the install and join commands for a new device on
// profile, with the device name and the routing mode to choose.
// login marks a join that auto-approves through the operator's own
// tailnet identity.
export function JoinSteps({
  url,
  profile,
  login = false,
}: {
  url: string;
  profile?: string;
  login?: boolean;
}) {
  const [hostname, setHostname] = useState("");
  // Per-process `clawpatrol run` is the default; --whole-machine
  // installs system Tailscale and routes all of the machine's network
  // traffic through clawpatrol.
  const [mode, setMode] = useState<JoinMode>("run");

  return (
    <div className="space-y-5">
      <div className="space-y-3">
        <label className="block space-y-1">
          <span className="text-xs text-text-muted font-sans">Device name (optional)</span>
          <input
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder="defaults to the machine's hostname"
            autoComplete="off"
            className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-xs text-text-muted font-sans">Mode</span>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as JoinMode)}
            className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
          >
            <option value="run">clawpatrol run (per-process, default)</option>
            <option value="whole-machine">
              --whole-machine (route all of this machine's traffic through clawpatrol)
            </option>
          </select>
        </label>
      </div>

      <Step n={1} label="Install" cmd={INSTALL_CMD} />
      <Step
        n={2}
        label={login ? "Join (auto-approves via your tailnet identity)" : "Join"}
        cmd={joinCommand({ url, profile, hostname, mode, login })}
      />
    </div>
  );
}

function Step({ n, label, cmd }: { n: number; label: string; cmd: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    if (await copyText(cmd)) {
      setCopied(true);
      setTimeout(() => setCopied(false), COPIED_FEEDBACK_MS);
    }
  }
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="w-6 h-6 squircle-md bg-navy-100 text-xs font-semibold font-mono flex items-center justify-center shrink-0">
            {n}
          </span>
          <span className="text-sm text-text-muted font-sans truncate">{label}</span>
        </div>
        <Button variant="outline" onClick={copy} className="shrink-0">
          {copied ? "copied" : "copy"}
        </Button>
      </div>
      <pre className="bg-navy rounded px-4 py-4 text-xs font-mono text-canvas overflow-x-auto whitespace-pre">
        {cmd}
      </pre>
    </div>
  );
}
