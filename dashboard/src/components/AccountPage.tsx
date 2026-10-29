import { useEffect, useState, type FormEvent } from "react";
import {
  changeOwnPassword,
  deleteMyChannel,
  getMyChannel,
  logout,
  resendMyChannelCode,
  setMyChannel,
  testMyChannel,
  verifyMyChannel,
  type UserChannel,
  type Whoami,
} from "../lib/api";
import { credentialTypeLabel } from "../lib/credentialLabels";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// Mirrors dashboardMinPasswordLen on the server, which re-checks it.
const MIN_PASSWORD_LEN = 12;

// AccountPage shows the currently authenticated principal (moved
// here from the global Header), logging out, and — for password
// sessions — changing one's own password.
export function AccountPage({ whoami }: { whoami: Whoami | null }) {
  return (
    <Main>
      <PageTitle trail={[{ label: "Account" }]} />
      {whoami?.role === "member" && <MemberNotice profiles={whoami.profiles ?? []} />}
      <section className="bg-canvas border-1.5 border-navy p-4 space-y-4">
        {whoami?.user ? <Identity whoami={whoami} /> : <NotLoggedIn />}
      </section>
      {(whoami?.auth_method === "password" || whoami?.auth_method === "oidc") && (
        <section className="bg-canvas border-1.5 border-navy p-4 space-y-3">
          <NotificationChannel />
        </section>
      )}
      {/* A single sign-on session changes its password at the provider. */}
      {whoami?.auth_method === "password" && (
        <section className="bg-canvas border-1.5 border-navy p-4">
          <ChangePasswordForm />
        </section>
      )}
    </Main>
  );
}

// MemberNotice tells a member what their account covers.
function MemberNotice({ profiles }: { profiles: string[] }) {
  return (
    <section className="bg-butter-100 border-1.5 border-butter-300 p-4 text-sm text-text">
      Your account has the <span className="font-bold">member</span> role. You see and manage the
      devices, requests, approvals and rules of{" "}
      {profiles.length ? (
        <>
          your profiles: <span className="font-mono font-bold">{profiles.join(", ")}</span>
        </>
      ) : (
        "your profiles — none are assigned yet; ask an admin"
      )}
      . Credentials shared with other teams are managed by an admin.
    </section>
  );
}

function ChangePasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (next !== confirm) {
      setMsg({ ok: false, text: "The new passwords do not match." });
      return;
    }
    setSaving(true);
    try {
      await changeOwnPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setMsg({ ok: true, text: "Password changed. Your other sessions were logged out." });
    } catch (e) {
      setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) });
    } finally {
      setSaving(false);
    }
  }

  const input =
    "border border-canvas-dark rounded px-2 py-1.5 text-xs focus:outline-none focus:border-text";
  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
      <label className="flex flex-col gap-1">
        <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Current password
        </span>
        <input
          type="password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
          autoComplete="current-password"
          className={input}
        />
      </label>
      <label className="flex flex-col gap-1">
        <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
          New password
        </span>
        <input
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
          minLength={MIN_PASSWORD_LEN}
          autoComplete="new-password"
          className={input}
        />
      </label>
      <label className="flex flex-col gap-1">
        <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Confirm new password
        </span>
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
          minLength={MIN_PASSWORD_LEN}
          autoComplete="new-password"
          className={input}
        />
      </label>
      <Button type="submit" disabled={saving}>
        {saving ? "Saving…" : "Change password"}
      </Button>
      {msg && (
        <div className={"basis-full text-xs " + (msg.ok ? "text-text" : "text-danger-500")}>
          {msg.text}
        </div>
      )}
    </form>
  );
}

function Identity({ whoami }: { whoami: Whoami }) {
  const method =
    whoami.auth_method === "password"
      ? "password"
      : whoami.auth_method === "tailscale"
        ? "tailscale"
        : whoami.auth_method === "oidc"
          ? "single sign-on"
          : null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-text">
        Logged in as <span className="font-bold">{whoami.user}</span>
        {method && (
          <>
            {" "}
            via <span className="font-bold">{method}</span>
          </>
        )}
        {whoami.role && (
          <>
            {" "}
            with the <span className="font-bold">{whoami.role}</span> role
          </>
        )}
        .
      </p>
      <LogoutControl whoami={whoami} />
    </div>
  );
}

function NotLoggedIn() {
  return <p className="text-sm text-text-muted">Not logged in.</p>;
}

// LogoutControl is enabled only when the active session is one the
// gateway can revoke — i.e. password auth. Tailnet allowlist hits
// have no server-side session to clear (the operator's tailnet
// identity is what's letting them in), so the button stays visible
// but disabled with a tooltip explaining why.
function LogoutControl({ whoami }: { whoami: Whoami }) {
  const method = whoami.auth_method;
  // Password and single sign-on sessions share the revocable cookie.
  const enabled = method === "password" || method === "oidc";
  const title = enabled
    ? "Log out"
    : method === "tailscale"
      ? "Tailnet auth — disconnect from tailscale to revoke access"
      : "Log out";
  const handle = async () => {
    if (!enabled) return;
    try {
      await logout();
    } finally {
      // Even on a network error we reload — the cookie may have
      // been cleared client-side, in which case the gate will
      // redirect to /__login on the next request.
      window.location.href = "/__login";
    }
  };
  return (
    <Button
      size="sm"
      onClick={handle}
      disabled={!enabled}
      title={title}
      aria-label={enabled ? "Log out" : "Log out (disabled — tailnet auth)"}
    >
      Log out
    </Button>
  );
}

const INPUT_CLASS =
  "border border-canvas-dark rounded px-2 py-1.5 text-xs focus:outline-none focus:border-text";

// TARGET_HINT is the placeholder for a kind's recipient field.
const TARGET_HINT: Record<string, string> = {
  signal_cli: "+41790000000 or group.<id>",
};

// NotificationChannel is where the user's approval prompts go: one
// channel, active once the code sent there is typed back.
function NotificationChannel() {
  const [channel, setChannel] = useState<UserChannel | null>(null);
  const [kinds, setKinds] = useState<string[]>([]);
  const [kind, setKind] = useState("");
  const [target, setTarget] = useState("");
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    const r = await getMyChannel();
    setChannel(r.channel);
    setKinds(r.kinds);
    setKind((k) => k || r.kinds[0] || "");
  }

  useEffect(() => {
    load().catch((e) => setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) }));
  }, []);

  async function run(action: () => Promise<void>, done: string) {
    setBusy(true);
    try {
      await action();
      await load();
      setMsg({ ok: true, text: done });
    } catch (e) {
      setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) });
    } finally {
      setBusy(false);
    }
  }

  function save(e: FormEvent) {
    e.preventDefault();
    run(async () => {
      await setMyChannel(kind, target);
      setTarget("");
    }, "A code was sent there. Type it below to start receiving approval prompts.");
  }

  function verify(e: FormEvent) {
    e.preventDefault();
    run(async () => {
      await verifyMyChannel(code);
      setCode("");
    }, "Verified. Approval prompts for your agents now come here.");
  }

  const label = (k: string) => credentialTypeLabel(k, k);
  return (
    <>
      <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">Notifications</h2>
      <p className="text-sm text-text">
        Approval prompts for your agents go to your own channel. Until it is verified they go to an
        admin.
      </p>
      {channel && (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span>
            {label(channel.kind)} <span className="font-mono font-bold">{channel.target}</span>{" "}
            {channel.verified ? (
              <span className="text-text-muted">verified</span>
            ) : (
              <span className="text-danger-500">not verified</span>
            )}
          </span>
          {channel.verified ? (
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => run(testMyChannel, "Test message sent.")}
            >
              Send a test message
            </Button>
          ) : (
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => run(resendMyChannelCode, "A new code was sent.")}
            >
              Send a new code
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => run(deleteMyChannel, "Channel removed. Your prompts go to an admin.")}
          >
            Remove
          </Button>
        </div>
      )}
      {channel && !channel.verified && (
        <form onSubmit={verify} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1">
            <span className="font-mono text-xs uppercase tracking-wider text-text-muted">Code</span>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              inputMode="numeric"
              autoComplete="one-time-code"
              className={INPUT_CLASS}
            />
          </label>
          <Button type="submit" disabled={busy}>
            Verify
          </Button>
        </form>
      )}
      {kinds.length === 0 ? (
        <p className="text-xs text-text-muted">
          The gateway has no notifier for personal channels yet; ask an admin.
        </p>
      ) : (
        <form onSubmit={save} className="flex flex-wrap items-end gap-3">
          {kinds.length > 1 && (
            <label className="flex flex-col gap-1">
              <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
                Via
              </span>
              <select
                value={kind}
                onChange={(e) => setKind(e.target.value)}
                className={INPUT_CLASS + " bg-canvas"}
              >
                {kinds.map((k) => (
                  <option key={k} value={k}>
                    {label(k)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="flex flex-col gap-1">
            <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
              {channel ? "New " : ""}
              {label(kind)} recipient
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
              placeholder={TARGET_HINT[kind] ?? ""}
              className={INPUT_CLASS + " w-72"}
            />
          </label>
          <Button type="submit" disabled={busy}>
            {busy ? "Sending…" : "Send code"}
          </Button>
        </form>
      )}
      {msg && (
        <div className={"text-xs " + (msg.ok ? "text-text" : "text-danger-500")}>{msg.text}</div>
      )}
    </>
  );
}
