import { useState, type FormEvent } from "react";
import { changeOwnPassword, logout, type Whoami } from "../lib/api";
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
  const enabled = method === "password";
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
