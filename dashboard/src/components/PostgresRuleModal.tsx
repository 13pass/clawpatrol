import { useEffect, useState, type ReactNode } from "react";
import {
  createRule,
  previewRule,
  setCredentialSlots,
  type EventRecord,
  type PostgresOutcome,
  type PostgresSSLMode,
  type RulePreviewResp,
  type RuleRequest,
  type Whoami,
} from "../lib/api";
import { Button } from "./Button";
import { CopyButton } from "./CopyButton";
import { Modal } from "./Modal";
import {
  calloutClass,
  ChoiceCards,
  CopyHCLButton,
  HCLPreview,
  inputClass,
  labelClass,
  PREVIEW_DEBOUNCE_MS,
  ReviewerField,
  RuleKindHeader,
} from "./RuleBuilder";

// postgres_credential has a single, unnamed secret slot.
const POSTGRES_PASSWORD_SLOT = "";

const OUTCOMES: { value: PostgresOutcome; label: string; help: string; badge?: string }[] = [
  {
    value: "log",
    label: "Log every statement",
    help: "Each statement is recorded in the request history. Nothing is held.",
  },
  {
    value: "approve_changes",
    label: "Require approval for changes",
    badge: "Recommended",
    help: "Reads (SELECT, SHOW, EXPLAIN) and transaction statements go through. Anything else waits for a reviewer.",
  },
  {
    value: "approve_all",
    label: "Require approval for every statement",
    help: "Every statement waits for a reviewer.",
  },
  {
    value: "deny",
    label: "Block this database",
    help: "Every statement is refused. No password is needed.",
  },
];

const SSL_MODES: { value: PostgresSSLMode; label: string }[] = [
  { value: "require", label: "Encrypted (require)" },
  { value: "prefer", label: "Encrypted if the server offers it (prefer)" },
  { value: "disable", label: "Off (disable)" },
];

type Settings = {
  name: string;
  user: string;
  sslmode: PostgresSSLMode;
  outcome: PostgresOutcome;
  approver: string;
};

function postgresRequest(s: Settings): RuleRequest {
  return {
    approver: s.approver,
    postgres: {
      name: s.name.trim() || undefined,
      user: s.user.trim(),
      sslmode: s.sslmode,
      outcome: s.outcome,
    },
  };
}

type Phase =
  | { step: "form" }
  | { step: "saving-config" }
  | { step: "saving-password"; credential: string }
  | { step: "password-failed"; credential: string; error: string }
  | { step: "done" };

// PostgresRuleModal turns a Postgres connection the gateway relayed
// uninspected into an endpoint it inspects: an endpoint for the
// address, a credential the gateway logs in with, and what happens to
// each statement. The password goes to the secret store, never to the
// config file, so it is saved by a second call once the config loads.
export function PostgresRuleModal({
  ev,
  whoami,
  onClose,
}: {
  ev: EventRecord;
  whoami: Whoami | null;
  onClose: () => void;
}) {
  const isAdmin = whoami?.role !== "member";
  const address = ev.host.slice(0, ev.host.lastIndexOf(":"));
  const [name, setName] = useState("");
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [sslmode, setSSLMode] = useState<PostgresSSLMode>("require");
  const [outcome, setOutcome] = useState<PostgresOutcome>("approve_changes");
  const [approver, setApprover] = useState("");
  const [preview, setPreview] = useState<RulePreviewResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>({ step: "form" });

  const blocking = outcome === "deny";
  const needsApprover = outcome === "approve_changes" || outcome === "approve_all";
  const missingUser = !blocking && !user.trim();
  const missingPassword = !blocking && !password;

  useEffect(() => {
    if (!ev.id || phase.step !== "form") return;
    if (missingUser) {
      setPreview(null);
      setErr(null);
      return;
    }
    let cancelled = false;
    const t = setTimeout(() => {
      previewRule(ev.id!, postgresRequest({ name, user, sslmode, outcome, approver }))
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
  }, [ev.id, name, user, sslmode, outcome, approver, phase.step, missingUser]);

  async function savePassword(credential: string) {
    setPhase({ step: "saving-password", credential });
    try {
      const res = await setCredentialSlots(credential, { [POSTGRES_PASSWORD_SLOT]: password });
      if (!res.ok) throw new Error(res.error || "the gateway did not save it");
      setPhase({ step: "done" });
    } catch (e) {
      setPhase({ step: "password-failed", credential, error: (e as Error).message });
    }
  }

  async function create() {
    if (!ev.id) return;
    setPhase({ step: "saving-config" });
    try {
      const created = await createRule(
        ev.id,
        postgresRequest({ name, user, sslmode, outcome, approver }),
      );
      if (password && created.new_credential) {
        await savePassword(created.new_credential);
      } else {
        setPhase({ step: "done" });
      }
    } catch (e) {
      setErr((e as Error).message || "create failed");
      setPhase({ step: "form" });
    }
  }

  const endpointName = preview?.rule.endpoint_name;
  const busy = phase.step === "saving-config" || phase.step === "saving-password";
  const canSave = !!preview?.writes_enabled && !missingUser && !missingPassword && !busy;

  return (
    <Modal title="Inspect a Postgres database" size="lg" onClose={busy ? () => {} : onClose}>
      <div className="p-4 space-y-4 overflow-auto">
        <RuleKindHeader
          kind="Postgres"
          host={ev.host}
          note={
            phase.step === "done"
              ? ""
              : "This connection passed through uninspected: no endpoint covers this database yet."
          }
        />
        {phase.step === "done" ? (
          <DoneScreen
            address={address}
            user={user.trim()}
            outcome={outcome}
            endpointName={endpointName}
            agentIP={ev.agent_ip}
          />
        ) : phase.step === "password-failed" ? (
          <div className="space-y-3">
            <div className={calloutClass}>
              The database endpoint was saved and loaded, but the password was not: {phase.error}.
              Statements are refused until the password is set.
            </div>
            <label className="flex flex-col gap-1 max-w-sm">
              <span className={labelClass}>Password for {user.trim()}</span>
              <input
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={inputClass}
              />
            </label>
          </div>
        ) : (
          <>
            <fieldset className="space-y-3">
              <legend className={labelClass}>1 · Database</legend>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field
                  label="Address"
                  help="Taken from this connection. Claw Patrol recognises the database by it."
                >
                  <input value={ev.host} readOnly className={inputClass + " text-text-muted"} />
                </Field>
                <Field label="Name" help="The endpoint's name in the config.">
                  <input
                    value={name}
                    placeholder={endpointName ?? "generated from the address"}
                    onChange={(e) => setName(e.target.value)}
                    className={inputClass}
                  />
                </Field>
                <Field
                  label="Database user"
                  help="The role Claw Patrol logs in as. The agent's own user and password are ignored."
                >
                  <input
                    value={user}
                    autoComplete="off"
                    placeholder={blocking ? "optional when blocking" : "e.g. app_readwrite"}
                    onChange={(e) => setUser(e.target.value)}
                    className={inputClass}
                  />
                </Field>
                <Field
                  label="Password"
                  help="Kept in the gateway's secret store, like Settings → Credentials. It is never written to the config."
                >
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={password}
                    placeholder={blocking ? "not needed when blocking" : ""}
                    disabled={blocking}
                    onChange={(e) => setPassword(e.target.value)}
                    className={inputClass}
                  />
                </Field>
                <Field
                  label="Encryption to the database"
                  help="Azure and most hosted Postgres require it. Certificate checks need a host name, and this database is known by its address only."
                >
                  <select
                    value={sslmode}
                    onChange={(e) => setSSLMode(e.target.value as PostgresSSLMode)}
                    className={inputClass}
                  >
                    {SSL_MODES.map((m) => (
                      <option key={m.value} value={m.value}>
                        {m.label}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
            </fieldset>

            <fieldset className="space-y-2">
              <legend className={labelClass}>2 · What should happen to each statement</legend>
              <ChoiceCards
                name="outcome"
                choices={OUTCOMES}
                value={outcome}
                onChange={setOutcome}
              />
              {needsApprover && (
                <ReviewerField whoami={whoami} approver={approver} onChange={setApprover} />
              )}
              <p className="text-xs text-text-muted">
                Finer rules, for one table or one kind of statement, can be made later from the
                statements this records.
              </p>
            </fieldset>

            <section className="space-y-2">
              <h3 className={labelClass}>3 · Review</h3>
              {missingUser ? (
                <p className="text-xs text-text-muted">
                  Enter the database user to see what will be added.
                </p>
              ) : err ? (
                <div className="text-sm text-danger-500 whitespace-pre-wrap">{err}</div>
              ) : preview ? (
                <ReviewSummary preview={preview} isAdmin={isAdmin} />
              ) : (
                <p className="text-xs text-text-subtle">Generating…</p>
              )}
            </section>
          </>
        )}
      </div>
      <div className="flex items-center gap-2 justify-end px-4 py-3 border-t border-navy bg-navy-100">
        {phase.step === "done" ? (
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        ) : phase.step === "password-failed" ? (
          <>
            <Button variant="outline" onClick={onClose}>
              Set it later in Settings
            </Button>
            <Button disabled={!password} onClick={() => savePassword(phase.credential)}>
              Save password
            </Button>
          </>
        ) : (
          <>
            <Button variant="outline" disabled={busy} onClick={onClose}>
              Cancel
            </Button>
            {preview && !preview.writes_enabled ? (
              <CopyHCLButton hcl={preview.rule.hcl} primary />
            ) : (
              <Button disabled={!canSave} onClick={create}>
                {phase.step === "saving-config"
                  ? "Saving config…"
                  : phase.step === "saving-password"
                    ? "Saving password…"
                    : blocking
                      ? "Block this database"
                      : "Inspect this database"}
              </Button>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}

function Field({ label, help, children }: { label: string; help: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className={labelClass}>{label}</span>
      {children}
      <span className="text-2xs text-text-muted">{help}</span>
    </label>
  );
}

function ReviewSummary({ preview, isAdmin }: { preview: RulePreviewResp; isAdmin: boolean }) {
  const rule = preview.rule;
  const [showHCL, setShowHCL] = useState(false);
  return (
    <div className="space-y-2">
      <ul className="text-xs text-text list-disc pl-5 space-y-0.5">
        <li>
          endpoint <code className="font-bold">{rule.endpoint_name}</code>, inspecting this address
        </li>
        <li>
          credential <code className="font-bold">{rule.new_credential}</code>, the login the gateway
          uses
        </li>
        {rule.rule_name ? (
          <li>
            rule <code className="font-bold">{rule.rule_name}</code>
          </li>
        ) : (
          <li>no rule: statements are allowed and recorded</li>
        )}
        <li>
          for {rule.profile_additions && rule.profile_additions.length > 1 ? "profiles" : "profile"}{" "}
          <code>{rule.profile_additions?.join(", ")}</code>
        </li>
      </ul>
      <p className="text-xs text-text-muted">
        {preview.recent_sampled} recent{" "}
        {preview.recent_sampled === 1 ? "connection" : "connections"}{" "}
        {isAdmin ? "" : "from your profile "}reached this address uninspected. Written to{" "}
        <code>{preview.file}</code>.
      </p>
      {rule.warnings?.map((w) => (
        <div key={w} className={calloutClass}>
          {w}
        </div>
      ))}
      {!preview.writes_enabled && preview.writes_unavailable && (
        <div className={calloutClass}>
          This can't be saved from the dashboard: {preview.writes_unavailable}. Copy the HCL into
          your config and deploy it the usual way, then paste the password under Settings →
          Credentials for <code>{rule.new_credential}</code>.
        </div>
      )}
      <button
        type="button"
        className="text-xs underline text-text-muted"
        onClick={() => setShowHCL(!showHCL)}
      >
        {showHCL ? "Hide HCL" : "Show HCL"}
      </button>
      {showHCL && (
        <div className="space-y-2">
          <HCLPreview hcl={rule.hcl} />
          <CopyHCLButton hcl={rule.hcl} />
        </div>
      )}
    </div>
  );
}

function DoneScreen({
  address,
  user,
  outcome,
  endpointName,
  agentIP,
}: {
  address: string;
  user: string;
  outcome: PostgresOutcome;
  endpointName?: string;
  agentIP?: string;
}) {
  const psql = `psql "host=${address} port=5432 user=${user || "<user>"} dbname=<database> sslmode=disable"`;
  return (
    <div className="space-y-4">
      <p className="text-sm text-text">
        {outcome === "deny" ? (
          <>
            ✓ Statements to <code className="font-bold">{address}</code> are now refused.
          </>
        ) : (
          <>
            ✓ <code className="font-bold">{address}</code> is now inspected
            {endpointName && (
              <>
                {" "}
                as <code>{endpointName}</code>
              </>
            )}
            . New connections record each statement in the request history.
          </>
        )}
      </p>
      {outcome !== "deny" && (
        <div className="border-1.5 border-navy p-3 space-y-2">
          <h3 className={labelClass}>Connect the agent</h3>
          <ul className="text-xs text-text list-disc pl-5 space-y-1">
            <li>
              Connect <span className="font-bold">without TLS</span> (<code>sslmode=disable</code>{" "}
              or <code>prefer</code>). The gateway encrypts the connection to the database itself
              and refuses a client that requires TLS.
            </li>
            <li>
              Any password works: the gateway logs in as <code>{user}</code>.
            </li>
            <li>Connections already open stay uninspected until they reconnect.</li>
          </ul>
          <div className="flex items-center gap-2">
            <code className="text-xs bg-canvas-muted px-2 py-1 overflow-auto">{psql}</code>
            <CopyButton text={() => psql} label="psql command" />
          </div>
        </div>
      )}
      <details className="text-xs">
        <summary className="cursor-pointer text-text-muted">If it doesn't connect</summary>
        <ul className="list-disc pl-5 mt-2 space-y-1 text-text">
          <li>
            The server must store the role's password as SCRAM-SHA-256. MD5 logins are not
            supported.
          </li>
          <li>
            Login errors reach the client's error message and the gateway log, not this dashboard.
          </li>
          <li>The password can be changed under Settings → Credentials.</li>
        </ul>
      </details>
      <p className="text-xs text-text-muted">
        <a href="#/rules" className="underline">
          View rules
        </a>
        {agentIP && (
          <>
            {" · "}
            <a href={`#/device/${encodeURIComponent(agentIP)}`} className="underline">
              Request history of this device
            </a>
          </>
        )}
      </p>
    </div>
  );
}
