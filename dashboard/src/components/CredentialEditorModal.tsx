import { useEffect, useMemo, useState } from "react";
import {
  declareCredential,
  editCredential,
  getCredentialConfigOptions,
  removeCredential,
  type CredentialConfigChange,
  type CredentialConfigOptions,
} from "../lib/api";
import { credentialTypeLabel } from "../lib/credentialLabels";
import { Button } from "./Button";
import { Modal } from "./Modal";

// Declares a credential, or edits one: its header settings, the
// endpoint it binds and the profiles that list it. The gateway writes
// the change to its config files and reloads. The secret itself is
// pasted afterwards in CredentialSecretsModal.

const INPUT_CLASS =
  "border border-canvas-dark rounded px-2 py-1.5 text-xs focus:outline-none focus:border-text";
const LABEL_CLASS = "font-mono text-xs uppercase tracking-wider text-text-muted";

export function CredentialEditorModal({
  name,
  defaultProfile,
  onClose,
  onSaved,
}: {
  // name of the credential to edit; absent to declare a new one.
  name?: string;
  // profile ticked for a new credential (the device's own).
  defaultProfile?: string;
  onClose: () => void;
  // declared is true when a new credential was added, so the caller
  // can ask for its secret.
  // needsSecret is true when the credential has no secret any more (a new
  // one, or one moved to another endpoint), so the caller can ask for it.
  onSaved: (name: string, needsSecret: boolean) => void;
}) {
  const editing = name !== undefined;
  const [opts, setOpts] = useState<CredentialConfigOptions | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [type, setType] = useState("header_token");
  const [credName, setCredName] = useState(name ?? "");
  const [header, setHeader] = useState("");
  const [prefix, setPrefix] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [profiles, setProfiles] = useState<string[]>([]);
  // The profiles listing the credential when the form opened: an edit
  // sends profiles only when they differ, so it never undoes another
  // admin's change to a profile this form did not touch.
  const [initialProfiles, setInitialProfiles] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getCredentialConfigOptions()
      .then((o) => {
        setOpts(o);
        if (name !== undefined) {
          const c = o.credentials[name];
          if (c) {
            setType(c.type);
            setHeader(c.header ?? "");
            setPrefix(c.prefix ?? "");
            setEndpoint(c.endpoint ?? "");
          }
          const listing = o.profiles.filter((p) => p.credentials.includes(name)).map((p) => p.name);
          setProfiles(listing);
          setInitialProfiles(listing);
        } else if (o.profiles.some((p) => p.name === defaultProfile && !p.read_only)) {
          // Pre-tick the device's profile, unless the form cannot change
          // it: a read-only box ticked could not be unticked.
          setProfiles([defaultProfile!]);
        }
      })
      .catch((e) => setLoadErr(String(e.message ?? e)));
  }, [name, defaultProfile]);

  const typeOpt = opts?.types.find((t) => t.type === type);
  const current = editing && opts ? opts.credentials[name] : undefined;
  // Settings and endpoint change only for the types the form knows,
  // and only where the credential's file is not read-only.
  const settingsEditable = !!typeOpt && !(current?.read_only ?? false);
  const hasHeader = typeOpt?.fields.includes("header") ?? false;
  const endpoints = useMemo(
    () => (opts?.endpoints ?? []).filter((e) => typeOpt?.families.includes(e.family)),
    [opts, typeOpt],
  );
  // Remove also edits every profile listing the credential, so a
  // read-only one among them blocks it.
  const lockedProfiles = (opts?.profiles ?? []).filter(
    (p) => p.read_only && editing && p.credentials.includes(name),
  );

  function toggleProfile(p: string, on: boolean) {
    setProfiles((cur) => (on ? [...cur, p] : cur.filter((x) => x !== p)));
  }

  function buildChange(): CredentialConfigChange {
    const change: CredentialConfigChange = { name: credName.trim() };
    const sameProfiles =
      profiles.length === initialProfiles.length &&
      profiles.every((p) => initialProfiles.includes(p));
    if (!editing || !sameProfiles) change.profiles = profiles;
    if (!editing) change.type = type;
    if (settingsEditable) {
      if (hasHeader && (!editing || header !== (current?.header ?? "")))
        change.header = header.trim();
      if (hasHeader && (!editing || prefix !== (current?.prefix ?? ""))) change.prefix = prefix;
      if (endpoint && (!editing || endpoint !== (current?.endpoint ?? ""))) {
        change.endpoint = endpoint;
      }
    }
    return change;
  }

  async function save() {
    setSaving(true);
    setErr(null);
    try {
      const change = buildChange();
      const result = editing ? await editCredential(change) : await declareCredential(change);
      onSaved(change.name, result.secret_cleared);
      onClose();
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    if (!name) return;
    if (
      !confirm(
        `Remove the credential ${name}?\n\nIts block and its entries in every profile are deleted from the config, and its stored secret is cleared. Agents on those profiles lose access through it at once.`,
      )
    ) {
      return;
    }
    setSaving(true);
    setErr(null);
    try {
      await removeCredential(name);
      onSaved(name, false);
      onClose();
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setSaving(false);
    }
  }

  const title = editing ? `Edit credential ${name}` : "Add credential";
  if (opts && editing && !current) {
    return (
      <Modal size="md" title={title} onClose={onClose}>
        <div className="p-5 text-sm text-text-muted">
          The gateway's config has no credential named <span className="font-mono">{name}</span>{" "}
          that the form can read. Reload the page; if it persists, change it in the config files.
        </div>
      </Modal>
    );
  }
  if (!opts) {
    return (
      <Modal size="md" title={title} onClose={onClose}>
        <div className="p-5 text-xs text-text-muted">
          {loadErr ? <span className="text-danger-500">{loadErr}</span> : "Loading…"}
        </div>
      </Modal>
    );
  }
  if (!opts.writes) {
    return (
      <Modal size="md" title={title} onClose={onClose}>
        <div className="p-5 text-sm text-text-muted">
          The dashboard cannot change the config: set <code>dashboard_config_writes = true</code> in
          the gateway block to manage credentials here.
        </div>
      </Modal>
    );
  }

  return (
    <Modal size="md" title={title} onClose={saving ? () => {} : onClose}>
      <div className="flex flex-col gap-3 p-5">
        {!editing && (
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1">
              <span className={LABEL_CLASS}>Type</span>
              <select
                value={type}
                onChange={(e) => {
                  setType(e.target.value);
                  setEndpoint("");
                }}
                className={INPUT_CLASS + " bg-canvas"}
              >
                {opts.types.map((t) => (
                  <option key={t.type} value={t.type}>
                    {credentialTypeLabel(t.type, t.type)}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className={LABEL_CLASS}>Name</span>
              <input
                autoFocus
                value={credName}
                onChange={(e) => setCredName(e.target.value)}
                placeholder="gitlab-pat"
                className={INPUT_CLASS + " font-mono"}
              />
            </label>
          </div>
        )}

        {editing && current && (
          <dl className="grid grid-cols-[auto,minmax(0,1fr)] gap-x-3 gap-y-1 rounded border border-canvas-300 bg-canvas-muted px-3 py-2 text-xs">
            <dt className="text-text-muted font-bold font-sans">Type</dt>
            <dd className="min-w-0 truncate text-text">
              {credentialTypeLabel(current.type, current.type)}{" "}
              <span className="font-mono text-text-muted">({current.type})</span>
            </dd>
            <dt className="text-text-muted font-bold font-sans">Declared in</dt>
            <dd className="min-w-0 truncate font-mono text-text">{current.file || "—"}</dd>
          </dl>
        )}
        {editing && !typeOpt && (
          <p className="text-xs text-text-muted border-l-2 border-rust-400 pl-3">
            The form does not edit the settings of this credential type. Change them in{" "}
            <span className="font-mono">{current?.file}</span>; the profiles below can change here.
          </p>
        )}
        {editing && typeOpt && current?.read_only && (
          <p className="text-xs text-text-muted border-l-2 border-rust-400 pl-3">
            <span className="font-mono">{current.file}</span> is generated from a template, so its
            settings and endpoint change there. The profiles below can change here.
          </p>
        )}

        {typeOpt && hasHeader && (
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1">
              <span className={LABEL_CLASS}>Header</span>
              <input
                value={header}
                disabled={!settingsEditable}
                onChange={(e) => setHeader(e.target.value)}
                placeholder="Authorization"
                className={INPUT_CLASS + " font-mono disabled:opacity-60"}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className={LABEL_CLASS}>Prefix (optional)</span>
              <input
                value={prefix}
                disabled={!settingsEditable}
                onChange={(e) => setPrefix(e.target.value)}
                placeholder="Bearer "
                className={INPUT_CLASS + " font-mono disabled:opacity-60"}
              />
            </label>
          </div>
        )}

        {typeOpt && (
          <label className="flex flex-col gap-1">
            <span className={LABEL_CLASS}>Endpoint</span>
            <select
              value={endpoint}
              disabled={!settingsEditable}
              onChange={(e) => setEndpoint(e.target.value)}
              className={INPUT_CLASS + " bg-canvas disabled:opacity-60"}
            >
              <option value="">Pick an endpoint…</option>
              {endpoints.map((e) => (
                <option key={e.name} value={e.name}>
                  {e.name}
                  {e.hosts ? ` — ${e.hosts.replace(/[[\]"]/g, "")}` : ""}
                </option>
              ))}
            </select>
            <span className="text-2xs text-text-subtle">
              A host with no endpoint is added from the log: open a request to it and create a rule
              from it.
            </span>
            {editing && endpoint && endpoint !== (current?.endpoint ?? "") && (
              <span className="text-2xs text-text-subtle">
                Moving it to another endpoint clears its stored secret, so the old token never
                reaches the new host: paste the new one after saving.
              </span>
            )}
          </label>
        )}

        <fieldset className="flex flex-col gap-1">
          <legend className={LABEL_CLASS + " mb-1"}>Profiles</legend>
          {opts.profiles.length === 0 && (
            <span className="text-xs text-text-subtle">No profiles declared.</span>
          )}
          {opts.profiles.map((p) => (
            <label
              key={p.name}
              className={
                "flex items-center gap-2 text-xs " +
                (p.read_only ? "text-text-subtle" : "text-text cursor-pointer")
              }
              title={p.read_only ? `${p.file} is generated: change this profile there` : p.file}
            >
              <input
                type="checkbox"
                checked={profiles.includes(p.name)}
                disabled={p.read_only || saving}
                onChange={(e) => toggleProfile(p.name, e.target.checked)}
                className="accent-rust-400 disabled:opacity-50"
              />
              <span className="font-mono">{p.name}</span>
              {p.read_only && <span className="text-2xs">(read-only, {p.file})</span>}
            </label>
          ))}
          <span className="text-2xs text-text-subtle">
            A profile takes one credential per endpoint. In the profiles you pick, this credential
            replaces the passthrough credential the host was added with.
          </span>
          {opts.profiles.some((p) => p.read_only) && (
            <span className="text-2xs text-text-subtle">
              Read-only profiles are declared in a file the dashboard does not change. To give one
              this credential, add it to the profile's credentials list in that file.
            </span>
          )}
        </fieldset>

        {err && (
          <div className="text-xs text-danger-500 whitespace-pre-wrap break-words">{err}</div>
        )}
      </div>
      <div className="flex items-center gap-2 px-4 py-3">
        {editing && settingsEditable && (
          <Button
            variant="outline"
            onClick={remove}
            disabled={saving || lockedProfiles.length > 0}
            title={
              lockedProfiles.length > 0
                ? `Listed by ${lockedProfiles.map((p) => `${p.name} (${p.file})`).join(", ")}, which the dashboard cannot change`
                : undefined
            }
          >
            Remove
          </Button>
        )}
        <span className="ml-auto" />
        <Button variant="outline" onClick={onClose} disabled={saving}>
          Cancel
        </Button>
        <Button onClick={save} disabled={saving}>
          {saving ? "Saving…" : editing ? "Save" : "Add"}
        </Button>
      </div>
    </Modal>
  );
}
