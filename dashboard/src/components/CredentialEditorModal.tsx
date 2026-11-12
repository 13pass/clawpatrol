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

// NEW_ENDPOINT is the endpoint picker's "declare a new host" choice.
const NEW_ENDPOINT = "__new__";

// endpointNameFromHost suggests an endpoint name: the host's first
// label that is not "www", "api" or "*".
function endpointNameFromHost(raw: string): string {
  const host = raw
    .trim()
    .replace(/^[a-z]+:\/\//i, "")
    .split(/[/:]/)[0]
    .toLowerCase();
  const label = host.split(".").find((l) => l && !["www", "api", "*"].includes(l)) ?? "";
  const name = label.replace(/[^a-z0-9_-]/g, "-");
  return /^[a-z]/.test(name) ? name : "";
}

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
  onSaved: (name: string, declared: boolean) => void;
}) {
  const editing = name !== undefined;
  const [opts, setOpts] = useState<CredentialConfigOptions | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [type, setType] = useState("header_token");
  const [credName, setCredName] = useState(name ?? "");
  const [header, setHeader] = useState("");
  const [prefix, setPrefix] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [newHost, setNewHost] = useState("");
  const [newEndpointName, setNewEndpointName] = useState("");
  const [endpointNameTouched, setEndpointNameTouched] = useState(false);
  const [profiles, setProfiles] = useState<string[]>([]);
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
          setProfiles(o.profiles.filter((p) => p.credentials.includes(name)).map((p) => p.name));
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
  const canAddHost = typeOpt?.families.includes("http") ?? false;

  function toggleProfile(p: string, on: boolean) {
    setProfiles((cur) => (on ? [...cur, p] : cur.filter((x) => x !== p)));
  }

  function buildChange(): CredentialConfigChange {
    const change: CredentialConfigChange = { name: credName.trim(), profiles };
    if (!editing) change.type = type;
    if (settingsEditable) {
      if (hasHeader && (!editing || header !== (current?.header ?? "")))
        change.header = header.trim();
      if (hasHeader && (!editing || prefix !== (current?.prefix ?? ""))) change.prefix = prefix;
      if (endpoint === NEW_ENDPOINT) {
        change.new_endpoint = { name: newEndpointName.trim(), host: newHost.trim() };
      } else if (endpoint && (!editing || endpoint !== (current?.endpoint ?? ""))) {
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
      if (editing) await editCredential(change);
      else await declareCredential(change);
      onSaved(change.name, !editing);
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
              {canAddHost && <option value={NEW_ENDPOINT}>New host…</option>}
            </select>
          </label>
        )}

        {endpoint === NEW_ENDPOINT && (
          <div className="flex flex-col gap-1">
            <div className="grid grid-cols-[minmax(0,2fr),minmax(0,1fr)] gap-3">
              <label className="flex flex-col gap-1">
                <span className={LABEL_CLASS}>Host or URL</span>
                <input
                  value={newHost}
                  onChange={(e) => {
                    setNewHost(e.target.value);
                    if (!endpointNameTouched)
                      setNewEndpointName(endpointNameFromHost(e.target.value));
                  }}
                  placeholder="https://git.example.org"
                  className={INPUT_CLASS + " font-mono"}
                />
              </label>
              <label className="flex flex-col gap-1">
                <span className={LABEL_CLASS}>Endpoint name</span>
                <input
                  value={newEndpointName}
                  onChange={(e) => {
                    setEndpointNameTouched(true);
                    setNewEndpointName(e.target.value);
                  }}
                  className={INPUT_CLASS + " font-mono"}
                />
              </label>
            </div>
            <span className="text-2xs text-text-subtle">
              Declares an https endpoint for this host in{" "}
              <span className="font-mono">{opts.file}</span>. It has no rules yet.
            </span>
          </div>
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
            A profile takes one credential per endpoint: the gateway refuses a second one.
          </span>
        </fieldset>

        {err && (
          <div className="text-xs text-danger-500 whitespace-pre-wrap break-words">{err}</div>
        )}
      </div>
      <div className="flex items-center gap-2 px-4 py-3">
        {editing && settingsEditable && (
          <Button variant="outline" onClick={remove} disabled={saving}>
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
