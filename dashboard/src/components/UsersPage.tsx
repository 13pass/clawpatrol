import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  createUser,
  deleteUser,
  getAudit,
  listUsers,
  updateUser,
  type AuditRecord,
  type DashboardRole,
  type DashboardUser,
  type Whoami,
} from "../lib/api";
import { fmtDateTime } from "../lib/format";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// Mirrors dashboardMinPasswordLen and dashboardUsernameRe on the server;
// the server re-checks both.
const MIN_PASSWORD_LEN = 12;
const USERNAME_PATTERN = "[a-z][a-z0-9\\-]{1,31}";
const ROOT_USERNAME = "root";
const AUDIT_PAGE_SIZE = 100;
const NS_PER_MS = 1e6;

const INPUT_CLASS =
  "border border-canvas-dark rounded px-2 py-1.5 text-xs focus:outline-none focus:border-text";

// UsersPage is the admin-only account management screen: create
// dashboard users, change their role, reset their password, delete
// them, and read the dashboard audit log.
export function UsersPage({ whoami }: { whoami: Whoami | null }) {
  const [users, setUsers] = useState<DashboardUser[]>([]);
  const [declared, setDeclared] = useState<Declared>({
    profiles: [],
    approvers: [],
    oidcProviders: [],
  });
  const [err, setErr] = useState("");

  async function refresh() {
    try {
      const list = await listUsers();
      setUsers(list.users);
      setDeclared({
        profiles: list.profiles,
        approvers: list.human_approvers,
        oidcProviders: list.oidc.map((p) => ({ name: p.name, displayName: p.display_name })),
      });
      setErr("");
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <Main>
      <PageTitle trail={[{ label: "Users" }]} />
      <Section title="Add a user">
        <CreateUserForm onCreated={refresh} oidcProviders={declared.oidcProviders} />
      </Section>
      <Section title="Users">
        {err && <div className="text-xs text-danger-500 px-4 py-2">{err}</div>}
        <UsersTable
          users={users}
          declared={declared}
          self={whoami?.user ?? ""}
          onChanged={refresh}
        />
      </Section>
      <Section title="Audit log">
        <AuditLog />
      </Section>
    </Main>
  );
}

// Declared is what the config offers for assignment, and the sign-in
// providers (gateway.dashboard_oidc blocks).
type OIDCProvider = { name: string; displayName: string };
type Declared = { profiles: string[]; approvers: string[]; oidcProviders: OIDCProvider[] };

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <h2 className="px-4 py-2 bg-navy-100 border-b border-navy font-mono text-xs uppercase tracking-wider font-bold text-navy">
        {title}
      </h2>
      {children}
    </section>
  );
}

function CreateUserForm({
  onCreated,
  oidcProviders,
}: {
  onCreated: () => void;
  oidcProviders: OIDCProvider[];
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [links, setLinks] = useState<Record<string, string>>({});
  const linked = Object.values(links).some((a) => a.trim() !== "");
  const [role, setRole] = useState<DashboardRole>("member");
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await createUser(username, password, role, links);
      setUsername("");
      setPassword("");
      setLinks({});
      setRole("member");
      setErr("");
      onCreated();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={submit} className="p-4 flex flex-wrap items-end gap-3">
      <Field label="Username">
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          pattern={USERNAME_PATTERN}
          title="Lowercase letters, digits and dashes; starts with a letter"
          autoComplete="off"
          className={INPUT_CLASS}
        />
      </Field>
      {oidcProviders.map((p) => (
        <Field key={p.name} label={`${p.displayName} account`}>
          <input
            value={links[p.name] ?? ""}
            onChange={(e) => setLinks({ ...links, [p.name]: e.target.value })}
            placeholder="username or email"
            autoComplete="off"
            className={INPUT_CLASS}
          />
        </Field>
      ))}
      <Field label={linked ? "Password (optional)" : "Initial password"}>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required={!linked}
          minLength={MIN_PASSWORD_LEN}
          autoComplete="new-password"
          className={INPUT_CLASS}
        />
      </Field>
      <Field label="Role">
        <RoleSelect value={role} onChange={setRole} />
      </Field>
      <Button type="submit" disabled={saving}>
        {saving ? "Adding…" : "Add user"}
      </Button>
      {err && <div className="basis-full text-xs text-danger-500">{err}</div>}
    </form>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono text-xs uppercase tracking-wider text-text-muted">{label}</span>
      {children}
    </label>
  );
}

function RoleSelect({
  value,
  onChange,
  disabled,
}: {
  value: DashboardRole;
  onChange: (role: DashboardRole) => void;
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as DashboardRole)}
      disabled={disabled}
      className={INPUT_CLASS + " bg-canvas disabled:text-text-subtle"}
    >
      <option value="member">member</option>
      <option value="admin">admin</option>
    </select>
  );
}

function UsersTable({
  users,
  declared,
  self,
  onChanged,
}: {
  users: DashboardUser[];
  declared: Declared;
  self: string;
  onChanged: () => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-xs">
        <thead className="border-b border-navy">
          <tr>
            <Th>Username</Th>
            <Th>Role</Th>
            <Th>Profiles</Th>
            <Th>Reviewer</Th>
            <Th>Sign-in</Th>
            <Th>Created</Th>
            <Th>Actions</Th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <UserRow
              key={u.username}
              user={u}
              declared={declared}
              isSelf={u.username === self}
              onChanged={onChanged}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Th({ children }: { children: ReactNode }) {
  return (
    <th className="text-left px-4 py-2 font-mono uppercase tracking-wider text-text-muted font-semibold">
      {children}
    </th>
  );
}

function Td({ children }: { children: ReactNode }) {
  return <td className="px-4 py-2 align-middle">{children}</td>;
}

function UserRow({
  user,
  declared,
  isSelf,
  onChanged,
}: {
  user: DashboardUser;
  declared: Declared;
  isSelf: boolean;
  onChanged: () => void;
}) {
  const [resetting, setResetting] = useState(false);
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const isRoot = user.username === ROOT_USERNAME;

  async function run(action: () => Promise<void>) {
    try {
      await action();
      setErr("");
      onChanged();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  return (
    <tr className="border-b border-canvas-muted last:border-b-0">
      <Td>
        <span className="font-bold">{user.username}</span>
        {isSelf && <span className="text-text-muted"> (you)</span>}
      </Td>
      <Td>
        <RoleSelect
          value={user.role}
          disabled={isRoot || isSelf}
          onChange={(role) => run(() => updateUser(user.username, { role }))}
        />
      </Td>
      <Td>
        {user.role === "admin" ? (
          <span className="text-text-muted">all</span>
        ) : (
          <ProfileChecklist
            username={user.username}
            declared={declared.profiles}
            owned={user.profiles}
            onChange={(profiles) => run(() => updateUser(user.username, { profiles }))}
          />
        )}
      </Td>
      <Td>
        {user.role === "admin" ? (
          <span className="text-text-muted">—</span>
        ) : (
          <select
            value={user.approver}
            onChange={(e) => run(() => updateUser(user.username, { approver: e.target.value }))}
            aria-label={`Reviewer for ${user.username}`}
            className={INPUT_CLASS + " bg-canvas"}
          >
            <option value="">the dashboard</option>
            {declared.approvers.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        )}
      </Td>
      <Td>
        <SignInCell user={user} providers={declared.oidcProviders} onChanged={onChanged} />
      </Td>
      <Td>
        <span className="font-mono">{fmtDateTime(user.created_ns / NS_PER_MS)}</span>
      </Td>
      <Td>
        <div className="flex flex-wrap items-center gap-2">
          {resetting ? (
            <form
              className="flex items-center gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                run(async () => {
                  await updateUser(user.username, { password });
                  setPassword("");
                  setResetting(false);
                });
              }}
            >
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={MIN_PASSWORD_LEN}
                autoComplete="new-password"
                placeholder="New password"
                aria-label={`New password for ${user.username}`}
                className={INPUT_CLASS}
              />
              <Button type="submit" size="xs">
                Save
              </Button>
              <Button type="button" size="xs" variant="outline" onClick={() => setResetting(false)}>
                Cancel
              </Button>
            </form>
          ) : (
            <Button
              size="xs"
              variant="outline"
              disabled={user.role === "admin"}
              title={
                user.role === "admin"
                  ? "Admins change their own password on the Account page"
                  : undefined
              }
              onClick={() => setResetting(true)}
            >
              Reset password
            </Button>
          )}
          <Button
            size="xs"
            variant="outline"
            disabled={isRoot || isSelf}
            title={isRoot ? "root cannot be deleted" : isSelf ? "you cannot delete yourself" : ""}
            onClick={() => {
              if (window.confirm(`Delete ${user.username}? Their sessions end immediately.`)) {
                run(() => deleteUser(user.username));
              }
            }}
          >
            Delete
          </Button>
        </div>
        {err && <div className="text-xs text-danger-500 mt-1">{err}</div>}
      </Td>
    </tr>
  );
}

// SignInCell shows how a user signs in, and lets an admin link or
// unlink their account at each sign-in provider. A link at a provider
// the config no longer declares stays listed so it can be removed.
function SignInCell({
  user,
  providers,
  onChanged,
}: {
  user: DashboardUser;
  providers: OIDCProvider[];
  onChanged: () => void;
}) {
  return (
    <div className="space-y-1">
      {user.has_password && <div className="text-text-muted">password</div>}
      {providers.map((p) => (
        <ProviderLink
          key={p.name}
          user={user}
          provider={p}
          link={user.oidc.find((l) => l.provider === p.name)}
          onChanged={onChanged}
        />
      ))}
      {user.oidc
        .filter((l) => !providers.some((p) => p.name === l.provider))
        .map((l) => (
          <ProviderLink
            key={l.provider}
            user={user}
            provider={{ name: l.provider, displayName: l.provider }}
            link={l}
            removed
            onChanged={onChanged}
          />
        ))}
    </div>
  );
}

function ProviderLink({
  user,
  provider,
  link,
  removed = false,
  onChanged,
}: {
  user: DashboardUser;
  provider: OIDCProvider;
  link?: { account: string; linked: boolean };
  // removed: the provider is no longer configured; the link can only
  // be unlinked.
  removed?: boolean;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(link?.account ?? "");
  const [err, setErr] = useState("");
  async function apply(change: Parameters<typeof updateUser>[1]) {
    try {
      await updateUser(user.username, change);
      setEditing(false);
      setErr("");
      onChanged();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }
  const save = () => apply({ oidc: { [provider.name]: value } });
  return (
    <div>
      <span className="text-text-muted">{provider.displayName}:</span>{" "}
      {link ? (
        <>
          <span className="font-mono">{link.account}</span>{" "}
          <span className="text-text-muted">
            ({removed ? "provider removed" : link.linked ? "linked" : "waiting for first sign-in"})
          </span>
        </>
      ) : (
        <span className="text-text-subtle">—</span>
      )}{" "}
      {editing ? (
        <form
          className="flex items-center gap-2 mt-1"
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
        >
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="account, empty to unlink"
            aria-label={`${provider.displayName} account for ${user.username}`}
            className={INPUT_CLASS}
          />
          <Button type="submit" size="xs">
            Save
          </Button>
          <Button type="button" size="xs" variant="outline" onClick={() => setEditing(false)}>
            Cancel
          </Button>
        </form>
      ) : removed ? (
        <Button
          size="xs"
          variant="outline"
          onClick={() => {
            if (window.confirm(`Unlink ${user.username}'s ${provider.name} account?`)) {
              apply({ oidc: { [provider.name]: "" } });
            }
          }}
        >
          Unlink
        </Button>
      ) : (
        <>
          <Button
            size="xs"
            variant="outline"
            onClick={() => {
              setValue(link?.account ?? "");
              setEditing(true);
            }}
          >
            {link ? "Change" : "Link"}
          </Button>
          {link?.linked && (
            <Button
              size="xs"
              variant="outline"
              title="For an account deleted and recreated at the provider: the next sign-in as this account binds afresh"
              onClick={() => {
                if (
                  window.confirm(
                    `Reset ${user.username}'s ${provider.displayName} binding? Their sessions end, and the next sign-in as ${link.account} is bound to them.`,
                  )
                ) {
                  apply({ oidc_rebind: [provider.name] });
                }
              }}
            >
              Reset binding
            </Button>
          )}
        </>
      )}
      {err && <div className="text-xs text-danger-500">{err}</div>}
    </div>
  );
}

// ProfileChecklist assigns the profiles a member owns. A profile the
// config no longer declares stays listed so it can be removed.
function ProfileChecklist({
  username,
  declared,
  owned,
  onChange,
}: {
  username: string;
  declared: string[];
  owned: string[];
  onChange: (profiles: string[]) => void;
}) {
  // Ticks are tracked here, not read back from `owned`, which only
  // refreshes after the update round-trip: two quick ticks must each
  // send the full current list.
  const [checked, setChecked] = useState(owned);
  useEffect(() => setChecked(owned), [owned]);
  const toggle = (p: string, on: boolean) => {
    const next = on ? [...checked, p] : checked.filter((x) => x !== p);
    setChecked(next);
    onChange(next);
  };
  const all = [...new Set([...declared, ...owned])].sort();
  if (all.length === 0) return <span className="text-text-muted">none declared</span>;
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-1">
      {all.map((p) => (
        <label key={p} className="flex items-center gap-1 font-mono">
          <input
            type="checkbox"
            checked={checked.includes(p)}
            aria-label={`${username} owns profile ${p}`}
            onChange={(e) => toggle(p, e.target.checked)}
          />
          <span className={declared.includes(p) ? "" : "line-through text-text-muted"}>{p}</span>
        </label>
      ))}
    </div>
  );
}

function AuditLog() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [more, setMore] = useState(false);
  const [err, setErr] = useState("");

  async function load(before?: number) {
    try {
      const page = await getAudit(before, AUDIT_PAGE_SIZE);
      setRecords((prev) => (before ? [...prev, ...page] : page));
      setMore(page.length === AUDIT_PAGE_SIZE);
      setErr("");
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="overflow-x-auto">
      {err && <div className="text-xs text-danger-500 px-4 py-2">{err}</div>}
      <table className="w-full border-collapse text-xs">
        <thead className="border-b border-navy">
          <tr>
            <Th>Time</Th>
            <Th>User</Th>
            <Th>Action</Th>
            <Th>Target</Th>
            <Th>Status</Th>
          </tr>
        </thead>
        <tbody className="font-mono">
          {records.map((r) => (
            <tr key={r.id} className="border-b border-canvas-muted last:border-b-0">
              <Td>{fmtDateTime(r.ts_ns / NS_PER_MS)}</Td>
              <Td>{r.username || "—"}</Td>
              <Td>
                {r.method} {r.path}
              </Td>
              <Td>{r.target || "—"}</Td>
              <Td>{r.status}</Td>
            </tr>
          ))}
          {records.length === 0 && !err && (
            <tr>
              <Td>
                <span className="text-text-muted font-sans">
                  No dashboard activity recorded yet.
                </span>
              </Td>
            </tr>
          )}
        </tbody>
      </table>
      {more && (
        <div className="px-4 py-2">
          <Button size="xs" variant="outline" onClick={() => load(records[records.length - 1]?.id)}>
            Load older
          </Button>
        </div>
      )}
    </div>
  );
}
