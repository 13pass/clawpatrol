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
  const [err, setErr] = useState("");

  async function refresh() {
    try {
      setUsers(await listUsers());
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
        <CreateUserForm onCreated={refresh} />
      </Section>
      <Section title="Users">
        {err && <div className="text-xs text-danger-500 px-4 py-2">{err}</div>}
        <UsersTable users={users} self={whoami?.user ?? ""} onChanged={refresh} />
      </Section>
      <Section title="Audit log">
        <AuditLog />
      </Section>
    </Main>
  );
}

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

function CreateUserForm({ onCreated }: { onCreated: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<DashboardRole>("member");
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await createUser(username, password, role);
      setUsername("");
      setPassword("");
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
      <Field label="Initial password">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
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
  self,
  onChanged,
}: {
  users: DashboardUser[];
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
            <Th>Created</Th>
            <Th>Actions</Th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <UserRow key={u.username} user={u} isSelf={u.username === self} onChanged={onChanged} />
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
  isSelf,
  onChanged,
}: {
  user: DashboardUser;
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
