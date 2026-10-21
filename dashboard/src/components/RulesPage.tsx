import { useEffect, useState, type ReactNode } from "react";
import { deleteMyRule, getMyRules, setMyRuleDisabled, type MyRule } from "../lib/api";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// RulesPage lists the rules in the viewer's own rules file — for a
// member, the ones they created from their requests — and lets them
// disable, re-enable or delete each one.
export function RulesPage() {
  const [file, setFile] = useState("");
  const [rules, setRules] = useState<MyRule[]>([]);
  const [unavailable, setUnavailable] = useState("");
  const [err, setErr] = useState("");

  async function refresh() {
    try {
      const r = await getMyRules();
      setFile(r.file);
      setRules(r.rules);
      setUnavailable(r.unavailable ?? "");
      setErr("");
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function run(action: () => Promise<unknown>) {
    try {
      await action();
      await refresh();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  return (
    <Main>
      <PageTitle trail={[{ label: "Rules" }]} />
      <p className="text-xs text-text-muted">
        {file ? (
          <>
            Rules created from the dashboard, kept in <code>{file}</code>. Create one from any
            request on the{" "}
            <a href="#/requests" className="underline">
              Requests
            </a>{" "}
            page.
          </>
        ) : (
          unavailable
        )}
      </p>
      {err && <div className="text-xs text-danger-500">{err}</div>}
      <section className="bg-canvas border-1.5 border-navy overflow-x-auto">
        <table className="w-full border-collapse text-xs">
          <thead className="bg-navy-100 border-b border-navy">
            <tr>
              <Th>Rule</Th>
              <Th>Endpoint</Th>
              <Th>Matches</Th>
              <Th>Outcome</Th>
              <Th>Actions</Th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr
                key={r.name}
                className={
                  "border-b border-canvas-muted last:border-b-0 " +
                  (r.disabled ? "text-text-subtle" : "")
                }
              >
                <Td>
                  <span className="font-mono font-bold">{r.name}</span>
                  {r.disabled && <span className="ml-2 text-text-muted">(disabled)</span>}
                </Td>
                <Td>
                  <span className="font-mono">{r.endpoints.join(", ")}</span>
                </Td>
                <Td>
                  <code className="whitespace-pre-wrap break-all">
                    {r.condition || "every request"}
                  </code>
                  {r.profile && <div className="text-text-muted mt-0.5">profile {r.profile}</div>}
                </Td>
                <Td>{outcome(r)}</Td>
                <Td>
                  <div className="flex gap-2">
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => run(() => setMyRuleDisabled(r.name, !r.disabled))}
                    >
                      {r.disabled ? "Enable" : "Disable"}
                    </Button>
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => {
                        if (window.confirm(`Delete rule ${r.name}?`)) {
                          run(() => deleteMyRule(r.name));
                        }
                      }}
                    >
                      Delete
                    </Button>
                  </div>
                </Td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <Td>
                  <span className="text-text-muted">No rules yet.</span>
                </Td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </Main>
  );
}

function outcome(r: MyRule): string {
  if (r.approve?.length) return "Require approval (" + r.approve.join(", ") + ")";
  if (r.verdict === "allow") return "Pre-approve";
  if (r.verdict === "deny") return "Deny";
  return r.verdict ?? "—";
}

function Th({ children }: { children: ReactNode }) {
  return (
    <th className="text-left px-4 py-2 font-mono uppercase tracking-wider text-navy font-bold">
      {children}
    </th>
  );
}

function Td({ children }: { children: ReactNode }) {
  return <td className="px-4 py-2 align-top">{children}</td>;
}
