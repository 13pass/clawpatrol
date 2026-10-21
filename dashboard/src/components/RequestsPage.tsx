import { useEffect, useState, type ReactNode } from "react";
import { getMyActions, type MyActionRow } from "../lib/api";
import { fmtDateTime, statusColorClass } from "../lib/format";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

const NS_PER_MS = 1e6;
const PAGE_SIZE = 200;

// RequestsPage lists the requests the viewer may see, newest first: a
// member's are those of their own profiles. Opening one leads to the
// request page, where it can be turned into a rule.
export function RequestsPage({ isMember }: { isMember: boolean }) {
  const [rows, setRows] = useState<MyActionRow[]>([]);
  const [more, setMore] = useState(false);
  const [err, setErr] = useState("");

  async function load(before?: number) {
    try {
      const page = await getMyActions(before);
      setRows((prev) => (before ? [...prev, ...page] : page));
      setMore(page.length === PAGE_SIZE);
      setErr("");
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <Main>
      <PageTitle trail={[{ label: isMember ? "My requests" : "Requests" }]} />
      <section className="bg-canvas border-1.5 border-navy overflow-x-auto">
        {err && <div className="text-xs text-danger-500 px-4 py-2">{err}</div>}
        <table className="w-full border-collapse text-xs">
          <thead className="bg-navy-100 border-b border-navy">
            <tr>
              <Th>Time</Th>
              <Th>Profile</Th>
              <Th>Request</Th>
              <Th>Status</Th>
              <Th>Outcome</Th>
              <Th>Rule</Th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.map((r) => (
              <tr
                key={r.cursor}
                className="border-b border-canvas-muted last:border-b-0 hover:bg-canvas-muted cursor-pointer"
                onClick={() => (window.location.hash = "#/request/" + encodeURIComponent(r.id))}
              >
                <Td>{fmtDateTime(r.ts_ns / NS_PER_MS)}</Td>
                <Td>{r.profile || "—"}</Td>
                <Td>
                  <a href={"#/request/" + encodeURIComponent(r.id)} className="hover:underline">
                    {r.method} {r.host}
                    {r.path}
                  </a>
                </Td>
                <Td>
                  <span className={statusColorClass(r.status ?? "")}>{r.status || "—"}</span>
                </Td>
                <Td>{r.action || "—"}</Td>
                <Td>{r.rule || "—"}</Td>
              </tr>
            ))}
            {rows.length === 0 && !err && (
              <tr>
                <Td>
                  <span className="font-sans text-text-muted">
                    {isMember
                      ? "No requests from your profiles yet. An admin assigns profiles on the Users page."
                      : "No requests recorded yet."}
                  </span>
                </Td>
              </tr>
            )}
          </tbody>
        </table>
        {more && (
          <div className="px-4 py-2">
            <Button size="xs" variant="outline" onClick={() => load(rows[rows.length - 1]?.cursor)}>
              Load older
            </Button>
          </div>
        )}
      </section>
    </Main>
  );
}

function Th({ children }: { children: ReactNode }) {
  return (
    <th className="text-left px-4 py-2 font-mono uppercase tracking-wider text-navy font-bold">
      {children}
    </th>
  );
}

function Td({ children }: { children: ReactNode }) {
  return <td className="px-4 py-2 align-middle whitespace-nowrap">{children}</td>;
}
