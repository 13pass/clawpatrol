// Settings page. Credentials declared in the config render at the
// top; the viewer below shows the running config in read-only mode —
// one file at a time when the config is a directory. Operators push
// HCL edits from a separate repo.

import { useEffect, useState } from "react";
import { getConfigFiles, getConfigHCL, type Integration } from "../lib/api";
import { CredentialsTypeGrid } from "./CredentialsTypeGrid";
import { HCLEditor } from "./HCLEditor";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

export function SettingsPage({
  isAdmin,
  integrations,
  onConnect,
  onRefresh,
}: {
  isAdmin: boolean;
  integrations: Integration[];
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  return (
    <Main>
      <PageTitle trail={[{ label: "Settings" }]} />

      <section className="space-y-3">
        <h2 className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
          Credentials
        </h2>
        {integrations.length === 0 ? (
          <div className="bg-canvas border-1.5 border-navy px-4 py-6 text-xs text-text-subtle">
            No credentials declared in gateway.hcl yet. Add a credential block to connect Anthropic
            / GitHub / Notion / Postgres / etc. here.
          </div>
        ) : (
          <CredentialsTypeGrid list={integrations} onConnect={onConnect} onRefresh={onRefresh} />
        )}
      </section>

      {isAdmin && <ConfigSection />}
    </Main>
  );
}

function ConfigSection() {
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [files, setFiles] = useState<string[]>([]);
  const [isDirectory, setIsDirectory] = useState(false);
  const [selected, setSelected] = useState("");

  useEffect(() => {
    getConfigFiles()
      .then((c) => {
        setIsDirectory(c.directory);
        setFiles(c.files.map((f) => f.name));
        setSelected(c.files[0]?.name ?? "");
      })
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }, []);

  useEffect(() => {
    if (!selected) return;
    getConfigHCL(isDirectory ? selected : undefined)
      .then((t) => {
        setText(t);
        setErr(null);
      })
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }, [selected, isDirectory]);

  return (
    <section className="space-y-3">
      <div className="bg-canvas border-1.5 border-navy overflow-hidden">
        <div className="flex items-center px-4 py-3 bg-navy-100 border-b border-navy">
          <h2 className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
            Configuration · {selected || "gateway.hcl"}
            <span className="ml-2 normal-case tracking-normal font-normal text-navy/70">
              · read-only (push edits via your config repo)
            </span>
          </h2>
          {isDirectory && files.length > 1 && (
            <select
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              aria-label="Config file"
              className="ml-auto border border-canvas-dark rounded px-2 py-1 text-xs font-mono bg-canvas focus:outline-none focus:border-text"
            >
              {files.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="overflow-auto">
          <HCLEditor value={text} onChange={() => {}} minHeight={420} readOnly />
        </div>
        {err && (
          <div className="flex items-center gap-2 px-4 py-3 border-t border-navy">
            <div className="text-xs text-danger-500 truncate">{err}</div>
          </div>
        )}
      </div>
    </section>
  );
}
