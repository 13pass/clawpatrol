import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  addEndpointDefaultRules,
  deleteMyRule,
  getCredentialConfigOptions,
  getMyRules,
  getRules,
  setMyRuleDisabled,
  type RuleChange,
  type RuleSummary,
} from "../lib/api";
import { Button } from "./Button";
import { EndpointRuleModal } from "./EndpointRuleModal";
import { Tag, type Tone } from "./Tag";

type Endpoint = { endpoint: string; family: string };

export function RulesPanel({
  profile,
  version,
  isMember,
  onChanged,
}: {
  profile?: string;
  isMember: boolean;
  version?: number;
  onChanged?: () => void;
}) {
  const [rows, setRows] = useState<RuleSummary[]>([]);
  const [myFile, setMyFile] = useState("");
  const [unavailable, setUnavailable] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState("");
  const [defaultRules, setDefaultRules] = useState<string[]>([]);
  // endpoints are those an admin may add a rule to, with or without one.
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [ruleFor, setRuleFor] = useState<Endpoint | null>(null);
  const loads = useRef(0);

  const refresh = useCallback(() => {
    const load = ++loads.current;
    const my = getMyRules().catch((e) => ({
      file: "",
      unavailable: `The rules you can change could not be loaded: ${e instanceof Error ? e.message : e}`,
      default_rules: [],
    }));
    const options = isMember
      ? Promise.resolve(null)
      : getCredentialConfigOptions().catch(() => null);
    return Promise.all([getRules(), my, options])
      .then(([all, my, opts]) => {
        if (load !== loads.current) return;
        setRows(all ?? []);
        setMyFile(my.file);
        setUnavailable(my.unavailable ?? "");
        setDefaultRules(my.default_rules ?? []);
        let eps = opts?.endpoints ?? [];
        if (profile && opts) {
          const listed = opts.profiles.find((p) => p.name === profile)?.credentials ?? [];
          const reached = new Set(listed.map((c) => opts.credentials[c]?.endpoint));
          eps = eps.filter((e) => reached.has(e.name));
        }
        setEndpoints(eps.map((e) => ({ endpoint: e.name, family: e.family })));
        setErr(null);
      })
      .catch((e) => {
        if (load === loads.current) setErr(String(e instanceof Error ? e.message : e));
      });
  }, [profile, isMember]);

  useEffect(() => {
    refresh();
  }, [refresh, version]);

  async function addDefaults(endpoint: string, names: string[]) {
    if (!window.confirm(`Add the rules ${names.join(", ")} to ${endpoint}?`)) return;
    setInfo("");
    setErr(null);
    try {
      const res = await addEndpointDefaultRules(endpoint);
      setInfo(`Added ${(res.default_rules ?? []).join(", ")} to ${endpoint}.`);
      onChanged?.();
      await refresh();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  async function change(r: RuleSummary, kind: RuleChange) {
    let reason: string | undefined;
    if (r.needs_review?.includes(kind)) {
      const answer = window.prompt(
        `An admin reviews this before it applies: ${kind} rule ${r.name}. Why do you need it? (optional)`,
      );
      if (answer === null) return;
      reason = answer;
    } else if (kind === "delete" && !window.confirm(`Delete rule ${r.name}?`)) {
      return;
    }
    setInfo("");
    setErr(null);
    try {
      const res =
        kind === "delete"
          ? await deleteMyRule(r.name, reason)
          : await setMyRuleDisabled(r.name, kind === "disable", reason);
      setInfo(
        res.pending
          ? `Sent to the admins: ${kind} ${r.name}. It applies once one approves it.`
          : "",
      );
      onChanged?.();
      await refresh();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  // Without a profile, a rule shows once per endpoint, not once per
  // profile that reaches it.
  const visible = useMemo(() => {
    if (profile) return rows.filter((r) => r.profile === profile);
    const seen = new Set<string>();
    return rows.filter((r) => {
      const key = `${r.name} ${r.endpoint}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [rows, profile]);

  return (
    <div className="bg-canvas border-1.5 border-navy">
      {err && <div className="px-4 py-3 text-xs text-rust-700">{err}</div>}
      {info && <div className="px-4 py-3 text-xs text-text">{info}</div>}
      {unavailable && <div className="px-4 py-3 text-xs text-text-muted">{unavailable}</div>}
      <Section
        title="Rules"
        rows={visible}
        endpoints={endpoints}
        myFile={myFile}
        isMember={isMember}
        defaultRules={defaultRules}
        onChange={change}
        onAddRule={setRuleFor}
        onAddDefaults={addDefaults}
        allRulesLink={!!profile}
      />
      {ruleFor && (
        <EndpointRuleModal
          endpoint={ruleFor.endpoint}
          family={ruleFor.family}
          onClose={() => setRuleFor(null)}
          onCreated={() => {
            onChanged?.();
            refresh();
          }}
        />
      )}
    </div>
  );
}

function Section({
  title,
  rows,
  endpoints,
  myFile,
  isMember,
  defaultRules,
  onChange,
  onAddRule,
  onAddDefaults,
  allRulesLink,
}: {
  title: string;
  rows: RuleSummary[];
  endpoints: Endpoint[];
  myFile: string;
  isMember: boolean;
  defaultRules: string[];
  onChange: (r: RuleSummary, kind: RuleChange) => void;
  onAddRule: (e: Endpoint) => void;
  onAddDefaults: (endpoint: string, names: string[]) => void;
  allRulesLink: boolean;
}) {
  // Highest priority first: the order rules are tried in.
  const groups = useMemo(() => {
    const m = new Map<string, { endpoint: string; family: string; rules: RuleSummary[] }>();
    for (const e of endpoints) m.set(e.endpoint, { ...e, rules: [] });
    for (const r of rows) {
      const g = m.get(r.endpoint) ?? {
        endpoint: r.endpoint,
        family: r.family,
        rules: [],
      };
      g.rules.push(r);
      m.set(r.endpoint, g);
    }
    for (const g of m.values()) g.rules.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
    return Array.from(m.values()).sort((a, b) => a.endpoint.localeCompare(b.endpoint));
  }, [rows, endpoints]);
  const canAdd = !isMember && !!myFile;

  return (
    <div className="last:border-b-0">
      <div className="flex items-center px-4 py-2.5 bg-navy-100 border-b border-navy">
        <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
          {title}
        </div>
        <span className="ml-2 text-2xs text-navy/70 tabular-nums">
          {rows.length} rule{rows.length === 1 ? "" : "s"}
        </span>
        {allRulesLink && (
          <a href="#/rules" className="ml-auto text-2xs text-navy underline">
            All rules
          </a>
        )}
      </div>
      {myFile && rows.some((r) => r.mine) && (
        <div className="px-4 py-2 text-2xs text-text-muted border-b border-canvas-muted">
          Rules in <code>{myFile}</code> can be disabled or deleted here.
          {isMember
            ? " An admin changes the others."
            : " The others change in the file named next to them."}
        </div>
      )}
      {groups.length === 0 ? (
        <div className="px-5 py-5 text-center text-xs text-text-subtle">no rules configured</div>
      ) : (
        <div className="flex flex-col">
          {groups.map((g) => (
            <EndpointGroup
              key={g.endpoint}
              group={g}
              onChange={onChange}
              missingDefaults={
                canAdd && g.family === "http"
                  ? defaultRules
                      .map((d) => `${g.endpoint}-${d}`)
                      .filter((name) => !g.rules.some((r) => r.name === name))
                  : []
              }
              onAddRule={canAdd ? () => onAddRule(g) : undefined}
              onAddDefaults={onAddDefaults}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function EndpointGroup({
  group,
  onChange,
  missingDefaults,
  onAddRule,
  onAddDefaults,
}: {
  group: { endpoint: string; family: string; rules: RuleSummary[] };
  onChange: (r: RuleSummary, kind: RuleChange) => void;
  missingDefaults: string[];
  onAddRule?: () => void;
  onAddDefaults: (endpoint: string, names: string[]) => void;
}) {
  return (
    <div className="border-b border-canvas-muted last:border-b-0">
      <div className="flex items-center gap-2 px-4 py-2 bg-navy-50">
        <FamilyDot family={group.family} />
        <span className="text-xs font-mono text-text">{group.endpoint}</span>
        <span className="text-2xs text-navy/70">{group.family}</span>
        <span className="ml-auto text-2xs text-navy/70 tabular-nums">
          {group.rules.length} rule{group.rules.length === 1 ? "" : "s"}
        </span>
        {missingDefaults.length > 0 && (
          <Button
            size="xs"
            variant="outline"
            onClick={() => onAddDefaults(group.endpoint, missingDefaults)}
          >
            Add default rules
          </Button>
        )}
        {onAddRule && (
          <Button size="xs" variant="outline" onClick={onAddRule}>
            Add rule
          </Button>
        )}
      </div>
      {group.rules.map((r, i) => (
        <RuleRow key={`${r.name}/${i}`} rule={r} onChange={onChange} />
      ))}
    </div>
  );
}

function RuleRow({
  rule: r,
  onChange,
}: {
  rule: RuleSummary;
  onChange: (r: RuleSummary, kind: RuleChange) => void;
}) {
  return (
    <div
      className={
        "flex items-start gap-3 px-4 py-2 border-t border-canvas-muted hover:bg-canvas-muted " +
        (r.disabled ? "opacity-50" : "")
      }
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <Verdict r={r} />
          {r.disabled && <span className="text-2xs text-text-muted">(disabled)</span>}
          {r.reason && (
            <span className="text-xs text-text-muted truncate" title={r.reason}>
              {r.reason}
            </span>
          )}
        </div>
        <div className="text-xs text-text-muted mt-1 font-mono truncate" title={renderCondition(r)}>
          {renderCondition(r)}
        </div>
        {r.pinned_profile && (
          <div className="text-2xs text-text-muted mt-0.5">profile {r.pinned_profile} only</div>
        )}
        {r.mine && !r.owned && (
          <div className="text-2xs text-text-muted mt-0.5">
            Its profile is no longer yours; an admin can change it.
          </div>
        )}
      </div>
      <div className="flex flex-col items-end gap-0.5 shrink-0">
        <span className="text-xs text-text-subtle truncate max-w-[10rem]" title={r.name}>
          {r.name}
        </span>
        {(r.priority ?? 0) !== 0 && (
          <span className="text-2xs text-text-subtle tabular-nums">
            p{(r.priority ?? 0) > 0 ? "+" : ""}
            {r.priority}
          </span>
        )}
        {r.mine ? (
          <div className="flex gap-1 mt-1">
            <Button
              size="xs"
              variant="outline"
              disabled={!r.owned}
              onClick={() => onChange(r, r.disabled ? "enable" : "disable")}
            >
              {r.disabled ? "Enable" : "Disable"}
            </Button>
            <Button
              size="xs"
              variant="outline"
              disabled={!r.owned}
              onClick={() => onChange(r, "delete")}
            >
              Delete
            </Button>
          </div>
        ) : (
          r.file && <span className="text-2xs text-text-subtle font-mono">in {r.file}</span>
        )}
      </div>
    </div>
  );
}

function FamilyDot({ family }: { family: string }) {
  // Family dots are categorical — three brand anchors give a clean
  // visual partition (cool / warm / accent) without overloading the
  // semantic success/danger colors with category meaning.
  const palette: Record<string, string> = {
    https: "bg-navy-400",
    sql: "bg-butter-500",
    k8s: "bg-rust-500",
  };
  return (
    <span
      className={
        "inline-block w-[6px] h-[6px] rounded-full " + (palette[family] ?? "bg-text-subtle")
      }
      title={family}
    />
  );
}

function Verdict({ r }: { r: RuleSummary }) {
  if (r.approve && r.approve.length > 0) {
    const names = r.approve.map((s) => s.name).join(" → ");
    return (
      <Tag tone="warning" title={names}>
        approve
      </Tag>
    );
  }
  const verdict = r.verdict || "allow";
  const tones: Record<string, Tone> = { allow: "success", deny: "danger" };
  return <Tag tone={tones[verdict] ?? "neutral"}>{verdict}</Tag>;
}

function renderCondition(r: RuleSummary): string {
  const parts: string[] = [];
  if (r.credential) parts.push(`credential = ${r.credential}`);
  if (r.condition) parts.push(r.condition);
  if (parts.length === 0) return "matches every request";
  return parts.join(" · ");
}
