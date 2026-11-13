import { useEffect, useMemo, useState } from "react";
import {
  deleteMyRule,
  getMyRules,
  getRules,
  setMyRuleDisabled,
  type MyRule,
  type RuleChange,
  type RuleSummary,
} from "../lib/api";
import { Button } from "./Button";
import { Tag, type Tone } from "./Tag";

// RulesPanel lists the rules that apply, grouped by endpoint: all of
// them, or those of one profile on a device page. The rules of the
// viewer's own file (the dashboard's, for an admin) are disabled,
// enabled or deleted here; the others name the file to change them in.
export function RulesPanel({
  profile,
  onChanged,
}: {
  profile?: string;
  // onChanged runs after a change, applied or sent for review.
  onChanged?: () => void;
}) {
  const [rows, setRows] = useState<RuleSummary[]>([]);
  const [mine, setMine] = useState<Map<string, MyRule>>(new Map());
  const [myFile, setMyFile] = useState("");
  const [unavailable, setUnavailable] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState("");

  function refresh() {
    return Promise.all([getRules(), getMyRules().catch(() => null)])
      .then(([all, my]) => {
        setRows(all ?? []);
        setMine(new Map((my?.rules ?? []).map((r) => [r.name, r])));
        setMyFile(my?.file ?? "");
        setUnavailable(my?.unavailable ?? "");
        setErr(null);
      })
      .catch((e) => setErr(String(e instanceof Error ? e.message : e)));
  }

  useEffect(() => {
    refresh();
  }, []);

  async function change(r: MyRule, kind: RuleChange) {
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
    if (profile) return rows.filter((r) => !r.profile || r.profile === profile);
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
        mine={mine}
        myFile={myFile}
        onChange={change}
        allRulesLink={!!profile}
      />
    </div>
  );
}

function Section({
  title,
  rows,
  mine,
  myFile,
  onChange,
  allRulesLink,
}: {
  title: string;
  rows: RuleSummary[];
  mine: Map<string, MyRule>;
  myFile: string;
  onChange: (r: MyRule, kind: RuleChange) => void;
  allRulesLink: boolean;
}) {
  // Group by endpoint. Server already sorts rules within an endpoint
  // by priority desc. Endpoint groups themselves sort alphabetically.
  const groups = useMemo(() => {
    const m = new Map<string, { endpoint: string; family: string; rules: RuleSummary[] }>();
    for (const r of rows) {
      const g = m.get(r.endpoint) ?? {
        endpoint: r.endpoint,
        family: r.family,
        rules: [],
      };
      g.rules.push(r);
      m.set(r.endpoint, g);
    }
    return Array.from(m.values()).sort((a, b) => a.endpoint.localeCompare(b.endpoint));
  }, [rows]);

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
      {myFile && (
        <div className="px-4 py-2 text-2xs text-text-muted border-b border-canvas-muted">
          Rules in <code>{myFile}</code> can be disabled or deleted here; the others change in the
          file named next to them.
        </div>
      )}
      {groups.length === 0 ? (
        <div className="px-5 py-5 text-center text-xs text-text-subtle">no rules configured</div>
      ) : (
        <div className="flex flex-col">
          {groups.map((g) => (
            <EndpointGroup key={g.endpoint} group={g} mine={mine} onChange={onChange} />
          ))}
        </div>
      )}
    </div>
  );
}

function EndpointGroup({
  group,
  mine,
  onChange,
}: {
  group: { endpoint: string; family: string; rules: RuleSummary[] };
  mine: Map<string, MyRule>;
  onChange: (r: MyRule, kind: RuleChange) => void;
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
      </div>
      {group.rules.map((r, i) => (
        <RuleRow key={`${r.name}/${i}`} rule={r} mine={mine.get(r.name)} onChange={onChange} />
      ))}
    </div>
  );
}

function RuleRow({
  rule: r,
  mine,
  onChange,
}: {
  rule: RuleSummary;
  mine?: MyRule;
  onChange: (r: MyRule, kind: RuleChange) => void;
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
        {mine && !mine.owned && (
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
        {mine ? (
          <div className="flex gap-1 mt-1">
            <Button
              size="xs"
              variant="outline"
              disabled={!mine.owned}
              onClick={() => onChange(mine, mine.disabled ? "enable" : "disable")}
            >
              {mine.disabled ? "Enable" : "Disable"}
            </Button>
            <Button
              size="xs"
              variant="outline"
              disabled={!mine.owned}
              onClick={() => onChange(mine, "delete")}
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
