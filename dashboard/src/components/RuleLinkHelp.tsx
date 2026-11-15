import { useState } from "react";
import { Button } from "./Button";

// RuleLinkHelp gives admins a prompt that teaches an agent to propose
// rules as dashboard links. Agents under `clawpatrol run` read the same
// in their manifest.
export function RuleLinkHelp() {
  const [copied, setCopied] = useState(false);
  const link = `${window.location.origin}${window.location.pathname}#/rules/new`;
  const prompt = [
    "When a Claw Patrol rule would help (a request was blocked or held, or a guard is needed), propose it as a link instead of describing it:",
    `${link}?endpoint=<endpoint>&verdict=<deny|allow|approve>&condition=<CEL>&note=<why>`,
    "- endpoint: the Claw Patrol endpoint name. verdict: deny, allow (pre-approve) or approve (hold for a human).",
    "- condition: a CEL expression on the request, e.g. http.method == 'DELETE' (http.method, http.path, http.query, http.headers, http.body_json); omit it for every request. Keep it as narrow as the need.",
    "- note: one sentence on why. Optional: approver=<human approver>, profile=<profile>.",
    "URL-encode every value. The link only fills in the dashboard's rule dialog; I check the preview and create the rule.",
  ].join("\n");

  return (
    <details className="border-1.5 border-navy bg-canvas px-4 py-3 text-xs">
      <summary className="cursor-pointer font-mono uppercase tracking-wider text-navy font-bold">
        Let an agent propose rules
      </summary>
      <div className="mt-3 space-y-2">
        <p className="text-text-muted">
          An agent can prepare a rule as a link that opens the rule dialog filled in. Agents running
          under <code>clawpatrol run</code> learn the format from their manifest; give others this
          prompt:
        </p>
        <pre className="border border-canvas-dark bg-canvas-muted p-3 font-mono text-2xs whitespace-pre-wrap break-all">
          {prompt}
        </pre>
        <Button
          size="xs"
          variant="outline"
          onClick={() =>
            navigator.clipboard.writeText(prompt).then(
              () => setCopied(true),
              () => setCopied(false),
            )
          }
        >
          {copied ? "Copied" : "Copy the prompt"}
        </Button>
      </div>
    </details>
  );
}
