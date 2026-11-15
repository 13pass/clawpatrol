import { useState } from "react";
import { Button } from "./Button";

// RuleLinkHelp gives admins a prompt that teaches an agent to propose
// rules as dashboard links. Agents under `clawpatrol run` read the same
// in their manifest.
export function RuleLinkHelp({ publicURL }: { publicURL?: string }) {
  const [copied, setCopied] = useState(false);
  // The gateway's public URL, as in the manifest, so every admin can open the link.
  const base = publicURL
    ? publicURL.replace(/\/+$/, "") + "/"
    : `${window.location.origin}${window.location.pathname}`;
  const prompt = [
    "When a Claw Patrol rule would help (a request was blocked or held, or a guard is needed), propose it as a link instead of describing it.",
    `- For an HTTPS or Kubernetes request the gateway refused (403), the response carries the link ready-made in its X-Clawpatrol-Rule-Link header and its body: give it as is, or append &verdict=<deny|allow|approve>&condition=<CEL>&note=<why> to fill it in. Its form: ${base}#/request/<request id>?rule`,
    `- Otherwise, for an endpoint (an admin must open it): ${base}#/rules/new?endpoint=<endpoint>&verdict=<deny|allow|approve>&condition=<CEL>&note=<why>`,
    "- verdict: deny, allow (pre-approve) or approve (hold for a human). endpoint (endpoint link only): the Claw Patrol endpoint name.",
    "- condition: a CEL expression on the request, e.g. http.method == 'DELETE'. HTTP: http.method, http.path, http.query, http.headers, http.body_json. Kubernetes adds k8s.verb, k8s.resource, k8s.namespace, k8s.name, k8s.params. SQL: sql.verb, sql.tables, sql.function, sql.statement. Omitted, the request link matches requests like that one and the endpoint link every request to the endpoint; keep it as narrow as the need.",
    "- note: one sentence on why. Endpoint link only, optional: approver=<human approver>, profile=<profile>.",
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
