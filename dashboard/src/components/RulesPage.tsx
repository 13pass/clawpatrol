import { useState } from "react";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";
import { RuleLinkDialog } from "./RuleLinkDialog";
import { RuleLinkHelp } from "./RuleLinkHelp";
import { RuleRequests } from "./RuleRequests";
import { RulesPanel } from "./RulesPanel";

export function RulesPage({
  isMember,
  ruleLink,
  onRuleLinkDone,
}: {
  isMember: boolean;
  // ruleLink is the query of a #/rules/new link, when one opened the page.
  ruleLink?: string;
  onRuleLinkDone: () => void;
}) {
  const [requestsVersion, setRequestsVersion] = useState(0);
  const [rulesVersion, setRulesVersion] = useState(0);

  return (
    <Main>
      <PageTitle trail={[{ label: "Rules" }]} />
      <p className="text-xs text-text-muted">
        Create a rule from any request on the{" "}
        <a href="#/requests" className="underline">
          Requests
        </a>{" "}
        page.
      </p>
      {!isMember && <RuleLinkHelp />}
      <RuleRequests
        isMember={isMember}
        version={requestsVersion}
        onDecided={() => setRulesVersion((v) => v + 1)}
      />
      <RulesPanel
        version={rulesVersion}
        isMember={isMember}
        onChanged={() => setRequestsVersion((v) => v + 1)}
      />
      {ruleLink !== undefined && (
        <RuleLinkDialog
          query={ruleLink}
          isMember={isMember}
          onDone={onRuleLinkDone}
          onCreated={() => setRulesVersion((v) => v + 1)}
        />
      )}
    </Main>
  );
}
