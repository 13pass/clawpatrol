import { useState } from "react";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";
import { RuleRequests } from "./RuleRequests";
import { RulesPanel } from "./RulesPanel";

export function RulesPage({ isMember }: { isMember: boolean }) {
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
    </Main>
  );
}
