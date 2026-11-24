import { useEffect, useState } from "react";
import { listProfiles, type Whoami } from "../lib/api";
import { AgentJoinPanel, useJoinIntent } from "./AgentJoinPanel";
import { JoinSteps } from "./JoinSteps";
import { Modal } from "./Modal";

export function AddDeviceModal({
  whoami,
  onClose,
}: {
  whoami?: Whoami | null;
  onClose: () => void;
}) {
  const url = whoami?.public_url || window.location.origin;
  const [profiles, setProfiles] = useState<string[]>([]);
  const [profile, setProfile] = useState("");
  // "agent": a prompt for an AI agent on the new device, approved in
  // this window (AgentJoinPanel).
  const [tab, setTab] = useState<"commands" | "agent">("commands");
  const join = useJoinIntent();
  function close() {
    join.cancelIfLive();
    onClose();
  }

  useEffect(() => {
    listProfiles()
      .then((p) => {
        setProfiles(p);
        // Mirror the gateway's default-profile pick: "default" if it
        // exists, else the first profile in source order.
        setProfile(p.includes("default") ? "default" : (p[0] ?? ""));
      })
      .catch(() => setProfiles([]));
  }, []);

  // An operator authenticated over the tailnet can mint joins that
  // auto-approve: --login joins with their identity and the gateway's
  // operator gate accepts the self-approval. Password sessions can't
  // promise that, so the plain browser-approval join is suggested.
  const login = whoami?.auth_method === "tailscale";

  return (
    <Modal title="Add device" onClose={close}>
      <div className="p-4 space-y-5">
        <div className="flex text-xs border-1.5 border-navy squircle-sm overflow-hidden w-fit font-mono">
          {(
            [
              ["commands", "Commands"],
              ["agent", "Agent prompt"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={`px-3 py-1 cursor-pointer ${tab === key ? "bg-navy text-canvas" : "text-text hover:bg-navy-100"}`}
            >
              {label}
            </button>
          ))}
        </div>

        {profiles.length > 1 && (
          <label className="block space-y-1">
            <span className="text-xs text-text-muted font-sans">Profile</span>
            <select
              value={join.intent ? join.intent.profile : profile}
              onChange={(e) => setProfile(e.target.value)}
              // The prompt carries its profile; a new prompt picks another.
              disabled={!!join.intent}
              className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
            >
              {profiles.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>
        )}

        {tab === "commands" ? (
          <>
            <h3 className="text-sm leading-none tracking-tight text-text font-mono">
              Run the following on the new device:
            </h3>
            <JoinSteps url={url} profile={profile} login={login} />
          </>
        ) : (
          <AgentJoinPanel
            gatewayURL={url}
            profile={profile}
            profileRequired={profiles.length > 0}
            join={join}
          />
        )}
      </div>
    </Modal>
  );
}
