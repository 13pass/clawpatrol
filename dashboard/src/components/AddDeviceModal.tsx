import { useEffect, useState } from "react";
import { listProfiles, type Whoami } from "../lib/api";
import { AgentJoinPanel, useJoinIntent } from "./AgentJoinPanel";
import { JoinSteps } from "./JoinSteps";
import { initialProfile } from "../lib/addDeviceProfile";
import { Modal } from "./Modal";

const LAST_PROFILE_KEY = "clawpatrol.addDevice.profile";

function lastProfile(): string {
  try {
    return localStorage.getItem(LAST_PROFILE_KEY) ?? "";
  } catch {
    return "";
  }
}

function rememberProfile(profile: string) {
  try {
    localStorage.setItem(LAST_PROFILE_KEY, profile);
  } catch {
    // Private windows may refuse storage; the next window asks again.
  }
}

export function AddDeviceModal({
  whoami,
  onClose,
}: {
  whoami?: Whoami | null;
  onClose: () => void;
}) {
  const url = whoami?.public_url || window.location.origin;
  // null while loading; the agent prompt waits for the profile.
  const [profiles, setProfiles] = useState<string[] | null>(null);
  const [profilesErr, setProfilesErr] = useState("");
  const [profile, setProfile] = useState("");
  // "agent": a prompt for an AI agent on the new device, approved in
  // this window (AgentJoinPanel). Closing the window revokes it.
  const [tab, setTab] = useState<"agent" | "commands">("agent");
  // A member can add devices only to a profile of their own; a gateway
  // without profiles still lets an admin make a prompt.
  const member = whoami?.role === "member";
  const noProfileOfTheirOwn = member && profiles?.length === 0;
  const mustChoose = !!profiles && profiles.length > 1 && !profile;
  const canPrompt = profiles !== null && !profilesErr && !noProfileOfTheirOwn && !mustChoose;
  const join = useJoinIntent(canPrompt ? profile : null);
  // Switching profile replaces the prompt, which would cancel a join
  // that is already waiting for approval.
  const joinInFlight = join.state === "pending" || join.state === "approved";

  useEffect(() => {
    listProfiles()
      .then((p) => {
        setProfiles(p);
        setProfile(initialProfile(p, member, lastProfile()));
      })
      .catch((e) => {
        setProfilesErr(String(e));
        setProfiles([]);
      });
  }, [member]);

  // An operator authenticated over the tailnet can mint joins that
  // auto-approve: --login joins with their identity and the gateway's
  // operator gate accepts the self-approval. Password sessions can't
  // promise that, so the plain browser-approval join is suggested.
  const login = whoami?.auth_method === "tailscale";

  return (
    <Modal title="Add device" onClose={onClose}>
      <div className="p-4 space-y-5">
        <div className="flex text-xs border-1.5 border-navy squircle-sm overflow-hidden w-fit font-mono">
          {(
            [
              ["agent", "Agent prompt"],
              ["commands", "Commands"],
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

        {profiles && profiles.length === 1 && (
          <p className="text-xs text-text-muted font-sans">
            Profile: <span className="font-mono text-text">{profile}</span>
          </p>
        )}
        {profiles && profiles.length > 1 && (
          <label className="block space-y-1">
            <span className="text-xs text-text-muted font-sans">Profile</span>
            <select
              value={profile}
              onChange={(e) => {
                setProfile(e.target.value);
                rememberProfile(e.target.value);
              }}
              disabled={joinInFlight}
              className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
            >
              {!profile && (
                <option value="" disabled>
                  Choose a profile…
                </option>
              )}
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
            join={join}
            blocked={
              profilesErr
                ? `Could not load your profiles: ${profilesErr}`
                : noProfileOfTheirOwn
                  ? "You have no profile yet, so there is nothing to add a device to. Ask an admin to assign you one."
                  : mustChoose
                    ? "Choose the profile the new device joins."
                    : ""
            }
          />
        )}
      </div>
    </Modal>
  );
}
