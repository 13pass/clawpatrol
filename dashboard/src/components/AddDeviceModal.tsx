import { useEffect, useState } from "react";
import { listProfiles, type Whoami } from "../lib/api";
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
    <Modal title="Add device" onClose={onClose}>
      <div className="p-4 space-y-5">
        <h3 className="text-sm leading-none tracking-tight text-text font-mono">
          Run the following on the new device:
        </h3>

        {profiles.length > 1 && (
          <label className="block space-y-1">
            <span className="text-xs text-text-muted font-sans">Profile</span>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
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
        <JoinSteps url={url} profile={profile} login={login} />
      </div>
    </Modal>
  );
}
