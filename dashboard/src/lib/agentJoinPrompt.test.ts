/// <reference lib="deno.ns" />
import { buildAgentJoinPrompt, formatExpiry } from "./agentJoinPrompt";

const input = {
  gatewayURL: "https://gateway.example.com",
  caFingerprint: "AB:CD:EF",
  profile: "gemma",
  deviceName: "",
  intent: "intent-123",
  expiresAt: Date.UTC(2026, 10, 24, 14, 32) / 1000,
};

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

Deno.test("buildAgentJoinPrompt: join command pins the CA and carries no name or profile flags", () => {
  const out = buildAgentJoinPrompt(input);
  const cmd =
    "clawpatrol join --intent intent-123 --ca-fingerprint AB:CD:EF --no-trust https://gateway.example.com";
  assert(out.includes(cmd), `missing join command in:\n${out}`);
  for (const flag of ["--profile", "--hostname", "--whole-machine", "--login"]) {
    assert(!out.includes(flag), `prompt must not use ${flag}`);
  }
  assert(out.includes("expires 14:32 UTC"), "missing expiry");
  assert(out.includes("<machine>-<OS account>"), "missing default device name");
});

Deno.test("buildAgentJoinPrompt: no fingerprint, no pin", () => {
  const out = buildAgentJoinPrompt({ ...input, caFingerprint: "", deviceName: "ci-runner" });
  assert(!out.includes("--ca-fingerprint"), "pinned an empty fingerprint");
  assert(!out.includes("CA SHA-256"), "listed an empty fingerprint");
  assert(out.includes("Device name: ci-runner"), "missing operator-chosen name");
});

Deno.test("formatExpiry: UTC hours and minutes", () => {
  assert(formatExpiry(Date.UTC(2026, 0, 2, 3, 4) / 1000) === "03:04 UTC", "wrong format");
});
