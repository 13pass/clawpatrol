/// <reference lib="deno.ns" />
import { buildAgentJoinPrompt } from "./agentJoinPrompt";

const input = {
  gatewayURL: "https://gateway.example.com",
  caFingerprint: "AB:CD:EF",
  profile: "gemma",
  intent: "intent-123",
};

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

Deno.test("buildAgentJoinPrompt: join command names the device and pins the CA", () => {
  const out = buildAgentJoinPrompt(input);
  const cmd =
    "clawpatrol join --intent intent-123 --hostname <device name> --ca-fingerprint AB:CD:EF --no-trust https://gateway.example.com";
  assert(out.includes(cmd), `missing join command in:\n${out}`);
  for (const flag of ["--profile", "--whole-machine", "--login"]) {
    assert(!out.includes(flag), `prompt must not use ${flag}`);
  }
});

Deno.test("buildAgentJoinPrompt: tells the agent how to name the device", () => {
  const out = buildAgentJoinPrompt(input);
  for (const part of ["<machine>-<OS account>", "hostname -s", "whoami", "devbox-alice"]) {
    assert(out.includes(part), `naming rule lacks ${part}`);
  }
});

Deno.test("buildAgentJoinPrompt: no fingerprint, no pin", () => {
  const out = buildAgentJoinPrompt({ ...input, caFingerprint: "" });
  assert(!out.includes("--ca-fingerprint"), "pinned an empty fingerprint");
  assert(!out.includes("CA SHA-256"), "listed an empty fingerprint");
});
