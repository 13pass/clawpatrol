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
  for (const part of [
    "<machine>-<OS account>",
    "`hostname`",
    "%COMPUTERNAME%",
    "whoami",
    "devbox-alice",
  ]) {
    assert(out.includes(part), `naming rule lacks ${part}`);
  }
});

Deno.test("buildAgentJoinPrompt: checks an installed client without joining", () => {
  const out = buildAgentJoinPrompt(input);
  assert(out.includes("installed now or before"), "version check only covers fresh installs");
  assert(out.includes("Do not try a join to find out"), "version check may start a join");
});

Deno.test("buildAgentJoinPrompt: no fingerprint, no pin", () => {
  const out = buildAgentJoinPrompt({ ...input, caFingerprint: "" });
  assert(!out.includes("--ca-fingerprint"), "pinned an empty fingerprint");
  assert(!out.includes("CA SHA-256"), "listed an empty fingerprint");
});
