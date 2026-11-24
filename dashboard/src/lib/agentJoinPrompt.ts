// The prompt the Add device window hands to an LLM agent so it can join
// its machine (onboard_intent.go on the gateway). Everything in it may
// end up in provider logs: it carries only public facts and a join
// intent that grants nothing until the operator approves in that window.

export type AgentJoinPromptInput = {
  gatewayURL: string;
  caFingerprint: string;
  profile: string;
  intent: string;
};

const installCmd = "curl -fsSL https://clawpatrol.dev/install.sh | sh";

export function buildAgentJoinPrompt(p: AgentJoinPromptInput): string {
  const pin = p.caFingerprint ? ` --ca-fingerprint ${p.caFingerprint}` : "";
  return [
    "Set up this machine as a Claw Patrol device. Claw Patrol is a gateway that holds",
    "API credentials for agents; once joined, commands run with `clawpatrol run --`",
    "reach APIs through it.",
    "",
    `Gateway:     ${p.gatewayURL}`,
    ...(p.caFingerprint ? [`CA SHA-256:  ${p.caFingerprint}`] : []),
    `Profile:     ${p.profile} (set by the gateway; you cannot change it)`,
    `Join intent: ${p.intent}`,
    "             single use, and only while the Add device window that made it stays",
    "             open (one hour at most); not a password, it grants nothing by itself",
    "",
    "Run every step as the OS account that will use this device, not as root.",
    "",
    "0. If `clawpatrol` is installed, run `clawpatrol status`. If this account is already",
    "   joined to a gateway, stop and report what it shows: joining again replaces that",
    "   device. A second profile on this machine needs another OS account; never point",
    "   HOME or XDG_* elsewhere to get around this.",
    "1. If `command -v clawpatrol` finds nothing, install it:",
    `   ${installCmd}`,
    "   Then, installed now or before, check that the output of `clawpatrol join --help`",
    '   contains the words "requires --hostname". If not, stop: the client is too old',
    "   for this prompt. Do not try a join to find out.",
    "2. Name the device <machine>-<OS account>, in lowercase:",
    "   - <machine> is the machine's short hostname: the part of `hostname` before",
    "     the first dot. If `hostname` is missing, use $HOSTNAME or /etc/hostname",
    "     (on Windows, %COMPUTERNAME%).",
    "   - <OS account> is `whoami` (on Windows, the part after the backslash).",
    "   For example, account alice on machine devbox gives devbox-alice. Always keep",
    "   the account part: other accounts on this machine may have devices of their own.",
    "   If the hostname means nothing to a person (a container ID, localhost, a random",
    "   cloud name), use a short word for what the machine is instead, such as",
    "   ci-runner-alice, and say so in your report.",
    "   Use only letters, digits, '.', '_' and '-', at most 63 characters.",
    "3. Start the join in the background; it waits up to 10 minutes for approval:",
    `   clawpatrol join --intent ${p.intent} --hostname <device name>${pin} --no-trust ${p.gatewayURL}`,
    "4. When it prints CLAWPATROL_USER_CODE=XXXX-XXXX, tell the user:",
    '   "Approve <device name> in the Add device window. The code is XXXX-XXXX."',
    "   Then wait for the join to exit.",
    "5. Check: clawpatrol status",
    "6. Tell the user to restart you as `clawpatrol run -- <the command that started you>`.",
    "   This session does not go through the gateway.",
    "",
    "Rules:",
    "- Do not use sudo. If a step needs it, stop and give the user the exact command.",
    "- Never change the gateway URL or the fingerprint, and never turn off TLS checks.",
    "  If the CA does not match, stop and report.",
    "- Do not approve the request yourself and do not open the dashboard.",
    "- Never print, copy or commit the files in ~/.clawpatrol or ~/.config/clawpatrol.",
    '- The join adds `eval "$(clawpatrol env)"` to the shell rc; say so in your report.',
    "- On an error, stop and report the last 20 lines of output. Do not run the join again:",
    "  the intent works once, and the user makes a new prompt.",
  ].join("\n");
}
