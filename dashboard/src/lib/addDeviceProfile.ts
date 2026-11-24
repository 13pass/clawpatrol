// initialProfile picks the profile a new Add device window starts on:
// the last one picked in this browser, else a member's first own
// profile. An admin sees every profile and none is theirs, so they
// choose ("" until then) rather than land on the gateway's fallback.
export function initialProfile(profiles: string[], member: boolean, last: string): string {
  if (profiles.includes(last)) return last;
  if (member || profiles.length === 1) return profiles[0] ?? "";
  return "";
}
