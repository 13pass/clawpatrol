/// <reference lib="deno.ns" />
import { initialProfile } from "./addDeviceProfile";

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

Deno.test("initialProfile: the last pick wins while it still exists", () => {
  assert(initialProfile(["default", "vincenth"], false, "vincenth") === "vincenth", "last pick");
  assert(initialProfile(["default", "gemma"], false, "vincenth") === "", "a stale pick");
});

Deno.test("initialProfile: an admin with several profiles chooses", () => {
  assert(initialProfile(["default", "vincenth"], false, "") === "", "admin landed on a profile");
  assert(initialProfile(["vincenth"], false, "") === "vincenth", "a single profile");
  assert(initialProfile([], false, "") === "", "a gateway without profiles");
});

Deno.test("initialProfile: a member starts on their own profile", () => {
  assert(initialProfile(["gemma", "ops"], true, "") === "gemma", "member's first profile");
});
