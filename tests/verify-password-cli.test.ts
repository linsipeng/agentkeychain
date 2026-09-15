import { expect, test } from "bun:test";
import { parseVerifyPasswordArgs } from "../src/cli/verify-password.ts";

test("verify-password CLI defaults to private browser input and rejects unreachable flags", () => {
  expect(parseVerifyPasswordArgs([])).toEqual({ openBrowser: true, json: false });
  expect(parseVerifyPasswordArgs(["--no-open"])).toEqual({ openBrowser: false, json: false });
  expect(parseVerifyPasswordArgs(["--json"])).toEqual({ openBrowser: true, json: true });
  expect(() => parseVerifyPasswordArgs(["--no-open", "--json"])).toThrow("cannot be combined");
  const candidate = "must-never-appear-in-error-output";
  expect(() => parseVerifyPasswordArgs([candidate])).toThrow("unknown option");
  try {
    parseVerifyPasswordArgs([candidate]);
  } catch (error) {
    expect(String(error)).not.toContain(candidate);
  }
});
