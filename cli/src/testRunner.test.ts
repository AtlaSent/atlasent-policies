import { describe, it, expect } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseTestFile, discoverTests, runTests, summarizeResults } from "./testRunner";
import type { PolicyDoc } from "./commands";

async function tempRepo(): Promise<string> {
  const dir = join(tmpdir(), `atlasent-test-harness-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(join(dir, "policies"), { recursive: true });
  return dir;
}

describe("parseTestFile", () => {
  it("parses a well-formed file", () => {
    const raw = JSON.stringify({
      bundle: "deployment.production",
      tests: [
        { name: "ok", context: { env: "prod" }, expect: "allow" },
        { name: "stale", context: {}, expect: "deny", expect_deny_code: "NO_TEMPLATE_MATCH" },
      ],
    });
    const parsed = parseTestFile(raw, "/x/deployment.production.tests.json", "/x");
    expect(parsed.bundle).toBe("deployment.production");
    expect(parsed.tests.length).toBe(2);
    expect(parsed.tests[1].expect_deny_code).toBe("NO_TEMPLATE_MATCH");
  });

  it("errors on missing bundle", () => {
    expect(() => parseTestFile(JSON.stringify({ tests: [] }), "/x/a.tests.json", "/x"))
      .toThrow(/"bundle" is required/);
  });

  it("errors on invalid decision value", () => {
    expect(() => parseTestFile(
      JSON.stringify({ bundle: "x", tests: [{ name: "t", expect: "maybe" }] }),
      "/x/a.tests.json",
      "/x",
    )).toThrow(/expect must be one of/);
  });

  it("errors on invalid ISO timestamp", () => {
    expect(() => parseTestFile(
      JSON.stringify({ bundle: "x", tests: [{ name: "t", expect: "allow", now: "not-a-date" }] }),
      "/x/a.tests.json",
      "/x",
    )).toThrow(/valid ISO timestamp/);
  });

  it("errors on invalid fail_mode", () => {
    expect(() => parseTestFile(
      JSON.stringify({ bundle: "x", tests: [{ name: "t", expect: "allow", fail_mode: "sometimes" }] }),
      "/x/a.tests.json",
      "/x",
    )).toThrow(/fail_mode must be/);
  });
});

describe("runTests", () => {
  const bundle: PolicyDoc = {
    action_type: "deployment.production",
    rules: {
      templates: [
        { decision: "allow", when: { all: [{ field: "context.env", eq: "prod" }, { field: "context.approvals", gte: 2 }] } },
        { decision: "deny" },
      ],
    },
  };

  it("pass: matches decision", () => {
    const results = runTests(
      [{
        path: "/p.tests.json",
        rel: "p.tests.json",
        bundle: "deployment.production",
        tests: [{ name: "prod with 2", context: { env: "prod", approvals: 2 }, expect: "allow" }],
      }],
      new Map([["deployment.production", bundle]]),
    );
    expect(results[0].cases[0].passed).toBe(true);
  });

  it("fail: mismatch on decision", () => {
    const results = runTests(
      [{
        path: "/p.tests.json", rel: "p.tests.json", bundle: "deployment.production",
        tests: [{ name: "prod with 1", context: { env: "prod", approvals: 1 }, expect: "allow" }],
      }],
      new Map([["deployment.production", bundle]]),
    );
    expect(results[0].cases[0].passed).toBe(false);
    expect(results[0].cases[0].reason).toMatch(/expected allow, got deny/);
  });

  it("fail: decision matches but expect_deny_code doesn't", () => {
    const results = runTests(
      [{
        path: "/p.tests.json", rel: "p.tests.json", bundle: "deployment.production",
        tests: [{ name: "t", context: { env: "dev" }, expect: "deny", expect_deny_code: "OUTSIDE_CHANGE_WINDOW" }],
      }],
      new Map([["deployment.production", bundle]]),
    );
    expect(results[0].cases[0].passed).toBe(false);
    expect(results[0].cases[0].reason).toMatch(/expected deny_code OUTSIDE_CHANGE_WINDOW/);
  });

  it("fail: no bundle matching action_type", () => {
    const results = runTests(
      [{
        path: "/p.tests.json", rel: "p.tests.json", bundle: "missing",
        tests: [{ name: "t", expect: "allow" }],
      }],
      new Map([["deployment.production", bundle]]),
    );
    expect(results[0].cases[0].passed).toBe(false);
    expect(results[0].cases[0].reason).toMatch(/no bundle found/);
  });

  it("honors test.now for time-dependent rules", () => {
    const timeBundle: PolicyDoc = {
      action_type: "x",
      rules: {
        change_window: { hours: { start: "09:00", end: "17:00" }, timezone: "UTC" },
        templates: [{ decision: "allow" }],
      },
    };
    const runAt = (now: string, expect: "allow" | "deny") => {
      const results = runTests(
        [{ path: "/t.tests.json", rel: "t.tests.json", bundle: "x",
           tests: [{ name: "in/out", now, expect }] }],
        new Map([["x", timeBundle]]),
      );
      return results[0].cases[0].passed;
    };
    expect(runAt("2026-04-17T12:00:00Z", "allow")).toBe(true);
    expect(runAt("2026-04-17T22:00:00Z", "deny")).toBe(true);
  });
});

describe("summarizeResults", () => {
  it("sums passed/failed across files", () => {
    const results = [
      { testFile: { path: "", rel: "", bundle: "x", tests: [] }, bundle: null, cases: [
        { test: { name: "a", expect: "allow" as const }, passed: true, actualDecision: "allow" as const },
        { test: { name: "b", expect: "deny" as const }, passed: false, actualDecision: "allow" as const },
      ]},
      { testFile: { path: "", rel: "", bundle: "y", tests: [] }, bundle: null, cases: [
        { test: { name: "c", expect: "allow" as const }, passed: true, actualDecision: "allow" as const },
      ]},
    ];
    expect(summarizeResults(results)).toEqual({ total: 3, passed: 2, failed: 1 });
  });
});

describe("discoverTests", () => {
  it("finds only *.tests.json files, ignoring bundle files", async () => {
    const repo = await tempRepo();
    await writeFile(
      join(repo, "policies/deployment.production.json"),
      JSON.stringify({ action_type: "deployment.production", rules: { templates: [{ decision: "allow" }] } }),
    );
    await writeFile(
      join(repo, "policies/deployment.production.tests.json"),
      JSON.stringify({ bundle: "deployment.production", tests: [{ name: "t", expect: "allow" }] }),
    );
    const found = await discoverTests(join(repo, "policies"));
    expect(found.length).toBe(1);
    expect(found[0].bundle).toBe("deployment.production");
  });

  it("silently skips malformed test files (caller's lint surfaces the error)", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "policies/good.tests.json"), JSON.stringify({
      bundle: "x", tests: [{ name: "t", expect: "allow" }],
    }));
    await writeFile(join(repo, "policies/broken.tests.json"), "{ not valid json");
    const found = await discoverTests(join(repo, "policies"));
    expect(found.length).toBe(1);
    expect(found[0].bundle).toBe("x");
  });

  it("invokes onError callback for structurally invalid test files", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "policies/good.tests.json"), JSON.stringify({
      bundle: "x", tests: [{ name: "t", expect: "allow" }],
    }));
    await writeFile(join(repo, "policies/bad.tests.json"), JSON.stringify({
      bundle: "x", tests: [{ name: "t", expect: "not-a-valid-decision" }],
    }));
    const errors: string[] = [];
    const found = await discoverTests(join(repo, "policies"), (_rel, err) => {
      errors.push(err.message);
    });
    expect(found.length).toBe(1);
    expect(found[0].bundle).toBe("x");
    expect(errors.length).toBe(1);
    expect(errors[0]).toMatch(/expect must be one of/);
  });
});
