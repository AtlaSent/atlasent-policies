import { describe, it, expect, vi } from "vitest";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdValidate, cmdTest, cmdPlan, cmdApply, cmdPull, cmdConvert, cmdSimulate, FetchBundlesClient, type Env, type BundlesClient } from "./commands";

async function tempRepo(): Promise<string> {
  const dir = join(tmpdir(), `atlasent-cli-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(join(dir, "policies"), { recursive: true });
  return dir;
}

function writeJSON(dir: string, name: string, doc: unknown) {
  return writeFile(join(dir, "policies", name), JSON.stringify(doc, null, 2));
}

type TestEnv = Env & { out: string[]; err: string[]; exitCode: number | null };

function fakeEnv(cwd: string, overrides: Partial<Env> = {}): TestEnv {
  const out: string[] = [];
  const err: string[] = [];
  const state = { exitCode: null as number | null };
  const base: Env = {
    cwd: () => cwd,
    stdout: (l: string) => { out.push(l); },
    stderr: (l: string) => { err.push(l); },
    exit: ((code: number): never => {
      state.exitCode = code;
      throw new ExitSignal(code);
    }),
    env: {},
    ...overrides,
  };
  return Object.defineProperties(base, {
    out: { get: () => out, enumerable: true },
    err: { get: () => err, enumerable: true },
    exitCode: { get: () => state.exitCode, enumerable: true },
  }) as TestEnv;
}

class ExitSignal extends Error {
  constructor(public code: number) { super(`exit(${code})`); }
}

function fakeBundlesClient(impl: Partial<BundlesClient>): BundlesClient {
  return {
    list: impl.list ?? vi.fn(),
    get: impl.get ?? vi.fn(),
    current: impl.current ?? vi.fn(),
    upsert: impl.upsert ?? vi.fn(),
    publish: impl.publish ?? vi.fn(),
    unpublish: impl.unpublish ?? vi.fn(),
    simulate: impl.simulate ?? vi.fn(),
  };
}

function attachFakeClient<E extends Env>(env: E, bundles: BundlesClient): E {
  const client = { bundles } as unknown as Parameters<NonNullable<Env["clientFactory"]>>[0];
  env.clientFactory = () => client as never;
  env.env.ATLASENT_API_KEY = "k";
  env.env.ATLASENT_BASE_URL = "https://x";
  return env;
}

describe("cmdValidate", () => {
  it("returns clean when every policy is valid", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "prod-deploy.json", {
      action_type: "deployment.production",
      rules: {
        templates: [
          { decision: "allow", when: { all: [{ field: "context.env", eq: "prod" }] } },
          { decision: "deny" },
        ],
      },
    });
    const env = fakeEnv(repo);
    await cmdValidate(["policies"], env).catch(() => {});
    expect(env.err.length).toBe(0);
    expect(env.exitCode).toBeNull();
    expect(env.out.some((l) => l.includes("clean"))).toBe(true);
  });

  it("exits 1 when any file has errors", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "bad.json", {
      action_type: "x",
      rules: { deny_actors: "mallory" }, // must be an array
    });
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdValidate(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown).toBeInstanceOf(ExitSignal);
    expect(thrown!.code).toBe(1);
    expect(env.out.some((l) => l.includes("EXPECTED_ARRAY"))).toBe(true);
  });

  it("exits 1 when no policy files found", async () => {
    const repo = await tempRepo();
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdValidate(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown).toBeInstanceOf(ExitSignal);
    expect(thrown!.code).toBe(1);
  });

  it("reports errors in structurally invalid *.tests.json files", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "x.json", {
      action_type: "x",
      rules: { templates: [{ decision: "allow" }] },
    });
    await writeJSON(repo, "x.tests.json", {
      bundle: "x",
      tests: [{ name: "t", expect: "not-a-valid-decision" }],
    });
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdValidate(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown).toBeInstanceOf(ExitSignal);
    expect(thrown!.code).toBe(1);
    expect(env.out.some((l) => l.includes("INVALID_TEST_FILE"))).toBe(true);
    expect(env.out.some((l) => l.includes("x.tests.json"))).toBe(true);
  });

  it("passes when *.tests.json files are structurally valid alongside clean policies", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "x.json", {
      action_type: "x",
      rules: { templates: [{ decision: "allow" }] },
    });
    await writeJSON(repo, "x.tests.json", {
      bundle: "x",
      tests: [{ name: "prod", context: { env: "prod" }, expect: "allow" }],
    });
    const env = fakeEnv(repo);
    await cmdValidate(["policies"], env).catch(() => {});
    expect(env.exitCode).toBeNull();
  });
});

describe("cmdTest", () => {
  it("passes when every test matches its bundle", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "x.json", {
      action_type: "x",
      rules: {
        templates: [
          { decision: "allow", when: { all: [{ field: "context.env", eq: "prod" }] } },
          { decision: "deny" },
        ],
      },
    });
    await writeJSON(repo, "x.tests.json", {
      bundle: "x",
      tests: [
        { name: "prod", context: { env: "prod" }, expect: "allow" },
        { name: "dev", context: { env: "dev" }, expect: "deny" },
      ],
    });
    const env = fakeEnv(repo);
    await cmdTest(["policies"], env);
    expect(env.exitCode).toBeNull();
    expect(env.out.some((l) => l.includes("2/2 cases passed"))).toBe(true);
  });

  it("exits 1 when any test fails", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "x.json", { action_type: "x", rules: { templates: [{ decision: "deny" }] } });
    await writeJSON(repo, "x.tests.json", {
      bundle: "x",
      tests: [{ name: "wrong expectation", expect: "allow" }],
    });
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdTest(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(env.out.some((l) => l.includes("✖ wrong expectation"))).toBe(true);
  });

  it("exits 1 when no test files exist", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "x.json", { action_type: "x", rules: {} });
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdTest(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
  });
});

describe("cmdSimulate", () => {
  it("calls bundles.simulate and prints the summary", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "x.json", {
      action_type: "x",
      rules: { deny_actors: [], templates: [{ decision: "allow" }] },
    });
    const simulate = vi.fn().mockResolvedValue({
      summary: {
        total: 100,
        identical: 95,
        diverged: 5,
        transitions: { allow: { deny: 5 } },
        samples: [{ request_id: "r1", from: "allow", to: "deny", to_deny_code: "X" }],
      },
    });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ simulate }));
    await cmdSimulate(["policies", "--days", "3", "--limit", "50"], env);
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      action_type: "x",
      limit: 50,
    }));
    expect(env.out.some((l) => l.includes("total: 100"))).toBe(true);
    expect(env.out.some((l) => l.includes("allow → deny: 5"))).toBe(true);
  });

  it("skips files with lint errors and continues", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "broken.json", {
      action_type: "x",
      rules: { templates: [{ decision: "allowww" }] },
    });
    const simulate = vi.fn();
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ simulate }));
    await cmdSimulate(["policies"], env);
    expect(simulate).not.toHaveBeenCalled();
    expect(env.out.some((l) => l.includes("lint errors"))).toBe(true);
  });
});

function writeYAML(dir: string, name: string, text: string) {
  return writeFile(join(dir, "policies", name), text);
}

const current = (rules: unknown, version = 3) => vi.fn().mockResolvedValue({ bundle: { id: "b-cur", version, rules } });
const noCurrent = () => vi.fn().mockResolvedValue({ bundle: null });

describe("policy loading", () => {
  it("reads YAML policies, keeping times and dates as strings", async () => {
    const repo = await tempRepo();
    await writeYAML(repo, "deploy.yaml", [
      "action_type: deployment.production",
      "rules:",
      "  change_window:",
      "    timezone: UTC",
      "    days_of_week: [1, 2, 3]",
      "    hours: { start: 09:00, end: 17:00 }",
      "  freeze_windows:",
      "    - name: holidays",
      "      date_ranges: [{ start: 2026-12-22, end: 2026-12-31 }]",
      "  templates:",
      "    - decision: allow",
    ].join("\n"));
    const upsert = vi.fn().mockResolvedValue({ dry_run: true, would: "publish_new_version" });
    const bundles = fakeBundlesClient({ current: noCurrent(), upsert });
    const env = attachFakeClient(fakeEnv(repo), bundles);
    await cmdPlan(["policies"], env);
    const sent = upsert.mock.calls[0][0] as { rules: Record<string, any> };
    expect(sent.rules.change_window.hours).toEqual({ start: "09:00", end: "17:00" });
    expect(sent.rules.freeze_windows[0].date_ranges[0]).toEqual({ start: "2026-12-22", end: "2026-12-31" });
  });

  it("fails plan instead of skipping a file that does not parse", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "ok.json", { action_type: "a", rules: {} });
    await writeYAML(repo, "broken.yaml", "action_type: b\nrules: [unclosed\n");
    const current = vi.fn();
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current }));
    let thrown: ExitSignal | undefined;
    await cmdPlan(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(current).not.toHaveBeenCalled();
    expect(env.out.some((l) => l.includes("broken.yaml") && l.includes("cannot parse"))).toBe(true);
  });

  it("refuses two files for the same action_type", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "a.json", { action_type: "dup", rules: {} });
    await writeYAML(repo, "a.yaml", "action_type: dup\nrules: {}\n");
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({}));
    let thrown: ExitSignal | undefined;
    await cmdApply(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(env.out.some((l) => l.includes('duplicate action_type "dup"'))).toBe(true);
  });

  it("rejects duplicate keys in YAML", async () => {
    const repo = await tempRepo();
    await writeYAML(repo, "a.yaml", "action_type: a\nrules: {}\nrules: { decision: allow }\n");
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdValidate(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
  });
});

describe("cmdPlan", () => {
  it("reports no change when live rules match, regardless of key order, without a dry-run write", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "p.json", { action_type: "x", rules: { deny_actors: ["m"], templates: [{ decision: "allow" }] } });
    const upsert = vi.fn();
    const bundles = fakeBundlesClient({ current: current({ templates: [{ decision: "allow" }], deny_actors: ["m"] }), upsert });
    const env = attachFakeClient(fakeEnv(repo), bundles);
    await cmdPlan(["policies"], env);
    expect(bundles.current).toHaveBeenCalledWith("x");
    expect(upsert).not.toHaveBeenCalled();
    expect(env.out.some((l) => l.includes("no change"))).toBe(true);
    expect(env.out.some((l) => l.includes("Plan: 0 to publish, 1 unchanged, 0 error(s)."))).toBe(true);
  });

  it("shows a rules diff against the live version and validates via dry-run", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "p.json", { action_type: "x", rules: { deny_actors: ["mallory", "zed"] } });
    const upsert = vi.fn().mockResolvedValue({ dry_run: true, would: "publish_new_version" });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: current({ deny_actors: ["mallory"] }, 4), upsert }));
    await cmdPlan(["policies"], env);
    expect(upsert.mock.calls[0][0]).toMatchObject({ action_type: "x", dry_run: true });
    expect(env.out.some((l) => l.includes("replaces v4"))).toBe(true);
    const diff = env.out.map((l) => l.trim());
    expect(diff).toContain("+   - zed");
    expect(diff).toContain("- mallory"); // unchanged context line
    expect(diff).not.toContain("-   - mallory"); // mallory is not removed
  });

  it("--detailed-exitcode exits 2 when there are changes", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "p.json", { action_type: "x", rules: { deny_actors: ["m"] } });
    const upsert = vi.fn().mockResolvedValue({ dry_run: true, would: "publish_new_version" });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: noCurrent(), upsert }));
    let thrown: ExitSignal | undefined;
    await cmdPlan(["policies", "--detailed-exitcode"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(2);
    expect(env.out.some((l) => l.includes("will publish v1"))).toBe(true);
  });

  it("exits 1 on lint errors without calling the API", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "bad.json", { action_type: "x", rules: { templates: [{ decision: "allowww" }] } });
    const upsert = vi.fn();
    const cur = vi.fn();
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ upsert, current: cur }));
    let thrown: ExitSignal | undefined;
    await cmdPlan(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(upsert).not.toHaveBeenCalled();
    expect(cur).not.toHaveBeenCalled();
    expect(env.out.some((l) => l.includes("lint errors"))).toBe(true);
  });

  it("exits 1 and explains NO_ACTION_CLASS", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "p.json", { action_type: "x", rules: {} });
    const cur = vi.fn().mockResolvedValue({ error_code: "NO_ACTION_CLASS", reason: "No active action class 'x'" });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: cur }));
    let thrown: ExitSignal | undefined;
    await cmdPlan(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(env.out.some((l) => l.includes("create the action class first"))).toBe(true);
  });

  it("exits 1 when server-side validation rejects the rules", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "p.json", { action_type: "x", rules: { deny_actors: ["m"] } });
    const upsert = vi.fn().mockResolvedValue({ error_code: "INVALID_RULES", errors: [{ path: "rules.x", message: "bad" }] });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: noCurrent(), upsert }));
    let thrown: ExitSignal | undefined;
    await cmdPlan(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(env.out.some((l) => l.includes("INVALID_RULES") && l.includes("rules.x: bad"))).toBe(true);
  });

  it("--format markdown renders a PR-comment body with a diff block", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "p.json", { action_type: "x", rules: { deny_actors: ["m"] } });
    const upsert = vi.fn().mockResolvedValue({ dry_run: true, would: "publish_new_version" });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: noCurrent(), upsert }));
    await cmdPlan(["policies", "--format", "markdown"], env);
    const md = env.out.join("\n");
    expect(md).toContain("### AtlaSent policy plan");
    expect(md).toContain("```diff");
    expect(md).toContain("+deny_actors:");
  });
});

describe("cmdApply", () => {
  it("refuses to write anything if any file has lint errors", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "ok.json", { action_type: "x", rules: { deny_actors: [] } });
    await writeJSON(repo, "bad.json", { action_type: "y", rules: { deny_actors: "alice" } });
    const upsert = vi.fn();
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ upsert }));
    let thrown: ExitSignal | undefined;
    await cmdApply(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown).toBeInstanceOf(ExitSignal); expect(thrown!.code).toBe(1);
    expect(upsert).not.toHaveBeenCalled();
  });

  it("publishes only files that differ from live, with provenance", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "a.json", { action_type: "a", rules: { deny_actors: ["m"] } });
    await writeJSON(repo, "b.json", { action_type: "b", rules: { deny_actors: ["n"] } });
    const cur = vi.fn(async (at: string) => ({ bundle: { id: `cur-${at}`, version: 1, rules: at === "a" ? { deny_actors: ["m"] } : {} } }));
    const upsert = vi.fn(async (p: Record<string, unknown>) =>
      p.dry_run ? { dry_run: true, would: "publish_new_version" } : { published: true, bundle: { id: "b-new", version: 2 } });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: cur, upsert }));
    env.env.GITHUB_SHA = "0123456789abcdef0123";
    await cmdApply(["policies"], env);
    const writes = upsert.mock.calls.map((c) => c[0]).filter((p) => !p.dry_run);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ action_type: "b", source_digest: "0123456789abcdef0123" });
    expect(String(writes[0].reason)).toContain("b.json @ 0123456789ab");
    expect(env.out.some((l) => l.includes("a.json — unchanged"))).toBe(true);
    expect(env.out.some((l) => l.includes("published v2"))).toBe(true);
  });

  it("refuses to write anything when any file fails server validation", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "a.json", { action_type: "a", rules: { deny_actors: ["m"] } });
    await writeJSON(repo, "b.json", { action_type: "b", rules: { deny_actors: ["n"] } });
    const cur = vi.fn(async (at: string) =>
      at === "b" ? { error_code: "NO_ACTION_CLASS", reason: "missing" } : { bundle: null });
    const upsert = vi.fn(async (p: Record<string, unknown>) => (p.dry_run ? { dry_run: true } : { published: true }));
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: cur, upsert }));
    let thrown: ExitSignal | undefined;
    await cmdApply(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(upsert.mock.calls.filter((c) => !c[0].dry_run)).toHaveLength(0);
    expect(env.out.some((l) => l.includes("NO_ACTION_CLASS"))).toBe(true);
  });

  it("exits 1 when the governed publish refuses (e.g. approval chain)", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "a.json", { action_type: "a", rules: { deny_actors: ["m"] } });
    const upsert = vi.fn(async (p: Record<string, unknown>) =>
      p.dry_run ? { dry_run: true } : { error_code: "approval_chain_required", reason: "needs approval" });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ current: noCurrent(), upsert }));
    let thrown: ExitSignal | undefined;
    await cmdApply(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(env.out.some((l) => l.includes("approval_chain_required"))).toBe(true);
  });
});

describe("cmdPull", () => {
  const list = () => vi.fn().mockResolvedValue({
    bundles: [
      { id: "b-1", action_type: "Production deploy", version: 2, is_published: true },
      { id: "b-2", action_type: "Production deploy", version: 1, is_published: false },
    ],
  });
  const get = () => vi.fn().mockResolvedValue({
    bundle: {
      id: "b-1",
      action_type: "Production deploy",
      action_type_slug: "deployment.production",
      is_published: true,
      rules: { templates: [{ decision: "allow" }] },
    },
  });

  it("writes YAML by default, named by slug, and skips drafts", async () => {
    const repo = await tempRepo();
    const g = get();
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ list: list(), get: g }));
    await cmdPull(["--out", "policies"], env);
    const text = await readFile(join(repo, "policies", "deployment.production.yaml"), "utf-8");
    expect(text.startsWith("# yaml-language-server: $schema=")).toBe(true);
    expect(text).toContain("action_type: deployment.production");
    expect(g).toHaveBeenCalledTimes(1);
  });

  it("--format json writes JSON", async () => {
    const repo = await tempRepo();
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ list: list(), get: get() }));
    await cmdPull(["--out", "policies", "--format", "json"], env);
    const parsed = JSON.parse(await readFile(join(repo, "policies", "deployment.production.json"), "utf-8"));
    expect(parsed).toEqual({ action_type: "deployment.production", rules: { templates: [{ decision: "allow" }] } });
  });

  it("pulled files plan as unchanged (round trip)", async () => {
    const repo = await tempRepo();
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({
      list: list(), get: get(), current: current({ templates: [{ decision: "allow" }] }),
    }));
    await cmdPull(["--out", "policies"], env);
    await cmdPlan(["policies"], env);
    expect(env.out.some((l) => l.includes("Plan: 0 to publish, 1 unchanged"))).toBe(true);
  });
});

describe("cmdConvert", () => {
  it("rewrites JSON policies and tests as YAML with identical content", async () => {
    const repo = await tempRepo();
    const doc = { action_type: "a", description: "d", rules: { change_window: { hours: { start: "09:00", end: "17:00" } }, templates: [{ decision: "allow" }] } };
    await writeJSON(repo, "a.json", doc);
    await writeJSON(repo, "a.tests.json", { bundle: "a", tests: [{ name: "t", now: "2026-04-14T12:00:00Z", expect: "allow" }] });
    const env = fakeEnv(repo);
    await cmdConvert(["policies"], env);
    const { readdir } = await import("node:fs/promises");
    expect((await readdir(join(repo, "policies"))).sort()).toEqual(["a.tests.yaml", "a.yaml"]);
    const yamlText = await readFile(join(repo, "policies", "a.yaml"), "utf-8");
    const { parsePolicyText } = await import("./policyFile");
    expect(parsePolicyText(yamlText, "a.yaml")).toEqual(doc);
    // The converted tests still run against the converted policy.
    await cmdTest(["policies"], env);
    expect(env.out.some((l) => l.includes("1/1 cases passed"))).toBe(true);
  });

  it("--keep leaves the originals in place", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "a.json", { action_type: "a", rules: {} });
    await cmdConvert(["policies", "--keep"], fakeEnv(repo));
    const { readdir } = await import("node:fs/promises");
    expect((await readdir(join(repo, "policies"))).sort()).toEqual(["a.json", "a.yaml"]);
  });
});

// ───────────────────────────────────────────────────────────────────────
// cmdVerifyBundle — five-point offline verifier (engine/export-bundle.ts).
// ───────────────────────────────────────────────────────────────────────

import { cmdVerifyBundle } from "./commands";
import {
  canonicalizeEnvelope,
  envelopeHashOf,
  type ContextEnvelopeV1,
} from "./engine/context-envelope.js";

async function sha256Hex(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const bytes = new Uint8Array(digest);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
async function makeSignedBundleFixture(): Promise<{ bundle: unknown; bundlePath: string; dir: string }> {
  const dir = await tempRepo();
  // Real signing key pair → real Ed25519 signature → bundle that passes verifier.
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  const spkiB64 = b64(new Uint8Array(spki));
  const body = spkiB64.match(/.{1,64}/g)?.join("\n") ?? spkiB64;
  const publicPem = `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`;

  const envelope: ContextEnvelopeV1 = {
    envelope_version: "atlasent.v1",
    request_id: "req-cli-1",
    issued_at: "2026-05-22T00:00:00.000Z",
    protected_action: "production.deploy",
    intent: { summary: "deploy", operation: "execute" },
    actor: { kind: "service_account", principal: "service:ci" },
    resource: { kind: "deployment", ref: "git:app@v1.0.0" },
    environment: { tenant_id: "org-cli" },
  };
  const envHash = await envelopeHashOf(canonicalizeEnvelope(envelope));
  const payload = [
    "v4", "org-cli", "ac-1", "req-cli-1", "ci", "allow", "", "fp", "pth",
    "b-1", "1", "rh", "", envHash, "", "2026-05-22T00:00:00.000000Z", "GENESIS",
  ].join("|");
  const entryHash = await sha256Hex(payload);

  const bundleWithoutSig = {
    version: 1,
    org_id: "org-cli",
    generated_at: "2026-05-22T00:00:00.000Z",
    range: { since: null, until: null, limit: 10000 },
    evaluations: [{
      id: "e-1",
      request_id: "req-cli-1",
      actor_id: "ci",
      decision: "allow",
      created_at: "2026-05-22T00:00:00.000Z",
      prev_hash: null,
      entry_hash: entryHash,
      payload_version: 4,
      envelope_hash: envHash,
      canonical_payload: payload,
    }],
    execution_head: { id: "e-1", entry_hash: entryHash },
    context_envelopes: [{
      request_id: "req-cli-1",
      envelope_version: "atlasent.v1",
      protected_action: "production.deploy",
      envelope,
      envelope_hash: envHash,
    }],
    public_key_pem: publicPem,
  };
  const canonical = canonicalizeEnvelope(bundleWithoutSig);
  const sigBytes = await crypto.subtle.sign(
    { name: "Ed25519" }, pair.privateKey, new TextEncoder().encode(canonical),
  );
  const bundle = { ...bundleWithoutSig, signature: b64(new Uint8Array(sigBytes)) };
  const bundlePath = join(dir, "bundle.json");
  await writeFile(bundlePath, JSON.stringify(bundle));
  return { bundle, bundlePath, dir };
}

describe("cmdVerifyBundle", () => {
  it("exits 0 and prints a green verdict on a valid bundle", async () => {
    const { dir } = await makeSignedBundleFixture();
    const env = fakeEnv(dir);
    const captured: { exit: ExitSignal | null } = { exit: null };
    await cmdVerifyBundle(["bundle.json"], env).catch((e) => { captured.exit = e as ExitSignal; });
    expect(captured.exit?.code).toBe(0);
    expect(env.out.join("\n")).toMatch(/bundle verifies/);
    expect(env.out.join("\n")).toMatch(/1 eval row\(s\), 1 envelope\(s\), 1 matched/);
  });

  it("exits 1 and prints failure rows when bundle is tampered", async () => {
    const { bundle, dir } = await makeSignedBundleFixture();
    // Tamper: flip the eval row's entry_hash.
    // deno-lint-ignore no-explicit-any
    (bundle as any).evaluations[0].entry_hash = "f".repeat(64);
    const bundlePath = join(dir, "bundle.json");
    await writeFile(bundlePath, JSON.stringify(bundle));
    const env = fakeEnv(dir);
    const captured: { exit: ExitSignal | null } = { exit: null };
    await cmdVerifyBundle(["bundle.json"], env).catch((e) => { captured.exit = e as ExitSignal; });
    expect(captured.exit?.code).toBe(1);
    expect(env.out.join("\n")).toMatch(/FAILED verification/);
    expect(env.out.join("\n")).toMatch(/entry_hash_recompute.*hash_mismatch/);
  });

  it("--json emits the raw ExportVerifyResult", async () => {
    const { dir } = await makeSignedBundleFixture();
    const env = fakeEnv(dir);
    const captured: { exit: ExitSignal | null } = { exit: null };
    await cmdVerifyBundle(["bundle.json", "--json"], env).catch((e) => { captured.exit = e as ExitSignal; });
    expect(captured.exit?.code).toBe(0);
    const parsed = JSON.parse(env.out[0]);
    expect(parsed.ok).toBe(true);
    expect(parsed.checks.evaluations).toBe(1);
  });

  it("--trusted-key rejects a bundle whose public_key_pem doesn't match", async () => {
    const { dir } = await makeSignedBundleFixture();
    // A different valid PEM, but not the one in the bundle.
    const otherPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const otherSpki = await crypto.subtle.exportKey("spki", otherPair.publicKey);
    const otherB64 = b64(new Uint8Array(otherSpki));
    const otherBody = otherB64.match(/.{1,64}/g)?.join("\n") ?? otherB64;
    const otherPem = `-----BEGIN PUBLIC KEY-----\n${otherBody}\n-----END PUBLIC KEY-----`;
    const keyPath = join(dir, "trusted.pem");
    await writeFile(keyPath, otherPem);
    const env = fakeEnv(dir);
    const captured: { exit: ExitSignal | null } = { exit: null };
    await cmdVerifyBundle(["bundle.json", "--trusted-key", "trusted.pem"], env).catch((e) => { captured.exit = e as ExitSignal; });
    expect(captured.exit?.code).toBe(1);
    expect(env.out.join("\n")).toMatch(/trusted_key_mismatch/);
  });

  it("exits 2 on missing file argument", async () => {
    const dir = await tempRepo();
    const env = fakeEnv(dir);
    const captured: { exit: ExitSignal | null } = { exit: null };
    await cmdVerifyBundle([], env).catch((e) => { captured.exit = e as ExitSignal; });
    expect(captured.exit?.code).toBe(2);
    expect(env.err.join("\n")).toMatch(/Usage: atlasent-policy verify-bundle/);
  });

  it("exits 2 when the bundle file isn't valid JSON", async () => {
    const dir = await tempRepo();
    await writeFile(join(dir, "bundle.json"), "{not-json");
    const env = fakeEnv(dir);
    const captured: { exit: ExitSignal | null } = { exit: null };
    await cmdVerifyBundle(["bundle.json"], env).catch((e) => { captured.exit = e as ExitSignal; });
    expect(captured.exit?.code).toBe(2);
    expect(env.err.join("\n")).toMatch(/not valid JSON/);
  });
});

// ───────────────────────────────────────────────────────────────────────
// FetchBundlesClient wire protocol. Every other test injects a fake
// client; this one pins the real HTTP shape, because the previous client
// called REST sub-paths the deployed handler never served and every
// fake-client test still passed.
// ───────────────────────────────────────────────────────────────────────

describe("FetchBundlesClient", () => {
  function stubFetch(responses: Array<{ status: number; body: unknown }>) {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      const r = responses.shift() ?? { status: 200, body: {} };
      return new Response(JSON.stringify(r.body), { status: r.status, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);
    return calls;
  }

  it("POSTs every call to <base>/v1-bundles with an action field", async () => {
    const calls = stubFetch([]);
    const c = new FetchBundlesClient("https://api.atlasent.io/functions/v1/", "ask_test_x");
    await c.list();
    await c.get("b-1");
    await c.current("deployment.production");
    await c.upsert({ action_type: "deployment.production", rules: {}, dry_run: true });
    await c.publish("b-2");
    expect(calls.map((x) => x.url)).toEqual(Array(5).fill("https://api.atlasent.io/functions/v1/v1-bundles"));
    expect(calls.every((x) => x.init.method === "POST")).toBe(true);
    expect(calls.map((x) => JSON.parse(String(x.init.body)))).toEqual([
      { action: "list" },
      { action: "get", id: "b-1" },
      { action: "current", action_type: "deployment.production" },
      { action: "upsert", action_type: "deployment.production", rules: {}, dry_run: true },
      { action: "publish", id: "b-2" },
    ]);
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe("Bearer ask_test_x");
    vi.unstubAllGlobals();
  });

  it("a payload cannot override the action", async () => {
    const calls = stubFetch([]);
    await new FetchBundlesClient("https://x", "k").upsert({ action: "unpublish", action_type: "a", rules: {} });
    expect(JSON.parse(String(calls[0].init.body)).action).toBe("upsert");
    vi.unstubAllGlobals();
  });

  it("returns domain errors and maps the deny envelope to error_code", async () => {
    stubFetch([
      { status: 404, body: { error_code: "NO_ACTION_CLASS", reason: "No active action class 'x'" } },
      { status: 403, body: { error: "unauthorized", message: "Caller lacks policy:write", status: 403 } },
    ]);
    const c = new FetchBundlesClient("https://x", "k");
    expect(await c.current("x")).toMatchObject({ error_code: "NO_ACTION_CLASS" });
    expect(await c.upsert({ action_type: "x", rules: {} })).toEqual({ error_code: "unauthorized", reason: "Caller lacks policy:write" });
    vi.unstubAllGlobals();
  });

  it("throws on an unrecognised error body instead of treating it as success", async () => {
    stubFetch([{ status: 502, body: "bad gateway" }]);
    await expect(new FetchBundlesClient("https://x", "k").list()).rejects.toThrow("API 502");
    vi.unstubAllGlobals();
  });
});

describe("review regressions", () => {
  it("pull refuses a non-canonical slug instead of writing outside --out", async () => {
    const repo = await tempRepo();
    const list = vi.fn().mockResolvedValue({ bundles: [{ id: "b-1", is_published: true }] });
    const get = vi.fn().mockResolvedValue({ bundle: { action_type_slug: "../../escape", rules: {} } });
    const env = attachFakeClient(fakeEnv(repo), fakeBundlesClient({ list, get }));
    let thrown: ExitSignal | undefined;
    await cmdPull(["--out", "policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    const { readdir } = await import("node:fs/promises");
    expect(await readdir(repo)).toEqual(["policies"]);
    expect(await readdir(join(repo, "policies"))).toEqual([]);
  });

  it("convert never overwrites an existing destination, even with --keep", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "a.json", { action_type: "a.one", rules: { deny_actors: ["x"] } });
    await writeYAML(repo, "a.yaml", "action_type: a.two\nrules: {}\n");
    for (const args of [["policies"], ["policies", "--keep"]]) {
      const env = fakeEnv(repo);
      let thrown: ExitSignal | undefined;
      await cmdConvert(args, env).catch((e) => { thrown = e as ExitSignal; });
      expect(thrown?.code).toBe(1);
      expect(await readFile(join(repo, "policies", "a.yaml"), "utf-8")).toBe("action_type: a.two\nrules: {}\n");
      expect(JSON.parse(await readFile(join(repo, "policies", "a.json"), "utf-8")).action_type).toBe("a.one");
    }
  });

  it("test exits 1 on a broken suite even when another suite passes", async () => {
    const repo = await tempRepo();
    await writeJSON(repo, "a.json", { action_type: "a.one", rules: { templates: [{ decision: "allow" }] } });
    await writeYAML(repo, "a.tests.yaml", "bundle: a.one\ntests:\n  - name: ok\n    expect: allow\n");
    await writeYAML(repo, "b.tests.yaml", "bundle: a.one\ntests: [unclosed\n");
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdTest(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(env.out.some((l) => l.includes("b.tests.yaml"))).toBe(true);
  });

  it("rejects duplicate keys in JSON policies too", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "policies", "a.json"),
      '{"action_type":"a.one","rules":{"deny_actors":["m"]},"rules":{}}');
    const env = fakeEnv(repo);
    let thrown: ExitSignal | undefined;
    await cmdValidate(["policies"], env).catch((e) => { thrown = e as ExitSignal; });
    expect(thrown?.code).toBe(1);
    expect(env.out.some((l) => l.includes("a.json") && l.includes("cannot parse"))).toBe(true);
  });
});
