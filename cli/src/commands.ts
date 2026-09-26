import { mkdir, readFile, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { parsePolicyFile, lintRules as lintRulesLegacy } from "./linter.js";
import { lintPolicy, hasErrors as lintHasErrors } from "./lint.js";
import { runTests as runRemoteSuite } from "./runner.js";
import { discoverTests, runTests as runDocTests, summarizeResults } from "./testRunner.js";
import { walk } from "./tests.js";
import {
  diffLines,
  dumpPolicy,
  formatOf,
  isPolicyFile,
  isTestFile,
  parsePolicyText,
  rulesEqual,
  rulesLines,
  type PolicyFormat,
} from "./policyFile.js";

// ───────────────────────────────────────────────────────────────────────
// Public types — the contract that run.ts, testRunner.ts, commands.test.ts,
// and external test harnesses depend on. Names + shapes are stable; renaming
// any of them is a breaking change.
// ───────────────────────────────────────────────────────────────────────

/**
 * Dependency-injection seam for cmd functions. Tests build a fake env
 * that captures stdout/stderr and tracks `exit`; the real CLI passes
 * one wired up to process.* and console.*.
 */
export interface Env {
  cwd(): string;
  stdout(line: string): void;
  stderr(line: string): void;
  exit(code: number): never;
  env: Record<string, string | undefined>;
  /**
   * Optional factory for the bundles HTTP client. Tests inject a fake;
   * the default cmd implementations build a real one when this is unset.
   * The exact `BundlesClient` surface is fleshed out in chunk 3 — for
   * now this is a forward declaration so types compose.
   */
  clientFactory?: (config: { apiKey: string; baseUrl: string }) => { bundles: BundlesClient };
}

/**
 * Forward-declared HTTP surface for `/v1-bundles`. Tests already lean
 * on this shape via `attachFakeClient` in commands.test.ts; chunk 3
 * implements the real fetch-backed version + wires the cmd functions
 * to it.
 */
export interface BundlesClient {
  list(): Promise<{ bundles: Array<Record<string, unknown>> }>;
  get(id: string): Promise<{ bundle: Record<string, unknown> }>;
  /** Published bundle for an action_type, or an `error_code` body (e.g. NO_ACTION_CLASS). */
  current(actionType: string): Promise<{ bundle?: Record<string, unknown> | null; error_code?: string; reason?: string }>;
  upsert(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
  publish(id: string): Promise<Record<string, unknown>>;
  unpublish(id: string): Promise<Record<string, unknown>>;
  simulate(payload: Record<string, unknown>): Promise<Record<string, unknown>>;
}

/** A parsed policy document — one `.yaml` / `.yml` / `.json` file in `policies/`. */
export interface PolicyDoc {
  action_type: string;
  description?: string;
  rules: Record<string, unknown>;
}

/** A loaded policy file with its on-disk path and its parsed body. */
export interface PolicyFile {
  /** Absolute path. */
  path: string;
  /** Path relative to the directory the user invoked the cmd against. */
  rel: string;
  /** Parsed body (YAML or JSON). */
  doc: PolicyDoc;
}

// ───────────────────────────────────────────────────────────────────────
// Default env — what bin.ts / direct callers get when they don't pass one.
// ───────────────────────────────────────────────────────────────────────

function defaultEnv(): Env {
  return {
    cwd: () => process.cwd(),
    stdout: (l: string) => { console.log(l); },
    stderr: (l: string) => { console.error(l); },
    exit: ((code: number): never => {
      process.exit(code);
      throw new Error(`exit(${code})`); // unreachable; keeps TS happy
    }) as Env["exit"],
    env: process.env as Record<string, string | undefined>,
  };
}

const POLICY_EXTS_LABEL = ".yaml, .yml, .json";

/** Canonical action_type slug (same rule v1-evaluate enforces). */
const ACTION_TYPE_SLUG = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

/** A policy file that could not be loaded. Never silently skipped. */
export interface PolicyLoadError {
  rel: string;
  message: string;
}

async function loadPolicyDocs(
  root: string,
  env: Env,
): Promise<{ files: PolicyFile[]; errors: PolicyLoadError[] }> {
  const absRoot = resolve(env.cwd(), root);
  const files: PolicyFile[] = [];
  const errors: PolicyLoadError[] = [];
  await walk(absRoot, async (p: string) => {
    if (!isPolicyFile(p)) return;
    const rel = relative(absRoot, p) || p;
    let parsed: unknown;
    try {
      parsed = parsePolicyText(await readFile(p, "utf-8"), p);
    } catch (err) {
      errors.push({ rel, message: `cannot parse: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}` });
      return;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      errors.push({ rel, message: "top level must be an object with action_type and rules" });
      return;
    }
    files.push({ path: p, rel, doc: parsed as PolicyDoc });
  });
  files.sort((a, b) => a.rel.localeCompare(b.rel));

  // Two files for one action_type would make apply publish both in turn,
  // last one winning — a silent, order-dependent result. Refuse instead.
  const seen = new Map<string, string>();
  for (const f of files) {
    const at = f.doc.action_type;
    if (typeof at !== "string") continue;
    const prior = seen.get(at);
    if (prior) errors.push({ rel: f.rel, message: `duplicate action_type "${at}" (also defined in ${prior})` });
    else seen.set(at, f.rel);
  }
  return { files, errors };
}

/**
 * Load every policy file under `target`, or exit 1 if any file fails to
 * load or none exist. Commands that act on the whole directory (validate,
 * plan, apply) use this so one broken file can never be skipped.
 */
async function loadPolicyDocsOrExit(target: string, env: Env): Promise<PolicyFile[]> {
  const { files, errors } = await loadPolicyDocs(target, env);
  for (const e of errors) env.stdout(`✗ ${e.rel} — ${e.message}`);
  if (errors.length > 0) env.exit(1);
  if (files.length === 0) {
    env.stdout(`No policy files (${POLICY_EXTS_LABEL}) found in ${target}`);
    env.exit(1);
  }
  return files;
}

async function isDirectory(p: string, env: Env): Promise<boolean> {
  try {
    const s = await stat(resolve(env.cwd(), p));
    return s.isDirectory();
  } catch { return false; }
}

// ───────────────────────────────────────────────────────────────────────
// Legacy HTTP helpers — preserved for chunk 2 so the plan/apply/pull/
// simulate cmds keep working against /v1-bundles. Chunk 3 replaces these
// with the BundlesClient surface.
// ───────────────────────────────────────────────────────────────────────

function getApiKey(env: Env): string {
  const key = env.env.ATLASENT_API_KEY;
  if (!key) {
    env.stderr("Error: ATLASENT_API_KEY environment variable is not set");
    env.exit(1);
  }
  return key;
}

function getBaseUrl(env: Env): string {
  return env.env.ATLASENT_BASE_URL ?? "https://api.atlasent.io/functions/v1";
}

async function apiRequest(
  env: Env,
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  const url = `${getBaseUrl(env)}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${getApiKey(env)}`,
      "Content-Type": "application/json",
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res;
}

// ───────────────────────────────────────────────────────────────────────
// Commands
// ───────────────────────────────────────────────────────────────────────

/**
 * Lint every policy file in `dir` (default "policies"). Walks
 * recursively; .tests.json files are skipped for policy linting but are
 * themselves validated for structural correctness (field types, decision
 * values, ISO timestamps). Exits 1 if any file has a lint error or if
 * no policy files were found.
 *
 * Backwards compat: if `dir` is actually a single .json file path,
 * behaves like the legacy single-file validator.
 */
export async function cmdValidate(args: string[], envIn?: Env): Promise<void> {
  const env = envIn ?? defaultEnv();
  const target = args[0] ?? "policies";

  // Single-file legacy path (pre-chunk-2 behavior).
  if (target.endsWith(".json") && !(await isDirectory(target, env))) {
    let bundle;
    try {
      bundle = parsePolicyFile(resolve(env.cwd(), target));
    } catch (err) {
      env.stderr(`Parse error: ${err instanceof Error ? err.message : String(err)}`);
      env.exit(1); // never returns
    }
    const violations = lintRulesLegacy(bundle!);
    for (const v of violations) {
      const prefix = v.severity === "error" ? "ERROR" : "WARN ";
      env.stdout(`${prefix}  ${v.path}  ${v.message}`);
    }
    if (violations.length === 0) env.stdout(`✓ ${target} — clean (no violations)`);
    if (violations.some((v) => v.severity === "error")) env.exit(1);
    return;
  }

  const { files, errors: loadErrors } = await loadPolicyDocs(target, env);
  for (const e of loadErrors) env.stdout(`✗ ${e.rel} — ${e.message}`);
  if (files.length === 0 && loadErrors.length === 0) {
    env.stdout(`No policy files (${POLICY_EXTS_LABEL}) found in ${target}`);
    env.exit(1);
  }

  let errorFiles = loadErrors.length;
  for (const f of files) {
    const findings = lintPolicy(f.doc as unknown as Record<string, unknown>);
    if (findings.length === 0) {
      env.stdout(`✓ ${f.rel} — clean`);
      continue;
    }
    for (const finding of findings) {
      const icon = finding.level === "error" ? "✗" : finding.level === "warning" ? "⚠" : "•";
      env.stdout(`${icon} ${f.rel} [${finding.code}] ${finding.path}: ${finding.message}`);
    }
    if (lintHasErrors(findings)) errorFiles++;
  }

  // Also validate *.tests.{yaml,yml,json} file structure (parse + field types only;
  // bundle matching is deferred to `atlasent-policy test`).
  await discoverTests(resolve(env.cwd(), target), (_rel, err) => {
    env.stdout(`✗ [INVALID_TEST_FILE] ${err.message}`);
    errorFiles++;
  });

  if (errorFiles > 0) env.exit(1);
}

/**
 * Run *.tests.json suites. With a directory argument, walks for test
 * files and matches each by `bundle` field to a sibling PolicyDoc;
 * runs evaluateRules() in-process (no network).
 *
 * Backwards compat: if the argument is a single .tests.json file (or
 * a non-directory path), falls back to the legacy server-based runner
 * (`runner.ts`).
 */
export async function cmdTest(args: string[], envIn?: Env): Promise<void> {
  const env = envIn ?? defaultEnv();
  const target = args[0] ?? "policies";

  // Legacy single-suite path → server-side runner.
  if (target.endsWith(".tests.json") || (target.endsWith(".json") && !(await isDirectory(target, env)))) {
    const { results, passed, failed } = await runRemoteSuite(resolve(env.cwd(), target));
    for (const r of results) {
      const icon = r.passed ? "✓" : "✗";
      const status = r.passed ? "PASS" : `FAIL (expected ${r.expected}, got ${r.actual})`;
      env.stdout(`  ${icon} ${r.description} — ${status}`);
      if (r.error) env.stdout(`      error: ${r.error}`);
    }
    env.stdout(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) env.exit(1);
    return;
  }

  const policies = await loadPolicyDocsOrExit(target, env);
  let brokenSuites = 0;
  const tests = await discoverTests(resolve(env.cwd(), target), (rel, err) => {
    env.stdout(`✗ ${rel} — ${err.message}`);
    brokenSuites++;
  });
  if (brokenSuites > 0) env.exit(1);
  if (tests.length === 0) {
    env.stdout(`No test files (*.tests.yaml, *.tests.json) found in ${target}`);
    env.exit(1);
  }

  const bundles = new Map<string, PolicyDoc>();
  for (const p of policies) {
    if (typeof p.doc.action_type === "string") bundles.set(p.doc.action_type, p.doc);
  }

  const results = runDocTests(tests, bundles);
  const summary = summarizeResults(results);

  for (const r of results) {
    for (const c of r.cases) {
      const icon = c.passed ? "✓" : "✖";
      const suffix = c.passed ? "" : ` — ${c.reason ?? ""}`;
      env.stdout(`${icon} ${c.test.name}${suffix}`);
    }
  }
  env.stdout(`${summary.passed}/${summary.total} cases passed`);
  if (summary.failed > 0) env.exit(1);
}

// ───────────────────────────────────────────────────────────────────────
// BundlesClient — fetch-backed default impl. Tests inject a fake via
// env.clientFactory; production callers fall through to this.
// ───────────────────────────────────────────────────────────────────────

function bundlesFor(env: Env): BundlesClient {
  if (env.clientFactory) {
    const apiKey = env.env.ATLASENT_API_KEY ?? "";
    const baseUrl = env.env.ATLASENT_BASE_URL ?? "";
    return env.clientFactory({ apiKey, baseUrl }).bundles;
  }
  return new FetchBundlesClient(getBaseUrl(env), getApiKey(env));
}

/**
 * Fetch-backed client for the runtime `v1-bundles` function. The deployed
 * handler is a single POST endpoint that routes on `body.action` (list /
 * get / current / upsert / publish / unpublish / validate); it has no
 * REST sub-paths. `baseUrl` is the functions base, e.g.
 * https://api.atlasent.io/functions/v1.
 */
export class FetchBundlesClient implements BundlesClient {
  constructor(private readonly baseUrl: string, private readonly apiKey: string) {}

  private async call(action: string, fields: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl.replace(/\/$/, "")}/v1-bundles`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ...fields, action }),
    });
    const text = await res.text();
    let parsed: unknown;
    try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { raw: text }; }
    if (!res.ok) {
      const obj = (parsed ?? {}) as Record<string, unknown>;
      // Domain errors (NO_ACTION_CLASS, INVALID_RULES, approval-chain refusals)
      // carry error_code; return them so commands can print a precise reason.
      if (typeof obj.error_code === "string") return obj;
      // Auth / rate-limit denials use the shared { error, message } envelope.
      if (typeof obj.error === "string") {
        return { error_code: obj.error, reason: typeof obj.message === "string" ? obj.message : `HTTP ${res.status}` };
      }
      throw new Error(`API ${res.status}: ${text || res.statusText}`);
    }
    return parsed as Record<string, unknown>;
  }

  list() { return this.call("list") as Promise<{ bundles: Array<Record<string, unknown>> }>; }
  get(id: string) { return this.call("get", { id }) as Promise<{ bundle: Record<string, unknown> }>; }
  current(actionType: string) {
    return this.call("current", { action_type: actionType }) as Promise<{ bundle?: Record<string, unknown> | null; error_code?: string; reason?: string }>;
  }
  upsert(payload: Record<string, unknown>) { return this.call("upsert", payload); }
  publish(id: string) { return this.call("publish", { id }); }
  unpublish(id: string) { return this.call("unpublish", { id }); }
  async simulate(_payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    // v1-bundles has no simulate action. Traffic replay lives in
    // v1-bundle-simulate and needs a stored draft bundle id; until the CLI
    // creates drafts for it, say so plainly rather than calling a route
    // that does not exist.
    return {
      error_code: "SIMULATE_NOT_SUPPORTED",
      reason: "simulate is not available from the CLI yet; use `test` for offline cases or the console simulator",
    };
  }
}

// ───────────────────────────────────────────────────────────────────────
// Flag parsing — small enough to inline; handles the "--flag value" and
// "--flag" boolean shapes commands.test.ts uses.
// ───────────────────────────────────────────────────────────────────────

function splitArgs(args: string[]): { positional: string[]; flags: Record<string, string | boolean> } {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("--")) { flags[key] = next; i++; }
      else flags[key] = true;
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function lintFile(file: PolicyFile): { findings: ReturnType<typeof lintPolicy>; hasErrors: boolean } {
  const findings = lintPolicy(file.doc as unknown as Record<string, unknown>);
  return { findings, hasErrors: lintHasErrors(findings) };
}

function printLintFindings(env: Env, file: PolicyFile, findings: ReturnType<typeof lintPolicy>): void {
  for (const f of findings) {
    const icon = f.level === "error" ? "✗" : f.level === "warning" ? "⚠" : "•";
    env.stdout(`  ${icon} [${f.code}] ${f.path}: ${f.message}`);
  }
}

// ───────────────────────────────────────────────────────────────────────
// plan / apply share one comparison: the file's rules vs the rules of the
// currently published bundle for that action_type, compared key-order
// independently. This is done client-side because the server only reports
// `unchanged` when the caller sends the server-computed rules_hash.
// ───────────────────────────────────────────────────────────────────────

type PlanStatus = "unchanged" | "create" | "update" | "error";

interface PlanEntry {
  file: PolicyFile;
  status: PlanStatus;
  /** Published version the change replaces, if any. */
  currentVersion?: number;
  /** Unified-style line diff of the rules (update/create only). */
  diff?: string[];
  /** Why the file cannot be planned/applied. */
  error?: string;
  lint?: ReturnType<typeof lintPolicy>;
}

async function planFile(bundles: BundlesClient, file: PolicyFile): Promise<PlanEntry> {
  const { findings, hasErrors } = lintFile(file);
  if (hasErrors) return { file, status: "error", error: "lint errors (run `atlasent-policy validate`)", lint: findings };

  const cur = (await bundles.current(file.doc.action_type)) as Record<string, unknown>;
  if (typeof cur.error_code === "string") {
    const hint = cur.error_code === "NO_ACTION_CLASS"
      ? " — create the action class first (console → Action classes, or POST /v1-action-classes)"
      : "";
    return { file, status: "error", error: `${cur.error_code}: ${String(cur.reason ?? "")}${hint}` };
  }
  const current = (cur.bundle ?? null) as { version?: number; rules?: unknown } | null;
  if (current && rulesEqual(current.rules, file.doc.rules)) {
    return { file, status: "unchanged", currentVersion: current.version };
  }

  // Server-side validation (the authority) without writing anything.
  const dry = await bundles.upsert({
    action_type: file.doc.action_type,
    description: file.doc.description,
    rules: file.doc.rules,
    dry_run: true,
  });
  if (typeof dry.error_code === "string") {
    const errs = Array.isArray(dry.errors)
      ? ` ${(dry.errors as Array<{ path?: string; message?: string }>).map((e) => `${e.path}: ${e.message}`).join("; ")}`
      : "";
    return { file, status: "error", error: `${dry.error_code}: ${String(dry.reason ?? "")}${errs}`.trim() };
  }

  return {
    file,
    status: current ? "update" : "create",
    currentVersion: current?.version,
    diff: diffLines(rulesLines(current?.rules), rulesLines(file.doc.rules)),
  };
}

function printPlanText(env: Env, entries: PlanEntry[]): void {
  for (const e of entries) {
    const at = e.file.doc.action_type;
    if (e.status === "unchanged") {
      env.stdout(`= ${e.file.rel} (${at}) — no change (matches published v${e.currentVersion ?? "?"})`);
    } else if (e.status === "error") {
      env.stdout(`✗ ${e.file.rel} (${at}) — ${e.error}`);
      if (e.lint) printLintFindings(env, e.file, e.lint);
    } else {
      const what = e.status === "create" ? "will publish v1 (no published bundle yet)" : `will publish a new version (replaces v${e.currentVersion ?? "?"})`;
      env.stdout(`~ ${e.file.rel} (${at}) — ${what}`);
      for (const line of e.diff ?? []) env.stdout(`    ${line}`);
    }
  }
}

function planSummary(entries: PlanEntry[]): { changes: number; unchanged: number; errors: number; text: string } {
  const changes = entries.filter((e) => e.status === "create" || e.status === "update").length;
  const unchanged = entries.filter((e) => e.status === "unchanged").length;
  const errors = entries.filter((e) => e.status === "error").length;
  return { changes, unchanged, errors, text: `Plan: ${changes} to publish, ${unchanged} unchanged, ${errors} error(s).` };
}

function renderPlanMarkdown(entries: PlanEntry[]): string {
  const { text } = planSummary(entries);
  const lines: string[] = ["### AtlaSent policy plan", "", `**${text}**`, ""];
  for (const e of entries) {
    const at = e.file.doc.action_type;
    if (e.status === "unchanged") continue;
    if (e.status === "error") {
      lines.push(`- ❌ \`${e.file.rel}\` (\`${at}\`): ${e.error}`);
      for (const f of e.lint ?? []) lines.push(`  - \`${f.path}\` ${f.code}: ${f.message}`);
      continue;
    }
    const what = e.status === "create" ? "new — publishes v1" : `publishes a new version (replaces v${e.currentVersion ?? "?"})`;
    lines.push(`<details open><summary><code>${e.file.rel}</code> (<code>${at}</code>): ${what}</summary>`, "", "```diff");
    for (const d of e.diff ?? []) lines.push(d.startsWith("  ") ? ` ${d.slice(2)}` : `${d[0]}${d.slice(2)}`);
    lines.push("```", "", "</details>");
  }
  if (entries.every((e) => e.status === "unchanged")) lines.push("No changes. Live policy matches the repository.");
  return lines.join("\n");
}

/**
 * plan: show what `apply` would publish, as a rules diff per file.
 *
 *   --format text|markdown   markdown is ready to post as a PR comment
 *   --detailed-exitcode      exit 2 when there are changes (Terraform-style)
 *
 * Exit codes: 0 no errors (and, with --detailed-exitcode, no changes);
 * 1 any file failed to load, lint, or validate; 2 changes present
 * (--detailed-exitcode only). Makes no writes.
 */
export async function cmdPlan(args: string[], envIn?: Env): Promise<void> {
  const env = envIn ?? defaultEnv();
  const { positional, flags } = splitArgs(args);
  const target = positional[0] ?? "policies";

  const files = await loadPolicyDocsOrExit(target, env);
  const bundles = bundlesFor(env);
  const entries: PlanEntry[] = [];
  for (const file of files) entries.push(await planFile(bundles, file));

  if (flags.format === "markdown") env.stdout(renderPlanMarkdown(entries));
  else {
    printPlanText(env, entries);
    env.stdout(planSummary(entries).text);
  }

  const { changes, errors } = planSummary(entries);
  if (errors > 0) env.exit(1);
  if (flags["detailed-exitcode"] === true && changes > 0) env.exit(2);
}

/**
 * apply: publish every file whose rules differ from the live published
 * bundle. Lints and plans EVERY file first (including server-side
 * validation) and writes nothing if any file fails that preflight.
 * Publishes are then made one action type at a time; each is atomic on its
 * own, but there is no cross-file transaction. If the governed path
 * (approval-chain gate + publish_policy_atomic) refuses a later file,
 * earlier files stay published, the command exits 1, and re-running after
 * the fix publishes only what is still out of date. Each publish carries provenance: `source_digest` (the git
 * commit, from --source-digest or $GITHUB_SHA) and a `reason`.
 */
export async function cmdApply(args: string[], envIn?: Env): Promise<void> {
  const env = envIn ?? defaultEnv();
  const { positional, flags } = splitArgs(args);
  const target = positional[0] ?? "policies";

  const files = await loadPolicyDocsOrExit(target, env);

  // Lint everything first — atomicity over progress.
  const linted = files.map((f) => ({ file: f, ...lintFile(f) }));
  const broken = linted.filter((x) => x.hasErrors);
  if (broken.length > 0) {
    env.stdout(`apply: refusing — ${broken.length} file(s) have lint errors:`);
    for (const b of broken) {
      env.stdout(`  ✗ ${b.file.rel}`);
      printLintFindings(env, b.file, b.findings);
    }
    env.exit(1);
  }

  const bundles = bundlesFor(env);
  const entries: PlanEntry[] = [];
  for (const file of files) entries.push(await planFile(bundles, file));
  const failed = entries.filter((e) => e.status === "error");
  if (failed.length > 0) {
    env.stdout(`apply: refusing — ${failed.length} file(s) cannot be applied:`);
    printPlanText(env, failed);
    env.exit(1);
  }

  const sourceDigest = typeof flags["source-digest"] === "string" ? flags["source-digest"] : env.env.GITHUB_SHA;
  let sawError = false;
  for (const e of entries) {
    if (e.status === "unchanged") {
      env.stdout(`= ${e.file.rel} — unchanged`);
      continue;
    }
    const reason = typeof flags.reason === "string"
      ? flags.reason
      : `atlasent-policy apply ${e.file.rel}${sourceDigest ? ` @ ${sourceDigest.slice(0, 12)}` : ""}`;
    const result = await bundles.upsert({
      action_type: e.file.doc.action_type,
      description: e.file.doc.description,
      rules: e.file.doc.rules,
      reason,
      ...(sourceDigest ? { source_digest: sourceDigest } : {}),
    });
    if (typeof result.error_code === "string") {
      env.stdout(`✗ ${e.file.rel} — ${result.error_code}: ${String(result.reason ?? "")}`);
      sawError = true;
      continue;
    }
    if (result.unchanged) {
      env.stdout(`= ${e.file.rel} — unchanged`);
      continue;
    }
    if (result.published) {
      const bundle = result.bundle as { id?: string; version?: number } | undefined;
      env.stdout(`+ ${e.file.rel} — published v${bundle?.version ?? "?"}${bundle?.id ? ` (id=${bundle.id})` : ""}`);
      continue;
    }
    env.stdout(`✗ ${e.file.rel} — unrecognised upsert response`);
    sawError = true;
  }

  if (sawError) env.exit(1);
}

/**
 * pull: download every published bundle into <out>/<action_type>.<ext>.
 * The easy on-ramp: point it at an org whose policies were authored in the
 * console and commit the result. Default format is YAML.
 *
 *   --out <dir>            default policies/
 *   --format yaml|json     default yaml
 */
export async function cmdPull(args: string[], envIn?: Env): Promise<void> {
  const env = envIn ?? defaultEnv();
  const { flags } = splitArgs(args);
  const outDir = typeof flags.out === "string" ? flags.out : "policies";
  const format: PolicyFormat = flags.format === "json" ? "json" : "yaml";

  const bundles = bundlesFor(env);
  const list = await bundles.list();
  const summaries = (list.bundles ?? []) as Array<{ id: string; is_published?: boolean }>;
  const published = summaries.filter((b) => b.is_published === true);
  if (published.length === 0) {
    env.stdout(`No published bundles to pull`);
    return;
  }

  const absOut = resolve(env.cwd(), outDir);
  let pullFailed = false;
  for (const summary of published) {
    const detail = await bundles.get(summary.id);
    const bundle = detail.bundle as {
      action_type?: string; action_type_slug?: string; description?: string; rules?: unknown;
    };
    // upsert/current resolve by slug; `action_type` on list/get is the
    // display name, so prefer the slug when the server provides it.
    const actionType = bundle?.action_type_slug ?? bundle?.action_type;
    if (!actionType) {
      env.stdout(`✗ ${summary.id} — missing action_type`);
      pullFailed = true;
      continue;
    }
    // The slug becomes a file name: only canonical dot-notation slugs are
    // written, so a server value like "../x" or "/etc/x" can never escape
    // the output directory.
    if (!ACTION_TYPE_SLUG.test(actionType)) {
      env.stdout(`✗ ${summary.id} — action_type ${JSON.stringify(actionType)} is not a canonical slug; not written`);
      pullFailed = true;
      continue;
    }
    const filePath = resolve(absOut, `${actionType}.${format === "json" ? "json" : "yaml"}`);
    await mkdir(dirname(filePath), { recursive: true });
    const doc: Record<string, unknown> = { action_type: actionType };
    if (bundle.description) doc.description = bundle.description;
    doc.rules = bundle.rules ?? {};
    await writeFile(filePath, dumpPolicy(doc, format), "utf-8");
    env.stdout(`↓ ${relative(env.cwd(), filePath)}`);
  }
  if (pullFailed) env.exit(1);
}

/**
 * convert: rewrite policy and test files between JSON and YAML in place.
 * Content is unchanged (verified by re-parsing before the original is
 * removed), so `plan` after a convert reports no changes.
 *
 *   atlasent-policy convert [dir] [--to yaml|json] [--keep]
 */
export async function cmdConvert(args: string[], envIn?: Env): Promise<void> {
  const env = envIn ?? defaultEnv();
  const { positional, flags } = splitArgs(args);
  const target = positional[0] ?? "policies";
  const to: PolicyFormat = flags.to === "json" ? "json" : "yaml";
  const keep = flags.keep === true;
  const absRoot = resolve(env.cwd(), target);

  const sources: string[] = [];
  await walk(absRoot, async (p) => {
    if ((isPolicyFile(p) || isTestFile(p)) && formatOf(p) !== to) sources.push(p);
  });
  if (sources.length === 0) {
    env.stdout(`Nothing to convert: no ${to === "yaml" ? "JSON" : "YAML"} policy or test files in ${target}`);
    return;
  }

  let failures = 0;
  for (const src of sources.sort()) {
    const rel = relative(env.cwd(), src);
    let doc: unknown;
    try { doc = parsePolicyText(await readFile(src, "utf-8"), src); }
    catch (err) {
      env.stdout(`✗ ${rel} — cannot parse: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`);
      failures++;
      continue;
    }
    const dest = src.replace(/\.(ya?ml|json)$/i, to === "yaml" ? ".yaml" : ".json");
    if (await stat(dest).then(() => true, () => false)) {
      env.stdout(`✗ ${rel} — ${relative(env.cwd(), dest)} already exists; not overwriting (merge or remove one of them)`);
      failures++;
      continue;
    }
    const text = isTestFile(src)
      ? (to === "json" ? JSON.stringify(doc, null, 2) + "\n" : dumpPolicy(doc as Record<string, unknown>, "yaml").replace(/^# yaml-language-server.*\n/, ""))
      : dumpPolicy(doc as Record<string, unknown>, to);
    // Round-trip check: never delete the original unless the new file
    // parses back to exactly the same content.
    if (!rulesEqual(parsePolicyText(text, dest), doc)) {
      env.stdout(`✗ ${rel} — round-trip mismatch, left unchanged`);
      failures++;
      continue;
    }
    await writeFile(dest, text, "utf-8");
    if (!keep) await unlink(src);
    env.stdout(`→ ${rel} → ${relative(env.cwd(), dest)}`);
  }
  if (failures > 0) env.exit(1);
}

// ───────────────────────────────────────────────────────────────────────
// simulate: per-file backtest. Skips files with lint errors and continues.
// ───────────────────────────────────────────────────────────────────────

export async function cmdSimulate(args: string[], envIn?: Env): Promise<void> {
  const env = envIn ?? defaultEnv();
  const { positional, flags } = splitArgs(args);
  const target = positional[0] ?? "policies";
  const days = flags.days !== undefined ? Number(flags.days) : undefined;
  const limit = flags.limit !== undefined ? Number(flags.limit) : undefined;
  const actionTypeFilter = typeof flags.action_type === "string" ? flags.action_type : undefined;

  const files = await loadPolicyDocsOrExit(target, env);

  const bundles = bundlesFor(env);
  let simulateFailed = false;

  for (const file of files) {
    if (actionTypeFilter && file.doc.action_type !== actionTypeFilter) continue;

    const { findings, hasErrors } = lintFile(file);
    if (hasErrors) {
      env.stdout(`✗ ${file.rel} — skipped: lint errors (run 'validate')`);
      printLintFindings(env, file, findings);
      continue;
    }

    const payload: Record<string, unknown> = {
      action_type: file.doc.action_type,
      rules: file.doc.rules,
    };
    if (days !== undefined) payload.days = days;
    if (limit !== undefined) payload.limit = limit;

    const result = await bundles.simulate(payload);
    if (typeof result.error_code === "string") {
      env.stdout(`✗ ${file.rel} — ${result.error_code}: ${String(result.reason ?? "")}`);
      simulateFailed = true;
      continue;
    }
    const summary = result.summary as
      | { total?: number; identical?: number; diverged?: number; transitions?: Record<string, Record<string, number>>; samples?: Array<Record<string, unknown>> }
      | undefined;

    env.stdout(`— ${file.rel} (${file.doc.action_type})`);
    if (!summary) { env.stdout(`  (no summary in response)`); continue; }
    env.stdout(`  total: ${summary.total ?? 0}`);
    env.stdout(`  identical: ${summary.identical ?? 0}, diverged: ${summary.diverged ?? 0}`);
    if (summary.transitions) {
      for (const [from, tos] of Object.entries(summary.transitions)) {
        for (const [to, n] of Object.entries(tos)) {
          env.stdout(`  ${from} → ${to}: ${n}`);
        }
      }
    }
    if (summary.samples && summary.samples.length > 0) {
      env.stdout(`  ${summary.samples.length} sample(s)`);
    }
  }
  if (simulateFailed) env.exit(1);
}

// ───────────────────────────────────────────────────────────────────────
// cmdVerifyBundle — offline verification of /v1/export-audit bundles
//
// Wraps the SDK's verifyAuditExportBundle for ops-friendly invocation.
// Reads a signed bundle JSON file from disk, runs the five-point check
// (chain hash + adjacency + envelope hash + chain↔envelope binding +
// Ed25519 signature), and prints a human-readable verdict to stdout.
// On any failure, dumps every failure row and exits 1; with --json, emits
// the raw ExportVerifyResult as a single JSON blob (machine consumption).
//
// Exit codes:
//   0 — bundle verifies
//   1 — bundle has one or more failures
//   2 — bad usage (file missing, malformed JSON, --trusted-key not readable)
// ───────────────────────────────────────────────────────────────────────

export async function cmdVerifyBundle(args: string[], envIn?: Env): Promise<void> {
  const env: Env = envIn ?? defaultEnv();
  const { verifyAuditExportBundle } = await import("./engine/export-bundle.js");

  let bundlePath: string | undefined;
  let trustedKeyPath: string | undefined;
  let jsonOut = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--trusted-key") {
      trustedKeyPath = args[++i];
      if (!trustedKeyPath) {
        env.stderr("--trusted-key requires a path argument");
        env.exit(2);
      }
    } else if (a === "--json") {
      jsonOut = true;
    } else if (a.startsWith("-")) {
      env.stderr(`Unknown flag: ${a}`);
      env.exit(2);
    } else if (!bundlePath) {
      bundlePath = a;
    } else {
      env.stderr(`Unexpected positional argument: ${a}`);
      env.exit(2);
    }
  }

  if (!bundlePath) {
    env.stderr("Usage: atlasent-policy verify-bundle <file> [--trusted-key <pem>] [--json]");
    env.exit(2);
  }

  const absBundle = resolve(env.cwd(), bundlePath!);
  let bundleRaw: string;
  try {
    bundleRaw = await readFile(absBundle, "utf8");
  } catch (err) {
    env.stderr(`Cannot read bundle file: ${absBundle}: ${err instanceof Error ? err.message : String(err)}`);
    env.exit(2);
  }

  let bundle: unknown;
  try {
    bundle = JSON.parse(bundleRaw);
  } catch (err) {
    env.stderr(`Bundle is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
    env.exit(2);
  }

  let trustedPublicKeyPem: string | undefined;
  if (trustedKeyPath) {
    const absKey = resolve(env.cwd(), trustedKeyPath);
    try {
      trustedPublicKeyPem = (await readFile(absKey, "utf8")).trim();
    } catch (err) {
      env.stderr(`Cannot read --trusted-key file: ${absKey}: ${err instanceof Error ? err.message : String(err)}`);
      env.exit(2);
    }
  }

  // deno-lint-ignore no-explicit-any
  const result = await verifyAuditExportBundle(bundle as any, { trustedPublicKeyPem });

  if (jsonOut) {
    env.stdout(JSON.stringify(result, null, 2));
    env.exit(result.ok ? 0 : 1);
  }

  if (result.ok) {
    env.stdout("✓ bundle verifies");
    env.stdout(
      `  ${result.checks.evaluations} eval row(s), ${result.checks.envelopes} envelope(s), ${result.checks.envelopes_matched} matched`,
    );
    env.stdout("  five-point verification: chain hash, chain adjacency, envelope hash, chain↔envelope binding, Ed25519 signature");
    env.exit(0);
  }

  env.stdout("✗ bundle FAILED verification");
  env.stdout(`  ${result.failures.length} failure(s):`);
  for (const f of result.failures) {
    const detail = f.detail ? ` — ${f.detail}` : "";
    const exp = f.expected ? ` expected=${f.expected}` : "";
    const act = f.actual ? ` actual=${f.actual}` : "";
    env.stdout(`  [${f.check}] ${f.subject_id}: ${f.reason}${exp}${act}${detail}`);
  }
  env.exit(1);
}
