/**
 * Policy files on disk: which files count, how they parse, how they're
 * written back, and how two rule sets are compared and diffed.
 *
 * A policy file is YAML (`.yaml` / `.yml`) or JSON (`.json`) holding
 * `{ action_type, description?, rules }`. `rules` is exactly the object
 * the runtime rule engine (`engine/rules.ts`, synced from the AtlaSent runtime) evaluates — there is
 * no second policy language. Test suites live next to policies as
 * `*.tests.yaml` / `*.tests.yml` / `*.tests.json`.
 *
 * Pure except for the caller-supplied text; zero network.
 */
import yaml from "js-yaml";

const POLICY_EXT = /\.(ya?ml|json)$/i;
const TEST_SUFFIX = /\.tests\.(ya?ml|json)$/i;

/** Published JSON Schema for policy files (editor autocomplete + validation). */
export const POLICY_SCHEMA_URL =
  "https://raw.githubusercontent.com/Atlasent/atlasent-policies/main/schema/policy.schema.json";

export type PolicyFormat = "yaml" | "json";

export function isTestFile(path: string): boolean {
  return TEST_SUFFIX.test(path);
}

export function isPolicyFile(path: string): boolean {
  return POLICY_EXT.test(path) && !isTestFile(path);
}

export function formatOf(path: string): PolicyFormat {
  return /\.json$/i.test(path) ? "json" : "yaml";
}

/**
 * Parse YAML or JSON text. YAML uses the core schema, so an unquoted
 * `2026-12-22` stays a string (the engine compares strings) instead of
 * becoming a Date, and duplicate keys are an error rather than a silent
 * last-one-wins. Throws on any parse error — callers must surface it, never
 * skip the file (this applies to JSON too): a policy that silently drops out of a directory scan would
 * make `plan` report "no change" and `apply` leave stale rules live.
 */
export function parsePolicyText(text: string, path: string): unknown {
  if (formatOf(path) === "json") {
    // JSON.parse keeps the last of duplicate keys silently; re-read with the
    // YAML parser (a JSON superset that rejects duplicates) to catch them.
    const value = JSON.parse(text);
    yaml.load(text, { schema: yaml.JSON_SCHEMA, filename: path });
    return value;
  }
  return yaml.load(text, { schema: yaml.CORE_SCHEMA, filename: path });
}

/** Render a policy document in the requested format, with a schema header for YAML. */
export function dumpPolicy(doc: Record<string, unknown>, format: PolicyFormat): string {
  if (format === "json") return JSON.stringify(doc, null, 2) + "\n";
  const body = yaml.dump(doc, { schema: yaml.CORE_SCHEMA, noRefs: true, lineWidth: 100, sortKeys: false });
  return `# yaml-language-server: $schema=${POLICY_SCHEMA_URL}\n${body}`;
}

/** Stable JSON with sorted object keys — key order never counts as a change. */
export function canonicalJSON(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[k];
      if (v !== undefined) out[k] = sortKeys(v);
    }
    return out;
  }
  return value;
}

export function rulesEqual(a: unknown, b: unknown): boolean {
  return canonicalJSON(a ?? {}) === canonicalJSON(b ?? {});
}

/** Rules rendered as key-sorted YAML lines, the unit `plan` diffs on. */
export function rulesLines(rules: unknown): string[] {
  if (rules === undefined || rules === null) return [];
  return yaml
    .dump(sortKeys(rules), { schema: yaml.CORE_SCHEMA, noRefs: true, lineWidth: -1 })
    .replace(/\n$/, "")
    .split("\n");
}

/**
 * Line diff (LCS). Returns lines prefixed "  " (same), "- " (removed from
 * `before`) and "+ " (added in `after`). Policies are small, so the
 * quadratic table is fine; `context` trims long unchanged runs.
 */
export function diffLines(before: string[], after: string[], context = 3): string[] {
  const n = before.length;
  const m = after.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = before[i] === after[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const ops: Array<{ tag: " " | "-" | "+"; line: string }> = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (before[i] === after[j]) { ops.push({ tag: " ", line: before[i] }); i++; j++; }
    else if (lcs[i + 1][j] >= lcs[i][j + 1]) { ops.push({ tag: "-", line: before[i] }); i++; }
    else { ops.push({ tag: "+", line: after[j] }); j++; }
  }
  while (i < n) ops.push({ tag: "-", line: before[i++] });
  while (j < m) ops.push({ tag: "+", line: after[j++] });

  const keep = ops.map((op, idx) =>
    op.tag !== " " || ops.slice(Math.max(0, idx - context), idx + context + 1).some((o) => o.tag !== " "),
  );
  const out: string[] = [];
  let skipped = false;
  ops.forEach((op, idx) => {
    if (keep[idx]) {
      if (skipped) { out.push("  ..."); skipped = false; }
      out.push(`${op.tag} ${op.line}`);
    } else {
      skipped = true;
    }
  });
  if (skipped && out.length > 0) out.push("  ...");
  return out;
}
