import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { VALID_TOP_LEVEL_KEYS, VALID_TEMPLATE_KEYS, VALID_CONDITION_KEYS } from "./lint";
import { POLICY_SCHEMA_URL } from "./policyFile";

const here = dirname(fileURLToPath(import.meta.url)); // ESM: no __dirname

// The JSON Schema (editor validation), the linter (CLI validation) and the
// engine (runtime) must agree on which keys exist. A key the schema allows
// but the engine ignores is a silent no-op control.
const schema = JSON.parse(readFileSync(join(here, "..", "..", "schema", "policy.schema.json"), "utf-8"));
const keys = (o: Record<string, unknown>) => Object.keys(o).sort();

describe("policy.schema.json", () => {
  it("allows exactly the rule keys the linter allows", () => {
    expect(keys(schema.$defs.rules.properties)).toEqual([...VALID_TOP_LEVEL_KEYS].sort());
  });
  it("allows exactly the template keys the linter allows", () => {
    expect(keys(schema.$defs.rules.properties.templates.items.properties)).toEqual([...VALID_TEMPLATE_KEYS].sort());
  });
  it("allows exactly the condition keys the linter allows", () => {
    expect(keys(schema.$defs.condition.properties)).toEqual([...VALID_CONDITION_KEYS].sort());
  });
  it("rejects unknown keys at every level", () => {
    expect(schema.additionalProperties).toBe(false);
    expect(schema.$defs.rules.additionalProperties).toBe(false);
    expect(schema.$defs.condition.additionalProperties).toBe(false);
    expect(schema.$defs.rules.properties.templates.items.additionalProperties).toBe(false);
  });
  it("matches server validation on shapes the linter doesn't cover", () => {
    const r = schema.$defs.rules.properties;
    // parseLocationRequirements: a non-empty array (max 2) of strict objects.
    expect(r.location_requirements.type).toBe("array");
    expect(r.location_requirements.items.required.sort()).toEqual(
      ["allowed_countries", "max_age_ms", "min_confidence", "subject", "trusted_issuers"]);
    // rules-validate: require_approvals / count must be integers >= 1.
    expect(r.require_approvals.oneOf[0].minimum).toBe(1);
    expect(r.require_approvals.oneOf[1].properties.count.minimum).toBe(1);
  });
  it("is published at the URL YAML files reference", () => {
    expect(schema.$id).toBe(POLICY_SCHEMA_URL);
  });
});

describe("linter vs engine", () => {
  it("allows exactly the Rules fields the engine declares, plus location_requirements", () => {
    const src = readFileSync(join(here, "engine", "rules.ts"), "utf-8");
    const body = src.slice(src.indexOf("export interface Rules {"));
    const block = body.slice(0, body.indexOf("\n}"));
    const engineKeys = [...block.matchAll(/^\s{2}([a-z_]+)\??:/gm)].map((m) => m[1]);
    expect(engineKeys.length).toBeGreaterThan(10);
    expect([...VALID_TOP_LEVEL_KEYS].sort()).toEqual([...engineKeys, "location_requirements"].sort());
  });
});

describe("documented example", () => {
  it("docs/policy-as-code example policy validates and its tests pass", async () => {
    const { cmdValidate, cmdTest } = await import("./commands");
    const out: string[] = [];
    const env = {
      cwd: () => join(here, "..", "examples"),
      stdout: (l: string) => { out.push(l); },
      stderr: (l: string) => { out.push(l); },
      exit: ((code: number): never => { throw new Error(`exit(${code}): ${out.join("\n")}`); }) as (c: number) => never,
      env: {},
    };
    await cmdValidate(["policies"], env);
    await cmdTest(["policies"], env);
    expect(out).toContain("4/4 cases passed");
    const doc = readFileSync(join(here, "..", "..", "docs", "policy-as-code.md"), "utf-8");
    const example = readFileSync(join(here, "..", "examples", "policies", "production.deploy.yaml"), "utf-8");
    expect(doc).toContain(example.trim());
  });
});
