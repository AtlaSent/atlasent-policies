import { readFileSync } from "node:fs";
import { extname } from "node:path";

export interface LintViolation {
  path: string;
  line?: number;
  message: string;
  severity: "error" | "warning";
}

export interface PolicyRule {
  id?: string;
  effect: "allow" | "deny";
  actions?: string[];
  resources?: string[];
  conditions?: Record<string, unknown>;
}

export interface PolicyBundle {
  id: string;
  version?: string;
  rules: PolicyRule[];
  metadata?: Record<string, unknown>;
}

export function lintRules(bundle: PolicyBundle): LintViolation[] {
  const violations: LintViolation[] = [];

  if (!bundle.id || typeof bundle.id !== "string") {
    violations.push({ path: "$.id", message: "Policy bundle must have a string id", severity: "error" });
  }

  if (!Array.isArray(bundle.rules)) {
    violations.push({ path: "$.rules", message: "Policy bundle must have a rules array", severity: "error" });
    return violations;
  }

  if (bundle.rules.length === 0) {
    violations.push({
      path: "$.rules",
      message: "Policy bundle has no rules — all requests will be denied",
      severity: "warning",
    });
  }

  for (let i = 0; i < bundle.rules.length; i++) {
    const rule = bundle.rules[i];
    const base = `$.rules[${i}]`;

    if (rule.effect !== "allow" && rule.effect !== "deny") {
      violations.push({
        path: `${base}.effect`,
        message: `Rule effect must be "allow" or "deny", got: ${JSON.stringify(rule.effect)}`,
        severity: "error",
      });
    }

    if (rule.actions !== undefined && !Array.isArray(rule.actions)) {
      violations.push({ path: `${base}.actions`, message: "Rule actions must be an array", severity: "error" });
    }

    if (rule.resources !== undefined && !Array.isArray(rule.resources)) {
      violations.push({ path: `${base}.resources`, message: "Rule resources must be an array", severity: "error" });
    }

    if (rule.conditions !== undefined && typeof rule.conditions !== "object") {
      violations.push({ path: `${base}.conditions`, message: "Rule conditions must be an object", severity: "error" });
    }

    const hasWildcardAction = Array.isArray(rule.actions) && rule.actions.some((a) => a === "*");
    const hasWildcardResource = Array.isArray(rule.resources) && rule.resources.some((r) => r === "*");
    if (rule.effect === "allow" && hasWildcardAction && hasWildcardResource && !rule.conditions) {
      violations.push({
        path: base,
        message: "Overly permissive: rule allows * actions on * resources without conditions",
        severity: "warning",
      });
    }
  }

  return violations;
}

export function parsePolicyFile(filePath: string): PolicyBundle {
  const ext = extname(filePath).toLowerCase();
  const raw = readFileSync(filePath, "utf-8");

  if (ext === ".json") {
    return JSON.parse(raw) as PolicyBundle;
  }

  if (ext === ".yaml" || ext === ".yml") {
    try {
      // Try to require js-yaml if available
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const yaml = require("js-yaml") as { load: (s: string) => unknown };
      return yaml.load(raw) as PolicyBundle;
    } catch {
      throw new Error(
        `YAML policy files require 'js-yaml'. Install it or convert to JSON.\nFile: ${filePath}`,
      );
    }
  }

  throw new Error(`Unsupported policy file format: ${ext}. Use .json, .yaml, or .yml`);
}
