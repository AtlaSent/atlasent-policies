/**
 * Static analysis of an AtlaSent policy `rules` object.
 *
 * Pure, zero-IO. Returns a list of findings; the caller decides whether
 * to print them, exit non-zero, etc. `hasErrors` is the convention CI
 * scripts use for the gate.
 *
 * Codes are stable strings; renaming one is a breaking change for
 * downstream tooling / dashboards. Levels are: "error" (fail the lint
 * gate), "warning" (informational), "info" (rarely used; reserved).
 */

export type LintLevel = "error" | "warning" | "info";

export interface LintFinding {
  level: LintLevel;
  code: string;
  path: string;
  message: string;
}

export function hasErrors(findings: LintFinding[]): boolean {
  return findings.some((f) => f.level === "error");
}

const VALID_DECISIONS = new Set(["allow", "deny", "hold", "escalate"]);

// Exactly the keys the runtime engine reads (`Rules` in engine/rules.ts
// rules.ts, plus `location_requirements`, read by v1-evaluate). Anything
// else is ignored at evaluation time, so a typo such as `deny_actor` would
// silently drop a control — that is an error here, not a warning.
export const VALID_TOP_LEVEL_KEYS = new Set([
  "templates",
  "require_approvals",
  "deny_actors",
  "allow_actors",
  "escalate_actors",
  "hold_actors",
  "deny_roles",
  "allow_roles",
  "escalate_roles",
  "hold_roles",
  "rate_limits",
  "risk",
  "rollout",
  "change_window",
  "freeze_windows",
  "shadow",
  "location_requirements",
  "decision",
  "deny_code",
  "deny_reason",
]);

export const VALID_TEMPLATE_KEYS = new Set([
  "decision",
  "name",
  "when",
  "deny_code",
  "deny_reason",
  "condition_id",
]);

const ARRAY_TOP_LEVEL_KEYS = new Set([
  "deny_actors",
  "allow_actors",
  "escalate_actors",
  "hold_actors",
  "deny_roles",
  "allow_roles",
  "escalate_roles",
  "hold_roles",
  "rate_limits",
  "freeze_windows",
]);

// Operators that need a `field` to bind to. Logical combinators
// (all/any/none/not) and exists are handled separately.
// Exactly the operators the engine evaluates. An unrecognised operator
// makes the condition evaluate false: a deny template silently never
// fires, and under `not` / `none` the guard flips the other way.
export const FIELD_OPERATORS = new Set([
  "eq",
  "neq",
  "gt",
  "gte",
  "lt",
  "lte",
  "in",
  "nin",
  "contains",
  "startswith",
  "endswith",
  "regex",
  "exists",
  "has_any",
  "has_all",
  "subset_of",
]);

// Spellings people reach for that the engine does not understand.
const OPERATOR_SUGGESTIONS: Record<string, string> = {
  ne: "neq",
  not_eq: "neq",
  equals: "eq",
  startsWith: "startswith",
  starts_with: "startswith",
  endsWith: "endswith",
  ends_with: "endswith",
  matches: "regex",
  not_in: "nin",
  includes: "contains",
};

export const LOGICAL_OPERATORS = new Set(["all", "any", "none", "not"]);

export const VALID_CONDITION_KEYS = new Set([
  "field",
  ...FIELD_OPERATORS,
  ...LOGICAL_OPERATORS,
  "regex_flags",
]);

function checkCondition(
  cond: unknown,
  path: string,
  findings: LintFinding[],
): void {
  if (!cond || typeof cond !== "object" || Array.isArray(cond)) {
    findings.push({
      level: "error",
      code: "CONDITION_NOT_OBJECT",
      path,
      message: "Condition must be an object",
    });
    return;
  }
  const c = cond as Record<string, unknown>;
  const keys = Object.keys(c);

  if (keys.length === 0) {
    findings.push({
      level: "error",
      code: "EMPTY_CONDITION",
      path,
      message: "Condition is empty (must contain a field+operator or a logical combinator)",
    });
    return;
  }

  for (const key of keys) {
    if (!VALID_CONDITION_KEYS.has(key)) {
      const hint = OPERATOR_SUGGESTIONS[key] ? ` — did you mean "${OPERATOR_SUGGESTIONS[key]}"?` : "";
      findings.push({
        level: "error",
        code: "UNKNOWN_CONDITION_KEY",
        path: `${path}.${key}`,
        message: `Unknown condition key: "${key}" (the engine would ignore it and the condition would never match)${hint}`,
      });
    }
  }

  const hasLogical = keys.some((k) => LOGICAL_OPERATORS.has(k));
  const hasFieldOp = keys.some((k) => FIELD_OPERATORS.has(k));
  if (hasFieldOp && !c.field && !hasLogical) {
    findings.push({
      level: "error",
      code: "OPERATOR_WITHOUT_FIELD",
      path,
      message: "Field operator used without a `field` reference",
    });
  }

  if (typeof c.regex === "string") {
    try { new RegExp(c.regex, typeof c.regex_flags === "string" ? c.regex_flags : undefined); }
    catch {
      findings.push({
        level: "error",
        code: "INVALID_REGEX",
        path: `${path}.regex`,
        message: `Invalid regex: ${c.regex}`,
      });
    }
  }

  for (const sub of ["all", "any", "none"] as const) {
    const v = c[sub];
    if (v === undefined) continue;
    if (!Array.isArray(v)) {
      findings.push({
        level: "error",
        code: "EXPECTED_ARRAY",
        path: `${path}.${sub}`,
        message: `"${sub}" must be an array of conditions`,
      });
      continue;
    }
    v.forEach((child, i) => checkCondition(child, `${path}.${sub}[${i}]`, findings));
  }
  if (c.not !== undefined) checkCondition(c.not, `${path}.not`, findings);
}

function lintTemplates(templates: unknown, basePath: string, findings: LintFinding[]): void {
  if (!Array.isArray(templates)) {
    findings.push({
      level: "error",
      code: "EXPECTED_ARRAY",
      path: basePath,
      message: `"${basePath}" must be an array`,
    });
    return;
  }
  let seenUnconditional = false;
  for (let i = 0; i < templates.length; i++) {
    const tpath = `${basePath}[${i}]`;
    const raw = templates[i];
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      findings.push({
        level: "error",
        code: "TEMPLATE_NOT_OBJECT",
        path: tpath,
        message: "Template must be an object",
      });
      continue;
    }
    const tmpl = raw as Record<string, unknown>;
    if (seenUnconditional) {
      findings.push({
        level: "warning",
        code: "UNREACHABLE_TEMPLATE",
        path: tpath,
        message: "Template is unreachable (a prior unconditional template catches everything)",
      });
    }
    for (const key of Object.keys(tmpl)) {
      if (!VALID_TEMPLATE_KEYS.has(key)) {
        findings.push({
          level: "error",
          code: "UNKNOWN_TEMPLATE_KEY",
          path: `${tpath}.${key}`,
          message: `Unknown template field: "${key}"`,
        });
      }
    }
    const dec = tmpl.decision;
    if (typeof dec !== "string" || !VALID_DECISIONS.has(dec)) {
      findings.push({
        level: "error",
        code: "INVALID_DECISION",
        path: `${tpath}.decision`,
        message: `Invalid decision ${JSON.stringify(dec)} — must be one of allow / deny / hold / escalate`,
      });
    }
    if (tmpl.when === undefined) {
      seenUnconditional = true;
    } else {
      checkCondition(tmpl.when, `${tpath}.when`, findings);
    }
  }
}

/**
 * Lint a policy's `rules` block. Accepts the wrapping object so the
 * caller can pass either the parsed file directly or just `{ rules }`.
 */
export function lintRules(policy: { rules?: unknown }): LintFinding[] {
  const findings: LintFinding[] = [];
  const rules = policy.rules;

  if (rules === undefined || rules === null) {
    findings.push({
      level: "error",
      code: "MISSING_RULES",
      path: "rules",
      message: 'Missing required "rules" field',
    });
    return findings;
  }

  if (typeof rules !== "object" || Array.isArray(rules)) {
    findings.push({
      level: "error",
      code: "RULES_NOT_OBJECT",
      path: "rules",
      message: '"rules" must be an object',
    });
    return findings;
  }

  const r = rules as Record<string, unknown>;

  for (const key of Object.keys(r)) {
    if (!VALID_TOP_LEVEL_KEYS.has(key)) {
      findings.push({
        level: "error",
        code: "UNKNOWN_TOP_LEVEL_KEY",
        path: `rules.${key}`,
        message: `Unknown rules field: "${key}" (the engine would ignore it)`,
      });
    }
  }

  for (const key of ARRAY_TOP_LEVEL_KEYS) {
    const v = r[key];
    if (v !== undefined && !Array.isArray(v)) {
      findings.push({
        level: "error",
        code: "EXPECTED_ARRAY",
        path: `rules.${key}`,
        message: `"rules.${key}" must be an array`,
      });
    }
  }

  if (r.templates !== undefined) {
    lintTemplates(r.templates, "rules.templates", findings);
  }

  if (r.shadow !== undefined) {
    if (typeof r.shadow !== "object" || Array.isArray(r.shadow)) {
      findings.push({
        level: "error",
        code: "RULES_NOT_OBJECT",
        path: "rules.shadow",
        message: '"rules.shadow" must be an object',
      });
    } else {
      // Recurse: shadow has the same shape as a top-level rules block.
      const shadowFindings = lintRules({ rules: r.shadow });
      for (const f of shadowFindings) {
        findings.push({ ...f, path: f.path.replace(/^rules/, "rules.shadow") });
      }
    }
  }

  return findings;
}

/**
 * Lint the whole policy file (action_type + description + rules).
 * Reuses lintRules for the rules subtree.
 */
export function lintPolicy(policy: Record<string, unknown>): LintFinding[] {
  const findings: LintFinding[] = [];
  if (typeof policy.action_type !== "string" || !policy.action_type) {
    findings.push({
      level: "error",
      code: "MISSING_ACTION_TYPE",
      path: "action_type",
      message: 'Missing required "action_type" string',
    });
  }
  for (const key of Object.keys(policy)) {
    if (!["action_type", "description", "rules"].includes(key)) {
      findings.push({
        level: "error",
        code: "UNKNOWN_POLICY_KEY",
        path: key,
        message: `Unknown policy field: "${key}" (expected action_type, description, rules)`,
      });
    }
  }
  return [...findings, ...lintRules(policy)];
}
