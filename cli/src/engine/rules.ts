// SYNCED COPY — do not edit here. Source of truth: the AtlaSent runtime's packages/sdk/src/rules.ts.
// Change it there; the runtime's CI fails if this copy drifts. Propose engine changes as an issue.
/**
 * AtlaSent Rule Evaluation Engine
 *
 * Zero-dependency, pure-TypeScript rule engine.
 * Canonical source for the **rule engine** (this expression
 * language, its evaluator, type signatures, combinators):
 * `packages/sdk/src/rules.ts`. Copied to
 * `supabase/functions/_shared/rules.ts` during build (enforced by
 * the `rules-sync` CI job).
 *
 * NOT the canonical source for **policy content** (the actual deny
 * rules, action prefixes, resource gates that ship with AtlaSent).
 * Policy content authority lives in
 * the control plane's reference Rego policy (`policies/atlasent/v1/evaluate.rego`) —
 * see ADR-029 (Policy definition authority and sync SLAs) for the
 * full authority + sync-SLA mapping per concept (engine / sentinel
 * rules / conformance vectors / reference templates).
 *
 * Capabilities:
 *   - Actor lists: deny / escalate / hold / allow
 *   - Role lists: deny_roles / escalate_roles / hold_roles / allow_roles
 *   - Rich expression language: eq, neq, gt/gte/lt/lte, in/nin, contains,
 *     startswith, endswith, regex, exists, has_any, has_all, subset_of
 *   - Logical combinators: all, any, none, not (nestable)
 *   - Nested path resolution: actor.roles, context.risk.score, etc.
 *   - M-of-N approvals with role gating, self-approval exclusion, temporal validity
 *   - Change windows + freeze windows (time/day/timezone)
 *   - Rate / budget limits via context-provided counters
 *   - Risk scoring (weighted signals + thresholds)
 *   - Staged rollout (deterministic actor-hash buckets, A/B groups)
 *   - Shadow / dry-run evaluation
 *   - Decision trace ("explain")
 *   - Deterministic fingerprint for caching
 */

export const DECISION_VALUES = ["allow", "deny", "hold", "escalate"] as const;
export type Decision = (typeof DECISION_VALUES)[number];

/** Max characters of a condition value tested against a `regex` operator. See evalCondition. */
const MAX_REGEX_INPUT_LENGTH = 200;
/** Maximum logical-condition nesting accepted by the evaluator. */
const MAX_CONDITION_DEPTH = 32;

export type FailMode = "closed" | "open";

export interface TraceEntry {
  stage: string;
  rule?: string;
  matched: boolean;
  detail?: string;
}

export interface ShadowResult {
  decision: Decision;
  deny_code?: string;
  deny_reason?: string;
  trace?: TraceEntry[];
}

export interface RolloutResult {
  bucket: number;
  group?: string;
  in_canary?: boolean;
}

export interface RuleEvalResult {
  decision: Decision;
  deny_code?: string;
  deny_reason?: string;
  trace?: TraceEntry[];
  risk_score?: number;
  rollout?: RolloutResult;
  shadow?: ShadowResult;
  fingerprint?: string;
  /**
   * The `name` of the template that produced this decision, when the matched
   * template declared one.
   *
   * INTERNAL ONLY — MUST NOT become a field on a caller-facing wire response.
   *
   * CORRECTED after review (#3502). An earlier version of this note claimed
   * template names are policy structure "a caller has no business reading",
   * which overstated the position: `evaluateRules` already puts `tmpl.name`
   * into `trace` entries, and `/v1-evaluate` returns that trace whenever a
   * caller passes `explain: true` and the deny tier is not `oracle_risk`
   * (`handler.ts`'s `exposeTrace`). So template names ALREADY reach callers,
   * deliberately, through a path with its own disclosure tiering.
   *
   * The real contract is narrower and is about not adding a SECOND path. The
   * trace disclosure is CONDITIONAL — opt-in via `explain`, and suppressed
   * entirely for oracle-risk denials. A response field would be
   * UNCONDITIONAL, handing every caller on every call what the existing
   * mechanism releases only under those two conditions, and bypassing the
   * tiering in `handler.ts` that exists precisely to withhold it. ADR-024
   * (deny-disclosure-guard.yml) names scope names as a disclosure risk; that
   * risk is managed today by the tiering, not by secrecy.
   *
   * `matched_template_not_disclosed.test.ts` pins that narrower contract. It
   * does NOT, and should not be read as, making template names secret.
   *
   * WHY IT EXISTS. Nothing in AtlaSent records which rule authorized an
   * action. Runtime's `execution_evaluations` does not carry it (see
   * `_shared/layered-shadow-replay.ts`), the console column that has the name
   * is written by nothing, and this result type had no field for it — so
   * "which policies are actually load-bearing, and which are dead?" has never
   * been answerable on the ENFORCING path. The matched template's name was
   * already computed here; it was only ever put in the opt-in `trace` and
   * thrown away. This surfaces the value that already existed.
   *
   * Absent when no template matched, or when the matched template is unnamed.
   * Never synthesised: an unnamed template yields no value rather than a
   * positional index, because an index is not an identity and would silently
   * re-point when a bundle is reordered.
   */
  matched_template?: string;
}

// ─── Expression language ────────────────────────────────────────────

export interface Condition {
  field?: string;
  // Equality
  eq?: unknown;
  neq?: unknown;
  // Numeric
  gt?: number;
  gte?: number;
  lt?: number;
  lte?: number;
  // Set membership (value in list)
  in?: unknown[];
  nin?: unknown[];
  // String operators
  contains?: string;
  startswith?: string;
  endswith?: string;
  regex?: string;
  regex_flags?: string;
  // Existence
  exists?: boolean;
  // Set operators (value is an array)
  has_any?: unknown[];
  has_all?: unknown[];
  subset_of?: unknown[];
  // Logical (nestable, no field needed)
  not?: Condition;
  all?: Condition[];
  any?: Condition[];
  none?: Condition[];
}

export interface WhenClause {
  all?: Condition[];
  any?: Condition[];
  none?: Condition[];
  not?: Condition;
}

export interface TemplateRule {
  decision: string;
  name?: string;
  when?: WhenClause;
  deny_code?: string;
  deny_reason?: string;
  /**
   * Optional canonical condition-type tag (e.g. "approval_required"). When set,
   * it must be one of the condition_ids in the taxonomy registry
   * (atlasent/contract/taxonomy/v1/condition-types.json). Metadata only — the
   * engine never reads it for matching; it makes policies queryable by the
   * condition they enforce. Validated by scripts/check-condition-tags.mjs.
   */
  condition_id?: string;
}

// ─── Path resolution ────────────────────────────────────────────────

function resolvePath(root: Record<string, unknown>, path: string): unknown {
  if (!path) return undefined;
  const parts = path.split(".");
  let cur: unknown = root;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

function resolveField(field: string, actorId: string, actor: Record<string, unknown>, context: Record<string, unknown>): unknown {
  if (field === "actor_id") return actorId;
  if (field === "actor") return actor;
  if (field === "context") return context;
  if (field.startsWith("context.")) return resolvePath(context, field.slice("context.".length));
  if (field.startsWith("actor.")) return resolvePath(actor, field.slice("actor.".length));
  // Bare field falls back to context for backward compat
  return resolvePath(context, field);
}

// ─── Condition evaluation ───────────────────────────────────────────

function isLogical(cond: Condition): boolean {
  return cond.all !== undefined || cond.any !== undefined || cond.none !== undefined || cond.not !== undefined;
}

/**
 * Inspect every condition tree that the evaluator can execute before
 * fingerprinting or recursive evaluation. Template when-clause wrappers are
 * not themselves conditions, so their all/any/none/not keys do not consume a
 * depth level; this matches validateWhenClause exactly.
 */
function inspectConditionSafety(
  rules: Record<string, unknown>,
  actorId: string,
  actor: Record<string, unknown>,
  context: Record<string, unknown>,
): { tooDeep: boolean; overlongRegexInput: boolean } {
  const roots: unknown[] = [];
  const ruleStack: Record<string, unknown>[] = [rules];
  const seenRules = new Set<object>();

  while (ruleStack.length > 0) {
    const current = ruleStack.pop()!;
    if (seenRules.has(current)) continue;
    seenRules.add(current);

    if (Array.isArray(current.templates)) {
      for (const rawTemplate of current.templates) {
        if (rawTemplate === null || typeof rawTemplate !== "object" || Array.isArray(rawTemplate)) continue;
        const when = (rawTemplate as Record<string, unknown>).when;
        if (when === null || typeof when !== "object" || Array.isArray(when)) continue;
        const whenObject = when as Record<string, unknown>;
        for (const key of ["all", "any", "none"] as const) {
          if (Array.isArray(whenObject[key])) roots.push(...whenObject[key]);
        }
        if ("not" in whenObject) roots.push(whenObject.not);
      }
    }

    const risk = current.risk;
    if (risk !== null && typeof risk === "object" && !Array.isArray(risk)) {
      const signals = (risk as Record<string, unknown>).signals;
      if (Array.isArray(signals)) {
        for (const rawSignal of signals) {
          if (rawSignal !== null && typeof rawSignal === "object" && !Array.isArray(rawSignal)) {
            const signal = rawSignal as Record<string, unknown>;
            if ("when" in signal) roots.push(signal.when);
          }
        }
      }
    }

    // Deliberately do not descend into current.shadow. evaluateWithShadow
    // evaluates that ruleset in a separate evaluateRules call; inspecting it
    // here would let an observational shadow failure bind the primary result.
  }

  const stack = roots.map((value) => ({ value, depth: 0 }));
  const seenConditions = new Map<object, number>();

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.depth > MAX_CONDITION_DEPTH) {
      return { tooDeep: true, overlongRegexInput: false };
    }
    if (current.value === null || typeof current.value !== "object" || Array.isArray(current.value)) continue;

    const conditionObject = current.value as Record<string, unknown>;
    const priorDepth = seenConditions.get(conditionObject);
    if (priorDepth !== undefined && priorDepth >= current.depth) continue;
    seenConditions.set(conditionObject, current.depth);

    if (typeof conditionObject.regex === "string" && typeof conditionObject.field === "string") {
      const value = resolveField(conditionObject.field, actorId, actor, context);
      if (typeof value === "string" && value.length > MAX_REGEX_INPUT_LENGTH) {
        return { tooDeep: false, overlongRegexInput: true };
      }
    }

    for (const key of ["all", "any", "none"] as const) {
      const children = conditionObject[key];
      if (Array.isArray(children)) {
        for (const child of children) stack.push({ value: child, depth: current.depth + 1 });
      }
    }
    if ("not" in conditionObject) stack.push({ value: conditionObject.not, depth: current.depth + 1 });
  }

  return { tooDeep: false, overlongRegexInput: false };
}

function evalCondition(
  cond: Condition,
  actorId: string,
  actor: Record<string, unknown>,
  context: Record<string, unknown>,
): boolean {
  // Logical combinators (no field needed). Excessive depth is rejected for
  // the whole evaluation by inspectConditionSafety before this recursion
  // starts, so no local false sentinel can be inverted by not/none.
  if (cond.not !== undefined) return !evalCondition(cond.not, actorId, actor, context);
  if (cond.all !== undefined) return cond.all.every((c) => evalCondition(c, actorId, actor, context));
  if (cond.any !== undefined) return cond.any.some((c) => evalCondition(c, actorId, actor, context));
  if (cond.none !== undefined) return !cond.none.some((c) => evalCondition(c, actorId, actor, context));

  // Fail-closed: a non-logical condition without a `field` has nothing to
  // check and must not silently satisfy a template guard.
  if (!cond.field) return false;
  const value = resolveField(cond.field, actorId, actor, context);

  if (cond.exists !== undefined) {
    const present = value !== undefined && value !== null;
    return cond.exists ? present : !present;
  }
  if (cond.eq !== undefined) return value === cond.eq;
  if (cond.neq !== undefined) return value !== cond.neq;
  if (cond.gt !== undefined) return typeof value === "number" ? value > cond.gt : Number(value) > cond.gt;
  if (cond.gte !== undefined) return typeof value === "number" ? value >= cond.gte : Number(value) >= cond.gte;
  if (cond.lt !== undefined) return typeof value === "number" ? value < cond.lt : Number(value) < cond.lt;
  if (cond.lte !== undefined) return typeof value === "number" ? value <= cond.lte : Number(value) <= cond.lte;
  if (cond.in !== undefined) return Array.isArray(cond.in) && cond.in.includes(value as never);
  if (cond.nin !== undefined) return Array.isArray(cond.nin) && !cond.nin.includes(value as never);
  if (cond.contains !== undefined) {
    if (typeof value === "string") return value.includes(cond.contains);
    if (Array.isArray(value)) return value.includes(cond.contains as never);
    return false;
  }
  if (cond.startswith !== undefined) return typeof value === "string" && value.startsWith(cond.startswith);
  if (cond.endswith !== undefined) return typeof value === "string" && value.endsWith(cond.endswith);
  if (cond.regex !== undefined) {
    if (typeof value !== "string") return false;
    try {
      // Bound worst-case backtracking cost (atlasent-api#2906). Never truncate:
      // truncation changes the value being authorized and can turn an anchored
      // non-match into a match (for example, "^a+$" against 200 "a" characters
      // followed by "!"). Values beyond the policy limit fail closed.
      if (value.length > MAX_REGEX_INPUT_LENGTH) return false;
      return new RegExp(cond.regex, cond.regex_flags).test(value);
    } catch {
      return false;
    }
  }
  if (cond.has_any !== undefined) {
    if (!Array.isArray(value)) return false;
    return cond.has_any.some((x) => (value as unknown[]).includes(x));
  }
  if (cond.has_all !== undefined) {
    if (!Array.isArray(value)) return false;
    return cond.has_all.every((x) => (value as unknown[]).includes(x));
  }
  if (cond.subset_of !== undefined) {
    const subsetOf = cond.subset_of;
    if (!Array.isArray(value)) return false;
    return (value as unknown[]).every((x) => subsetOf.includes(x));
  }
  // Fail-closed: if no recognized operator matched, the condition is
  // malformed; refuse to treat it as satisfied.
  return false;
}

function evalWhen(
  when: WhenClause,
  actorId: string,
  actor: Record<string, unknown>,
  context: Record<string, unknown>,
): boolean {
  if (when.all && !when.all.every((c) => evalCondition(c, actorId, actor, context))) return false;
  if (when.any && !when.any.some((c) => evalCondition(c, actorId, actor, context))) return false;
  if (when.none && when.none.some((c) => evalCondition(c, actorId, actor, context))) return false;
  if (when.not && evalCondition(when.not, actorId, actor, context)) return false;
  return true;
}

// ─── Hashing (zero-dep, deterministic, sync) ────────────────────────

/** FNV-1a 32-bit hash. Fast, deterministic, good for bucketing. */
export function fnv1a(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/** Canonical JSON: sorted keys, stable across runtimes. */
export function canonicalJSON(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
  }
  return "null";
}

/** Stable fingerprint of a value, suitable for cache keys. */
export function fingerprint(value: unknown): string {
  return fnv1a(canonicalJSON(value)).toString(16).padStart(8, "0");
}

// ─── Time windows ───────────────────────────────────────────────────

export interface TimeWindow {
  name?: string;
  timezone?: string;                            // IANA TZ; default UTC
  days_of_week?: number[];                      // 0=Sun .. 6=Sat
  hours?: { start: string; end: string };       // "HH:MM" 24h
  date_ranges?: { start: string; end: string }[]; // ISO date strings
}

interface ZonedParts { y: number; mo: number; d: number; h: number; mi: number; dow: number }

function zonedParts(now: Date, tz: string): ZonedParts {
  // Use Intl to get date parts in the target timezone. Fall back to UTC if unknown.
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat("en-US", {
      timeZone: tz || "UTC",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
      weekday: "short",
    }).formatToParts(now);
  } catch {
    parts = new Intl.DateTimeFormat("en-US", {
      timeZone: "UTC",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
      weekday: "short",
    }).formatToParts(now);
  }
  const map: Record<string, string> = {};
  for (const p of parts) map[p.type] = p.value;
  const dowMap: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return {
    y: Number(map.year),
    mo: Number(map.month),
    d: Number(map.day),
    h: Number(map.hour === "24" ? "0" : map.hour),
    mi: Number(map.minute),
    dow: dowMap[map.weekday] ?? 0,
  };
}

function parseHM(hm: string): { h: number; m: number } | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(hm);
  if (!m) return null;
  return { h: Number(m[1]), m: Number(m[2]) };
}

export function inWindow(win: TimeWindow, now: Date): boolean {
  const tz = win.timezone || "UTC";
  const parts = zonedParts(now, tz);

  if (win.days_of_week && win.days_of_week.length > 0) {
    if (!win.days_of_week.includes(parts.dow)) return false;
  }

  if (win.hours) {
    const start = parseHM(win.hours.start);
    const end = parseHM(win.hours.end);
    if (start && end) {
      const cur = parts.h * 60 + parts.mi;
      const s = start.h * 60 + start.m;
      const e = end.h * 60 + end.m;
      // Support windows that wrap midnight (e.g., 22:00 - 06:00)
      const inHours = s <= e ? cur >= s && cur < e : cur >= s || cur < e;
      if (!inHours) return false;
    }
  }

  if (win.date_ranges && win.date_ranges.length > 0) {
    const today = `${parts.y}-${String(parts.mo).padStart(2, "0")}-${String(parts.d).padStart(2, "0")}`;
    const matched = win.date_ranges.some((r) => today >= r.start && today <= r.end);
    if (!matched) return false;
  }

  return true;
}

// ─── Approvals (M-of-N + role-gated + temporal) ─────────────────────

export interface Approver {
  id: string;
  role?: string;
  timestamp?: string; // ISO
}

export interface ApprovalPolicy {
  count?: number;                                          // minimum total approvals
  required_roles?: { role: string; count: number }[];      // M-of-N per role
  // Requester can't approve own request. SAFE BY DEFAULT (B1, internal
  // architecture hardening review, 2026-08-25): true unless explicitly set to
  // `false`. Before this, an unset field was silently permissive — a caller
  // could satisfy any object-form approval policy with a single self-declared
  // approver id. Set `false` only when self-approval is a deliberate, reviewed
  // choice for that specific policy.
  exclude_actor?: boolean;
  max_age_seconds?: number;                                // approvals must be recent
  // De-dupe approvers by id. SAFE BY DEFAULT for the same reason as
  // exclude_actor above: true unless explicitly set to `false`.
  unique_approvers?: boolean;
}

interface ApprovalsResult { ok: boolean; deny_code?: string; deny_reason?: string }

function evalApprovals(
  policy: ApprovalPolicy | number,
  actorId: string,
  context: Record<string, unknown>,
  now: Date,
): ApprovalsResult {
  // Backward-compat: numeric require_approvals counts context.approvals
  if (typeof policy === "number") {
    const approvals = Number(context.approvals ?? 0);
    if (approvals < policy) {
      return {
        ok: false,
        deny_code: "INSUFFICIENT_APPROVALS",
        deny_reason: `Requires ${policy} approvals, got ${approvals}`,
      };
    }
    return { ok: true };
  }

  const raw = (context.approvers as unknown) ?? [];
  const approvers: Approver[] = Array.isArray(raw)
    ? (raw.filter((a) => a && typeof a === "object") as Approver[])
    : [];

  let valid = approvers;

  // SAFE BY DEFAULT (B1, internal architecture hardening review,
  // 2026-08-25): both checks below now run unless explicitly disabled with
  // `false`. An absent/undefined flag used to skip the check entirely —
  // meaning a caller could satisfy any object-form require_approvals policy
  // with a single self-declared, duplicated approver id and no platform
  // verification of any kind, unless the policy author remembered to opt in
  // to both flags. `!== false` (not `=== true`) is the load-bearing change.
  if (policy.exclude_actor !== false) {
    valid = valid.filter((a) => a.id !== actorId);
  }
  if (policy.unique_approvers !== false) {
    const seen = new Set<string>();
    valid = valid.filter((a) => (seen.has(a.id) ? false : (seen.add(a.id), true)));
  }
  if (policy.max_age_seconds && policy.max_age_seconds > 0) {
    const cutoff = now.getTime() - policy.max_age_seconds * 1000;
    valid = valid.filter((a) => {
      if (!a.timestamp) return false;
      const t = Date.parse(a.timestamp);
      return Number.isFinite(t) && t >= cutoff;
    });
  }

  if (typeof policy.count === "number" && valid.length < policy.count) {
    return {
      ok: false,
      deny_code: "INSUFFICIENT_APPROVALS",
      deny_reason: `Requires ${policy.count} approvals, got ${valid.length}`,
    };
  }

  if (policy.required_roles) {
    for (const req of policy.required_roles) {
      const matchCount = valid.filter((a) => a.role === req.role).length;
      if (matchCount < req.count) {
        return {
          ok: false,
          deny_code: "INSUFFICIENT_ROLE_APPROVALS",
          deny_reason: `Requires ${req.count} approvals from role '${req.role}', got ${matchCount}`,
        };
      }
    }
  }

  return { ok: true };
}

// ─── Risk scoring ───────────────────────────────────────────────────

export interface RiskSignal {
  field?: string;          // pull a numeric value, multiplied by weight
  when?: Condition;        // OR: condition that contributes weight when true
  weight: number;
  name?: string;
}

export interface RiskPolicy {
  signals: RiskSignal[];
  thresholds?: {
    deny_gte?: number;
    escalate_gte?: number;
    hold_gte?: number;
  };
}

/**
 * Computes a weighted risk score for one evaluation.
 *
 * This is the F07 ("Risk / Pressure / System Modes" patent claim)
 * embodiment for *reproducible* risk scoring — this doc comment is the
 * full, precise specification of the algorithm, and the determinism
 * claimed below is enforced mechanically, not just asserted: this file is
 * one of the two files (`packages/sdk/src/rules.ts` and its build-time
 * mirror `supabase/functions/_shared/rules.ts`) statically scanned by
 * `packages/sdk/scripts/check-policy-determinism.mjs` (ADR-015 §5), which
 * forbids wall-clock reads, RNG, and I/O anywhere in this module.
 *
 * ── Purity contract ──
 * `computeRiskScore` is a pure function of its four scoring arguments —
 * `(policy, actorId, actor, context)`. Given identical arguments it
 * returns an identical number on every call, in this process or any
 * other, forever. Concretely:
 *   - no I/O (no network calls, no database reads)
 *   - no wall-clock reads (no querying the system clock or timers)
 *   - no randomness (no RNG, no UUID generation)
 *   - no reads of module-level or global mutable state
 * The optional `trace` parameter is the one apparent exception: when
 * supplied, matched signals are appended to it for explainability. This is
 * an output sink, not an input — passing a `trace` array never changes the
 * returned score, and omitting it never changes which signals matched or
 * what score they produce. `evalCondition` and `resolveField` (the two
 * helpers this function delegates to for condition matching and dotted-path
 * field lookup) are themselves pure for the same reasons.
 *
 * ── Algorithm ──
 * The score starts at 0 and is a **weighted sum over `policy.signals`**.
 * Each signal contributes independently, based on which of its two mutually
 * exclusive shapes it declares:
 *
 *   1. **Condition-matched signal** (`signal.when` is set): contributes its
 *      full flat `signal.weight` if and only if `when` evaluates to `true`
 *      against `(actorId, actor, context)` via this engine's `Condition`
 *      evaluator (`evalCondition`) — the identical evaluator used for
 *      `deny`/`hold`/`escalate` template guards elsewhere in this file. A
 *      non-matching condition contributes 0. `when` takes priority over
 *      `field` if a signal author sets both.
 *
 *   2. **Field-based signal** (`signal.field` is set, `signal.when` is not):
 *      contributes `field_value * signal.weight`, where `field_value` is
 *      resolved from `signal.field` via `resolveField` (the same
 *      dotted-path resolver `Condition.field` uses — e.g.
 *      `"context.failure_count"`, `"actor.tenure_days"`) and coerced with
 *      `Number(...)` when not already a `number`. If the resolved value is
 *      not finite per `Number.isFinite` (missing, `undefined`, `NaN`,
 *      `Infinity`, or a non-numeric string) the signal is skipped entirely
 *      — it contributes 0 and is silently omitted, rather than being
 *      treated as a `0 * weight` contribution that would still appear in
 *      the trace.
 *
 *   A signal with neither `when` nor `field` set is inert and contributes 0.
 *
 * The return value is the plain arithmetic sum of every signal's
 * contribution — **no normalization, clamping, or [0, 1] banding happens
 * here.** A policy author's `thresholds.{deny_gte,escalate_gte,hold_gte}`
 * (see `RiskPolicy`) are compared directly against this raw sum, in
 * whatever units the policy's own weights were authored in. Downstream
 * consumers that need a bounded [0, 1] score for
 * `CanonicalDecisionObject.riskScore` — which does enforce `[0, 1]` and
 * throws on values outside it, see `_shared/cdo.ts`'s `riskLevelFromScore`
 * — clamp this raw value themselves; the live path for that is
 * `_shared/risk-envelope.ts`'s
 * `computeRiskEnvelope`, which folds the engine's raw `risk_score` in via
 * `Math.max(0, Math.min(1, engineResult.risk_score))` before it ever
 * contributes to `weightedScore`. That clamp intentionally does not live in
 * this function, so a policy author's raw, un-banded score stays legible
 * against the thresholds they wrote it against.
 *
 * @param policy - The risk policy: `signals` (scored per the algorithm
 *   above) plus optional `thresholds` (compared by the caller, not here).
 * @param actorId - The evaluating actor's id — same value `Condition` /
 *   `resolveField` resolve as the bare `"actor_id"` field.
 * @param actor - The actor record — same value resolved for `"actor.*"`
 *   fields.
 * @param context - The evaluation context — same value resolved for
 *   `"context.*"` fields (and the fallback for a bare, unprefixed field).
 * @param trace - Optional explain-mode sink; entries are appended, never
 *   read. Does not affect the returned score (see "Purity contract").
 * @returns The raw weighted-sum risk score. Deterministic and reproducible
 *   from the four scoring arguments; not bounded to [0, 1].
 */
export function computeRiskScore(
  policy: RiskPolicy,
  actorId: string,
  actor: Record<string, unknown>,
  context: Record<string, unknown>,
  trace?: TraceEntry[],
): number {
  let score = 0;
  for (const sig of policy.signals) {
    if (sig.when) {
      const matched = evalCondition(sig.when, actorId, actor, context);
      if (matched) {
        score += sig.weight;
        trace?.push({ stage: "risk", rule: sig.name ?? "signal", matched: true, detail: `+${sig.weight}` });
      }
      continue;
    }
    if (sig.field) {
      const v = resolveField(sig.field, actorId, actor, context);
      const n = typeof v === "number" ? v : Number(v);
      if (Number.isFinite(n)) {
        const contribution = n * sig.weight;
        score += contribution;
        trace?.push({ stage: "risk", rule: sig.name ?? sig.field, matched: true, detail: `+${contribution}` });
      }
    }
  }
  return score;
}

/**
 * Alias for {@link computeRiskScore} matching the `scoreRisk()` vocabulary
 * used by the F07 patent attorney-briefing doc
 * (`atlasent-legal/patents/attorney-package/06-attorney-briefing-and-defensibility.md`
 * §4). Same function, same reference — kept as a `const` alias rather than
 * a rename so existing call sites and tests referencing `computeRiskScore`
 * (the name already used throughout this file, `v1-evaluate/handler.ts`,
 * and `risk-envelope.ts`'s doc comments) are undisturbed. Cite either name;
 * they are guaranteed identical by construction, not by convention.
 */
export const scoreRisk = computeRiskScore;

// ─── Rollout (canary % via deterministic actor hash) ────────────────

export interface RolloutGroup {
  name: string;
  actors?: string[];
  roles?: string[];
}

export interface RolloutPolicy {
  percentage?: number; // 0..100 — actor is in canary if hash bucket < percentage
  seed?: string;
  groups?: RolloutGroup[];
}

function computeRollout(policy: RolloutPolicy, actorId: string, actor: Record<string, unknown>): RolloutResult {
  const seed = policy.seed ?? "atlasent";
  const bucket = fnv1a(`${seed}:${actorId}`) % 100;
  const result: RolloutResult = { bucket };

  if (policy.groups) {
    const roles = Array.isArray(actor.roles) ? (actor.roles as string[]) : [];
    for (const g of policy.groups) {
      if (g.actors && g.actors.includes(actorId)) { result.group = g.name; break; }
      if (g.roles && g.roles.some((r) => roles.includes(r))) { result.group = g.name; break; }
    }
  }

  if (typeof policy.percentage === "number") {
    result.in_canary = bucket < Math.max(0, Math.min(100, policy.percentage));
  }
  return result;
}

// ─── Rate / budget limits ───────────────────────────────────────────

export interface RateLimit {
  name?: string;
  scope?: "actor" | "global";
  counter_field: string;     // path inside context, e.g., "rate.actor_deploys_1h"
  max: number;
  decision?: Decision;       // default: deny
  deny_code?: string;
  deny_reason?: string;
}

interface RateResult { ok: boolean; decision?: Decision; deny_code?: string; deny_reason?: string }

function evalRateLimits(
  limits: RateLimit[],
  actorId: string,
  actor: Record<string, unknown>,
  context: Record<string, unknown>,
  trace?: TraceEntry[],
): RateResult {
  for (const lim of limits) {
    const v = resolveField(lim.counter_field, actorId, actor, context);
    const n = typeof v === "number" ? v : Number(v);
    if (!Number.isFinite(n)) {
      trace?.push({ stage: "rate_limit", rule: lim.name ?? lim.counter_field, matched: false, detail: "counter missing" });
      continue;
    }
    trace?.push({ stage: "rate_limit", rule: lim.name ?? lim.counter_field, matched: n >= lim.max, detail: `${n}/${lim.max}` });
    if (n >= lim.max) {
      return {
        ok: false,
        decision: lim.decision ?? "deny",
        deny_code: lim.deny_code ?? "RATE_LIMIT_EXCEEDED",
        deny_reason: lim.deny_reason ?? `Rate limit exceeded for ${lim.counter_field}: ${n}/${lim.max}`,
      };
    }
  }
  return { ok: true };
}

// ─── Top-level rules shape ──────────────────────────────────────────

export interface Rules {
  // Actor lists (literal IDs)
  deny_actors?: string[];
  escalate_actors?: string[];
  hold_actors?: string[];
  allow_actors?: string[];

  // Role lists (resolved against actor.roles)
  deny_roles?: string[];
  escalate_roles?: string[];
  hold_roles?: string[];
  allow_roles?: string[];

  // Approvals — number for backward-compat, or full policy
  require_approvals?: number | ApprovalPolicy;

  // Time windows
  change_window?: TimeWindow;        // require evaluation to fall inside
  freeze_windows?: TimeWindow[];     // deny if inside any

  // Rate / budget
  rate_limits?: RateLimit[];

  // Risk
  risk?: RiskPolicy;

  // Rollout
  rollout?: RolloutPolicy;

  // Templates (rich expressions)
  templates?: TemplateRule[];

  // Shadow ruleset — evaluated in parallel, never affects decision
  shadow?: Rules;

  // Top-level decision override — simplified bundles may specify the outcome directly
  decision?: "allow" | "deny" | "hold" | "escalate";
  deny_code?: string;
  deny_reason?: string;
}

export interface EvaluateOptions {
  failMode?: FailMode;
  /** Collect a step-by-step trace in the result. */
  explain?: boolean;
  /** Override the wall clock (deterministic tests, replay). */
  now?: Date;
  /** Treat this evaluation as shadow/dry-run. Surfaces in trace. */
  shadow?: boolean;
  /** Skip evaluating the embedded shadow ruleset (avoid infinite recursion). */
  skipShadow?: boolean;
}

function actorFromContext(context: Record<string, unknown>): Record<string, unknown> {
  const a = context.actor;
  if (a && typeof a === "object" && !Array.isArray(a)) return a as Record<string, unknown>;
  return {};
}

function rolesOf(actor: Record<string, unknown>): string[] {
  const r = actor.roles;
  return Array.isArray(r) ? (r as string[]) : [];
}

function intersects(a: string[], b: string[]): boolean {
  return a.some((x) => b.includes(x));
}

// Supports exact match and prefix-wildcard patterns (e.g. "github:*" matches any "github:…" actor).
function matchesActorPattern(pattern: string, actorId: string): boolean {
  if (pattern.endsWith(":*")) return actorId.startsWith(pattern.slice(0, -1));
  return pattern === actorId;
}

function denyResult(code: string, reason: string, trace?: TraceEntry[]): RuleEvalResult {
  return trace ? { decision: "deny", deny_code: code, deny_reason: reason, trace } : { decision: "deny", deny_code: code, deny_reason: reason };
}

// ─── Main evaluator ─────────────────────────────────────────────────

export function evaluateRules(
  rules: Rules | Record<string, unknown> | null | undefined,
  actorId: string,
  context: Record<string, unknown> | undefined,
  failModeOrOptions: FailMode | EvaluateOptions = "closed",
): RuleEvalResult {
  const opts: EvaluateOptions = typeof failModeOrOptions === "string"
    ? { failMode: failModeOrOptions }
    : { failMode: "closed", ...failModeOrOptions };

  const failMode: FailMode = opts.failMode ?? "closed";
  const trace: TraceEntry[] | undefined = opts.explain ? [] : undefined;
  // atlasent-determinism-allow: defensive fallback when opts.now is omitted by
  // a caller. Production callers (v1-evaluate handler) always pass opts.now from
  // context.now, so this branch is unreachable for replay-relevant evaluations.
  // ADR-015 §5 — replay determinism requires opts.now to be supplied; replay
  // harness asserts this and treats a missing opts.now as a vector-author bug.
  const now = opts.now ?? new Date();

  const ctx = context ?? {};
  const actor = actorFromContext(ctx);
  const roles = rolesOf(actor);

  // Reject unsafe condition input before recursive evaluation or canonical
  // fingerprinting. These are evaluation-wide failures: treating one unsafe
  // predicate as an ordinary false can be inverted by `not` or skipped by a
  // deny-template followed by an allow-template.
  if (rules) {
    const safety = inspectConditionSafety(rules as Record<string, unknown>, actorId, actor, ctx);
    if (safety.tooDeep) {
      return denyResult("RULES_TOO_DEEP", `Policy conditions exceed the maximum nesting depth of ${MAX_CONDITION_DEPTH}`, trace);
    }
    if (safety.overlongRegexInput) {
      return denyResult("REGEX_INPUT_TOO_LONG", `Regex input exceeds the maximum length of ${MAX_REGEX_INPUT_LENGTH}`, trace);
    }
  }

  // Compute fingerprint over inputs (excluding the time component, so cache hits are stable per input set)
  const fp = fingerprint({ actorId, ctx, rules: rules ?? null });

  if (!rules || (typeof rules === "object" && Object.keys(rules).length === 0)) {
    if (failMode === "closed") {
      const res = denyResult("NO_RULES", "No published constraint bundle and fail_mode is closed", trace);
      res.fingerprint = fp;
      trace?.push({ stage: "fail_mode", matched: true, detail: "closed → deny" });
      return res;
    }
    trace?.push({ stage: "fail_mode", matched: true, detail: "open → allow" });
    return trace ? { decision: "allow", trace, fingerprint: fp } : { decision: "allow", fingerprint: fp };
  }

  const r = rules as Rules;

  // ── Top-level decision override ──
  // Simplified bundles may specify a bare `decision` field (e.g. { decision: "deny" })
  // without any actor/role lists. Honour it directly before the actor-level checks.
  if (typeof r.decision === "string" && r.decision !== "allow") {
    const overrideDecision = r.decision as "deny" | "hold" | "escalate";
    const code = (r.deny_code as string) ?? (
      overrideDecision === "deny" ? "POLICY_DENY" :
      overrideDecision === "hold" ? "ACTOR_HELD" : "ACTOR_ESCALATED"
    );
    const reason = (r.deny_reason as string) ?? `${overrideDecision} by policy`;
    trace?.push({ stage: "decision_override", matched: true, detail: overrideDecision });
    if (overrideDecision === "hold" || overrideDecision === "escalate") {
      return { decision: overrideDecision, deny_code: code, deny_reason: reason, trace, fingerprint: fp };
    }
    const res = denyResult(code, reason, trace);
    res.fingerprint = fp;
    return res;
  }

  // ── Actor lists ──
  // deny/escalate/hold entries support the same exact-or-":*"-prefix matching
  // as allow_actors (matchesActorPattern) — a bundle author writing
  // `deny_actors: ["untrusted-bot:*"]` expects it to block the whole actor
  // class, not silently match nothing because no real actor_id is the literal
  // string "untrusted-bot:*".
  if (Array.isArray(r.deny_actors) && r.deny_actors.some((p) => matchesActorPattern(p, actorId))) {
    trace?.push({ stage: "deny_actors", matched: true });
    const res = denyResult("ACTOR_BLOCKED", "Actor is on deny list", trace);
    res.fingerprint = fp;
    return res;
  }
  if (Array.isArray(r.deny_roles) && intersects(r.deny_roles, roles)) {
    trace?.push({ stage: "deny_roles", matched: true, detail: roles.join(",") });
    const res = denyResult("ROLE_BLOCKED", "Actor role is on deny list", trace);
    res.fingerprint = fp;
    return res;
  }

  if (Array.isArray(r.escalate_actors) && r.escalate_actors.some((p) => matchesActorPattern(p, actorId))) {
    trace?.push({ stage: "escalate_actors", matched: true });
    return { decision: "escalate", deny_code: "ACTOR_ESCALATED", deny_reason: "Actor requires escalation review", trace, fingerprint: fp };
  }
  if (Array.isArray(r.escalate_roles) && intersects(r.escalate_roles, roles)) {
    trace?.push({ stage: "escalate_roles", matched: true });
    return { decision: "escalate", deny_code: "ROLE_ESCALATED", deny_reason: "Actor role requires escalation review", trace, fingerprint: fp };
  }

  if (Array.isArray(r.hold_actors) && r.hold_actors.some((p) => matchesActorPattern(p, actorId))) {
    trace?.push({ stage: "hold_actors", matched: true });
    return { decision: "hold", deny_code: "ACTOR_HELD", deny_reason: "Actor requires manual review", trace, fingerprint: fp };
  }
  if (Array.isArray(r.hold_roles) && intersects(r.hold_roles, roles)) {
    trace?.push({ stage: "hold_roles", matched: true });
    return { decision: "hold", deny_code: "ROLE_HELD", deny_reason: "Actor role requires manual review", trace, fingerprint: fp };
  }

  if (Array.isArray(r.allow_actors) && !r.allow_actors.some(p => matchesActorPattern(p, actorId))) {
    trace?.push({ stage: "allow_actors", matched: false });
    const res = denyResult("ACTOR_NOT_ALLOWED", "Actor not on allow list", trace);
    res.fingerprint = fp;
    return res;
  }
  if (Array.isArray(r.allow_roles) && r.allow_roles.length > 0 && !intersects(r.allow_roles, roles)) {
    trace?.push({ stage: "allow_roles", matched: false });
    const res = denyResult("ROLE_NOT_ALLOWED", "Actor role not on allow list", trace);
    res.fingerprint = fp;
    return res;
  }

  // ── Freeze windows (any match → deny) ──
  if (Array.isArray(r.freeze_windows)) {
    for (const fw of r.freeze_windows) {
      if (inWindow(fw, now)) {
        trace?.push({ stage: "freeze_window", rule: fw.name ?? "freeze", matched: true });
        const res = denyResult("FROZEN", `Inside freeze window${fw.name ? ` '${fw.name}'` : ""}`, trace);
        res.fingerprint = fp;
        return res;
      }
    }
  }

  // ── Change window (must match) ──
  if (r.change_window) {
    if (!inWindow(r.change_window, now)) {
      trace?.push({ stage: "change_window", matched: false });
      const res = denyResult("OUTSIDE_CHANGE_WINDOW", "Outside permitted change window", trace);
      res.fingerprint = fp;
      return res;
    }
    trace?.push({ stage: "change_window", matched: true });
  }

  // ── Rate limits ──
  if (Array.isArray(r.rate_limits) && r.rate_limits.length > 0) {
    const rate = evalRateLimits(r.rate_limits, actorId, actor, ctx, trace);
    if (!rate.ok) {
      const res: RuleEvalResult = {
        decision: rate.decision ?? "deny",
        deny_code: rate.deny_code,
        deny_reason: rate.deny_reason,
        fingerprint: fp,
      };
      if (trace) res.trace = trace;
      return res;
    }
  }

  // ── Approvals ──
  if (r.require_approvals !== undefined) {
    const ap = evalApprovals(r.require_approvals, actorId, ctx, now);
    trace?.push({ stage: "approvals", matched: ap.ok, detail: ap.deny_reason });
    if (!ap.ok) {
      const res = denyResult(ap.deny_code!, ap.deny_reason!, trace);
      res.fingerprint = fp;
      return res;
    }
  }

  // ── Risk scoring ──
  let riskScore: number | undefined;
  if (r.risk && Array.isArray(r.risk.signals) && r.risk.signals.length > 0) {
    riskScore = computeRiskScore(r.risk, actorId, actor, ctx, trace);
    const t = r.risk.thresholds;
    if (t) {
      if (typeof t.deny_gte === "number" && riskScore >= t.deny_gte) {
        const res = denyResult("RISK_DENY", `Risk score ${riskScore} >= deny threshold ${t.deny_gte}`, trace);
        res.fingerprint = fp;
        res.risk_score = riskScore;
        return res;
      }
      if (typeof t.escalate_gte === "number" && riskScore >= t.escalate_gte) {
        return { decision: "escalate", deny_code: "RISK_ESCALATE", deny_reason: `Risk score ${riskScore} >= escalate threshold ${t.escalate_gte}`, trace, fingerprint: fp, risk_score: riskScore };
      }
      if (typeof t.hold_gte === "number" && riskScore >= t.hold_gte) {
        return { decision: "hold", deny_code: "RISK_HOLD", deny_reason: `Risk score ${riskScore} >= hold threshold ${t.hold_gte}`, trace, fingerprint: fp, risk_score: riskScore };
      }
    }
  }

  // ── Rollout (computed but does not block; surfaced in result) ──
  let rollout: RolloutResult | undefined;
  if (r.rollout) {
    rollout = computeRollout(r.rollout, actorId, actor);
    trace?.push({ stage: "rollout", matched: !!rollout.in_canary, detail: `bucket=${rollout.bucket} group=${rollout.group ?? "-"}` });
  }

  // ── Templates ──
  if (Array.isArray(r.templates)) {
    for (const tmpl of r.templates as TemplateRule[]) {
      // Carry deny_code / deny_reason from the template through to the
      // decision so callers can distinguish multiple matches that share
      // the same `decision` (e.g. several `escalate` tiers signalling
      // different approval queues via deny_code).
      const base: RuleEvalResult = { decision: tmpl.decision as Decision };
      if (tmpl.deny_code !== undefined) base.deny_code = tmpl.deny_code;
      if (tmpl.deny_reason !== undefined) base.deny_reason = tmpl.deny_reason;
      // Carried only on the two paths below that actually RETURN this base —
      // a non-matching template `continue`s and its base is discarded, so a
      // template that was merely considered never claims the decision.
      //
      // `typeof === "string"` rather than `!== undefined` (Copilot review,
      // #3502): `evaluateRules` accepts `Record<string, unknown>` and casts
      // each entry to TemplateRule, and NOTHING anywhere type-checks
      // `tmpl.name` — there is no template validator in this engine. A stored
      // or directly-supplied bundle carrying `name: null`, or
      // `name: { leaked: true }`, would otherwise put a non-string into a
      // field declared `string`, breaking the attribution contract for every
      // consumer downstream and silently violating this field's own
      // documented "absent for an unnamed template" rule.
      if (typeof tmpl.name === "string") base.matched_template = tmpl.name;

      if (!tmpl.when) {
        if (DECISION_VALUES.includes(tmpl.decision as Decision)) {
          trace?.push({ stage: "template", rule: tmpl.name ?? tmpl.decision, matched: true, detail: "unconditional" });
          return finalize(base, trace, fp, riskScore, rollout);
        }
        continue;
      }
      const matched = evalWhen(tmpl.when, actorId, actor, ctx);
      trace?.push({ stage: "template", rule: tmpl.name ?? tmpl.decision, matched });
      if (matched && DECISION_VALUES.includes(tmpl.decision as Decision)) {
        return finalize(base, trace, fp, riskScore, rollout);
      }
    }
    return finalize(denyResult("NO_TEMPLATE_MATCH", "No template condition matched"), trace, fp, riskScore, rollout);
  }

  return finalize({ decision: "allow" }, trace, fp, riskScore, rollout);
}

function finalize(
  base: RuleEvalResult,
  trace: TraceEntry[] | undefined,
  fp: string,
  risk: number | undefined,
  rollout: RolloutResult | undefined,
): RuleEvalResult {
  const out: RuleEvalResult = { ...base, fingerprint: fp };
  if (trace) out.trace = trace;
  if (risk !== undefined) out.risk_score = risk;
  if (rollout) out.rollout = rollout;
  return out;
}

/**
 * Evaluate a ruleset and (optionally) a shadow ruleset side-by-side.
 * The primary decision is binding; the shadow result is observational only.
 */
export function evaluateWithShadow(
  rules: Rules | Record<string, unknown> | null | undefined,
  actorId: string,
  context: Record<string, unknown> | undefined,
  options: EvaluateOptions = {},
): RuleEvalResult {
  // Shadow content is observational and must not participate in the binding
  // decision or its fingerprint. Detach it before primary evaluation so even
  // pathological unvalidated shadow structure cannot exhaust canonicalJSON
  // and turn a shadow-only failure into a binding POLICY_ENGINE_ERROR denial.
  const rulesObject = rules && typeof rules === "object" ? rules as Rules : undefined;
  const shadowRules = rulesObject?.shadow;
  const primaryRules = rulesObject
    ? Object.fromEntries(Object.entries(rulesObject).filter(([key]) => key !== "shadow"))
    : rules;
  const primary = evaluateRules(primaryRules, actorId, context, { ...options, skipShadow: true });
  if (shadowRules && !options.skipShadow) {
    const shadow = evaluateRules(shadowRules, actorId, context, { ...options, skipShadow: true, explain: options.explain });
    primary.shadow = {
      decision: shadow.decision,
      deny_code: shadow.deny_code,
      deny_reason: shadow.deny_reason,
      trace: shadow.trace,
    };
  }
  return primary;
}

