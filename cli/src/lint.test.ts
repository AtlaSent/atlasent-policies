import { describe, it, expect } from "vitest";
import { lintRules, hasErrors } from "./lint";

function codes(findings: { code: string }[]): string[] {
  return findings.map((f) => f.code);
}

describe("lintRules", () => {
  it("accepts a clean template ruleset", () => {
    const findings = lintRules({
      rules: {
        deny_actors: ["mallory"],
        templates: [
          { decision: "allow", when: { all: [{ field: "context.env", eq: "prod" }] } },
          { decision: "deny" },
        ],
      },
    });
    expect(hasErrors(findings)).toBe(false);
    const warns = findings.filter((f) => f.level === "warning");
    expect(warns.length).toBe(0);
  });

  it("flags an unknown top-level key as an error (the engine would ignore it)", () => {
    // A typo like this silently drops the control at evaluation time.
    const findings = lintRules({ rules: { denny_actors: ["x"] } });
    expect(codes(findings)).toContain("UNKNOWN_TOP_LEVEL_KEY");
    expect(hasErrors(findings)).toBe(true);
  });

  it("accepts every key the engine reads", () => {
    const findings = lintRules({
      rules: {
        deny_actors: [], allow_actors: [], escalate_actors: [], hold_actors: [],
        deny_roles: [], allow_roles: [], escalate_roles: [], hold_roles: [],
        require_approvals: 2,
        change_window: { timezone: "UTC", days_of_week: [1], hours: { start: "09:00", end: "17:00" } },
        freeze_windows: [], rate_limits: [], risk: {}, rollout: {},
        location_requirements: {}, decision: "allow", deny_code: "X", deny_reason: "y",
        templates: [{ decision: "allow", name: "n", condition_id: "approval_required" }],
        shadow: { templates: [{ decision: "deny" }] },
      },
    });
    expect(codes(findings).filter((c) => c.startsWith("UNKNOWN"))).toEqual([]);
  });

  it("rejects operator spellings the engine does not evaluate, with a suggestion", () => {
    const findings = lintRules({
      rules: { templates: [{ decision: "deny", when: { all: [{ field: "context.env", ne: "dev" }] } }] },
    });
    const f = findings.find((x) => x.code === "UNKNOWN_CONDITION_KEY");
    expect(f?.level).toBe("error");
    expect(f?.message).toContain('did you mean "neq"');
  });

  it("flags an unknown template key as an error", () => {
    const findings = lintRules({ rules: { templates: [{ decision: "deny", whenn: {} }] } });
    expect(codes(findings)).toContain("UNKNOWN_TEMPLATE_KEY");
    expect(hasErrors(findings)).toBe(true);
  });

  it("flags non-array for deny_actors as an error", () => {
    const findings = lintRules({ rules: { deny_actors: "alice" } });
    expect(codes(findings)).toContain("EXPECTED_ARRAY");
    expect(hasErrors(findings)).toBe(true);
  });

  it("flags invalid decision in a template", () => {
    const findings = lintRules({
      rules: { templates: [{ decision: "allowww" }] },
    });
    expect(codes(findings)).toContain("INVALID_DECISION");
  });

  it("flags unreachable template after unconditional one", () => {
    const findings = lintRules({
      rules: {
        templates: [
          { decision: "allow" },
          { decision: "deny" }, // unreachable
        ],
      },
    });
    expect(codes(findings)).toContain("UNREACHABLE_TEMPLATE");
  });

  it("does not flag unreachable when the earlier template has a when", () => {
    const findings = lintRules({
      rules: {
        templates: [
          { decision: "allow", when: { all: [{ field: "context.env", eq: "prod" }] } },
          { decision: "deny" },
        ],
      },
    });
    expect(codes(findings)).not.toContain("UNREACHABLE_TEMPLATE");
  });

  it("flags empty condition", () => {
    const findings = lintRules({
      rules: { templates: [{ decision: "allow", when: { all: [{}] } }] },
    });
    expect(codes(findings)).toContain("EMPTY_CONDITION");
  });

  it("flags operator without field", () => {
    const findings = lintRules({
      rules: { templates: [{ decision: "allow", when: { all: [{ eq: "prod" }] } }] },
    });
    expect(codes(findings)).toContain("OPERATOR_WITHOUT_FIELD");
  });

  it("flags invalid regex", () => {
    const findings = lintRules({
      rules: {
        templates: [{ decision: "allow", when: { all: [{ field: "context.x", regex: "(((" }] } }],
      },
    });
    expect(codes(findings)).toContain("INVALID_REGEX");
  });

  it("accepts valid regex with flags", () => {
    const findings = lintRules({
      rules: {
        templates: [{ decision: "allow", when: { all: [{ field: "context.ref", regex: "^main$", regex_flags: "i" }] } }],
      },
    });
    expect(hasErrors(findings)).toBe(false);
  });

  it("recurses into logical combinators", () => {
    const findings = lintRules({
      rules: {
        templates: [{
          decision: "allow",
          when: { all: [{ any: [{ not: { field: "context.x", eq: "bad" } }] }] },
        }],
      },
    });
    expect(hasErrors(findings)).toBe(false);
  });

  it("flags condition with unknown operator", () => {
    const findings = lintRules({
      rules: {
        templates: [{ decision: "allow", when: { all: [{ field: "context.x", equalsish: "y" }] } }],
      },
    });
    expect(codes(findings)).toContain("UNKNOWN_CONDITION_KEY");
  });

  it("recurses into shadow rules", () => {
    const findings = lintRules({
      rules: {
        shadow: { templates: [{ decision: "nope" }] },
      },
    });
    expect(codes(findings)).toContain("INVALID_DECISION");
  });

  it("errors when rules is not an object", () => {
    const findings = lintRules({ rules: [1, 2] });
    expect(codes(findings)).toContain("RULES_NOT_OBJECT");
  });
});
