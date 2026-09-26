import { readFileSync } from "node:fs";

/**
 * Legacy single-suite runner: evaluates each case against the LIVE runtime
 * (`POST {base}/v1-evaluate`). `atlasent-policy test <dir>` runs cases
 * in-process instead; this path is only taken for a single `*.tests.json`
 * file in the old `{ bundle_id, tests: [{ agent, action, expect }] }` shape.
 *
 * Fail-closed, like the SDK's authorizeOrThrow: a case counts as "allow"
 * only when the runtime answers decision "allow" WITH a permit token.
 * Every other decision, an HTTP error, or a malformed response is "deny",
 * and non-decision failures are surfaced in `error`.
 */

export interface PolicyTestCase {
  description: string;
  agent: string;
  action: string;
  context?: Record<string, unknown>;
  expect: "allow" | "deny";
}

export interface PolicyTestSuite {
  bundle_id: string;
  tests: PolicyTestCase[];
}

export interface TestResult {
  description: string;
  passed: boolean;
  expected: "allow" | "deny";
  actual: "allow" | "deny";
  error?: string;
}

export interface EvaluateClient {
  evaluate(body: Record<string, unknown>): Promise<{ decision?: unknown; permit_token?: unknown }>;
}

export async function runTests(
  suitePath: string,
  client?: EvaluateClient,
): Promise<{ results: TestResult[]; passed: number; failed: number }> {
  const raw = readFileSync(suitePath, "utf-8");
  const suite = JSON.parse(raw) as PolicyTestSuite;

  const atlasent = client ?? makeDefaultClient();

  const results: TestResult[] = [];

  for (const tc of suite.tests) {
    let actual: "allow" | "deny" = "deny";
    let error: string | undefined;

    try {
      const res = await atlasent.evaluate({
        action_type: tc.action,
        actor_id: tc.agent,
        context: tc.context ?? {},
        bundle_id: suite.bundle_id,
      });
      if (res.decision === "allow") {
        if (typeof res.permit_token === "string" && res.permit_token.length > 0) actual = "allow";
        else error = "allow decision missing permit_token";
      } else if (!["deny", "hold", "escalate"].includes(String(res.decision))) {
        error = `unexpected decision ${JSON.stringify(res.decision)}`;
      }
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }

    results.push({
      description: tc.description,
      passed: actual === tc.expect,
      expected: tc.expect,
      actual,
      error,
    });
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;
  return { results, passed, failed };
}

function makeDefaultClient(): EvaluateClient {
  const apiKey = process.env.ATLASENT_API_KEY;
  const baseUrl = process.env.ATLASENT_BASE_URL;
  if (!apiKey || !baseUrl) {
    throw new Error(
      "ATLASENT_API_KEY and ATLASENT_BASE_URL must be set, or pass an EvaluateClient explicitly",
    );
  }
  const base = baseUrl.replace(/\/+$/, "");
  return {
    async evaluate(body) {
      const r = await fetch(`${base}/v1-evaluate`, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const text = await r.text();
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        throw new Error(`HTTP ${r.status}: non-JSON response`);
      }
      if (!r.ok) {
        const code = (json as { error?: { code?: string } })?.error?.code ?? "error";
        throw new Error(`HTTP ${r.status}: ${code}`);
      }
      return json as { decision?: unknown; permit_token?: unknown };
    },
  };
}
