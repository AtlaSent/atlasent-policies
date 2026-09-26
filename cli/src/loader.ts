import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";

export interface PolicyFile {
  path: string;
  policy: Record<string, unknown>;
}

export interface TestCase {
  name: string;
  context: Record<string, unknown>;
  actor_id?: string;
  expect: "allow" | "deny" | "hold" | "escalate";
  expect_deny_code?: string;
  fail_mode?: "open" | "closed";
  now?: string;
}

export interface TestSuite {
  bundle: string;
  tests: TestCase[];
}

export interface TestFile {
  path: string;
  suite: TestSuite;
}

function readJson(filePath: string): unknown {
  try {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  } catch (e) {
    throw new Error(`Failed to parse ${filePath}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

export function loadPolicyFiles(dir: string): PolicyFile[] {
  const results: PolicyFile[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      results.push(...loadPolicyFiles(full));
    } else if (extname(entry) === ".json" && !entry.endsWith(".tests.json")) {
      results.push({ path: full, policy: readJson(full) as Record<string, unknown> });
    }
  }
  return results;
}

export function loadTestFiles(dir: string): TestFile[] {
  const results: TestFile[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      results.push(...loadTestFiles(full));
    } else if (entry.endsWith(".tests.json")) {
      results.push({ path: full, suite: readJson(full) as TestSuite });
    }
  }
  return results;
}
