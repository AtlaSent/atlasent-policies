export { lintRules, lintPolicy, hasErrors } from "./lint.js";
export type { LintFinding, LintLevel } from "./lint.js";

export {
  cmdValidate,
  cmdTest,
  cmdPlan,
  cmdApply,
  cmdPull,
  cmdConvert,
  cmdSimulate,
  cmdVerifyBundle,
} from "./commands.js";
export type {
  Env,
  BundlesClient,
  PolicyDoc,
  PolicyFile,
  PolicyLoadError,
} from "./commands.js";
export { FetchBundlesClient } from "./commands.js";
export {
  parsePolicyText,
  dumpPolicy,
  diffLines,
  rulesEqual,
  isPolicyFile,
  isTestFile,
  POLICY_SCHEMA_URL,
} from "./policyFile.js";
export type { PolicyFormat } from "./policyFile.js";

export {
  parseTestFile,
  discoverTests,
  runTests,
  summarizeResults,
} from "./testRunner.js";
export type { PolicyTestCase, PolicyTestFile, TestRunResult } from "./testRunner.js";

export { run } from "./run.js";
