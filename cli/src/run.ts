import { cmdValidate, cmdPlan, cmdApply, cmdPull, cmdConvert, cmdTest, cmdSimulate, cmdVerifyBundle, type Env } from "./commands.js";

const USAGE = `
atlasent-policy — policy as code for AtlaSent (YAML or JSON), plus audit verification

Usage:
  atlasent-policy validate [dir]              static analysis; no network. default dir: policies/
  atlasent-policy test     [dir]              run *.tests.yaml / *.tests.json against their policies (no network)
  atlasent-policy plan     [dir]              diff each policy against what is live; no writes
    [--format text|markdown]                  markdown is ready to post as a PR comment
    [--detailed-exitcode]                     exit 2 when there are changes
  atlasent-policy apply    [dir]              publish every policy whose rules differ from what is live
    [--source-digest SHA] [--reason TEXT]     provenance; source digest defaults to $GITHUB_SHA
  atlasent-policy pull     [--out dir]        download published policies (existing console-authored ones)
    [--format yaml|json]                      default yaml
  atlasent-policy convert  [dir]              rewrite JSON policy/test files as YAML (or back)
    [--to yaml|json] [--keep]
  atlasent-policy verify-bundle <file>        offline five-point check on a /v1/export-audit bundle.
    [--trusted-key <pem>] [--json]            no network. exit 0 ok, 1 failure, 2 usage.

Env:
  ATLASENT_API_KEY       API key with policy:read (plan, pull) and policy:write (apply)
  ATLASENT_BASE_URL      default https://api.atlasent.io/functions/v1

File format (policies/<action_type>.yaml):
  # yaml-language-server: $schema=https://raw.githubusercontent.com/Atlasent/atlasent-policies/main/schema/policy.schema.json
  action_type: production.deploy
  description: optional human text
  rules:
    require_approvals: { count: 2 }
    templates:
      - decision: allow
`;

export async function run(argv: string[], env: Env): Promise<void> {
  const [subcommand, ...rest] = argv;
  try {
    switch (subcommand) {
      case "validate":      return await cmdValidate(rest, env);
      case "test":          return await cmdTest(rest, env);
      case "plan":          return await cmdPlan(rest, env);
      case "apply":         return await cmdApply(rest, env);
      case "pull":          return await cmdPull(rest, env);
      case "convert":       return await cmdConvert(rest, env);
      case "simulate":      return await cmdSimulate(rest, env);
      case "verify-bundle": return await cmdVerifyBundle(rest, env);
      case "-h":
      case "--help":
      case "help":
      case undefined:
        env.stdout(USAGE.trim());
        return;
      default:
        env.stderr(`Unknown command: ${subcommand}`);
        env.stdout(USAGE.trim());
        env.exit(2);
    }
  } catch (err) {
    env.stderr(`atlasent-policy: ${err instanceof Error ? err.message : String(err)}`);
    env.exit(1);
  }
}
