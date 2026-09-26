# Policy as code

Keep your AtlaSent policies as YAML files in a repo. Review changes as pull requests, see exactly what will change with `plan`, and publish on merge with `apply` — the same loop as Terraform.

Starter policies with test suites are in [`policies/`](../policies/); the JSON Schema is [`schema/policy.schema.json`](../schema/policy.schema.json); the GitHub Action is [`actions/policy`](../actions/policy/action.yml).

The repo is the drafting surface; the AtlaSent runtime stays the system of record (CROSS-011). `apply` publishes through the runtime's governed path: approval-chain gates and atomic, immutable versioning still apply, and a refused publish fails the CI job.

## Layout

```
your-repo/
├── .github/workflows/
│   ├── policy-pr.yml                       # validate + test + plan on PRs
│   └── policy-apply.yml                    # apply on merge to main
└── policies/
    ├── deployment.production.yaml          # one policy per action type
    ├── deployment.production.tests.yaml    # its test cases
    └── payments.transfer.yaml
```

## A policy file

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/Atlasent/atlasent-policies/main/schema/policy.schema.json
action_type: deployment.production
description: Two approvals, business hours only, no deploys over the holidays.
rules:
  deny_actors:
    - github:actions-bot-compromised
  change_window:
    timezone: America/Los_Angeles
    days_of_week: [1, 2, 3, 4]        # Mon–Thu (0 = Sunday)
    hours: { start: "09:00", end: "17:00" }
  freeze_windows:
    - name: holiday-freeze
      date_ranges: [{ start: "2026-12-22", end: "2026-12-31" }]
  require_approvals:
    count: 2
    required_roles: [{ role: security, count: 1 }]
    exclude_actor: true               # the requester can't approve their own deploy
    max_age_seconds: 86400
  templates:
    - decision: allow
```

- **One file per action type.** `action_type` is the action class slug. The action class must exist first (console → Action classes, or `POST /v1-action-classes`); `plan` tells you if it doesn't.
- **`rules` is the runtime rule object** — the same one the engine evaluates, not a separate language. Gate order and semantics: see the rule engine in `@atlasent/sdk` (`rules.ts`).
- **The first line enables autocomplete and inline errors** in VS Code (with the Red Hat YAML extension) and other editors that read `yaml-language-server` schema hints.
- **Unknown keys are errors.** The engine ignores fields it doesn't know, so a typo like `deny_actor` would silently drop a control. `validate` rejects it; so does the schema.
- **Approvals in `rules` are counted from the request.** `require_approvals` reads `context.approvers`, which the caller sends. For production gates, back it with platform-verified approval: set `requires_human_approval` / `requires_independent_approval` on the action class, or require signed approval artifacts, so a caller can't approve itself by sending a list.
- **Quote times and dates** (`"09:00"`, `"2026-12-22"`). The CLI reads them as strings either way, but other YAML tools may not.
- **JSON works too.** `.json` files use the same shape; mix freely.

## Commands

| Command | Network | What it does |
|---|---|---|
| `atlasent-policy validate [dir]` | no | Parse + lint every policy and test file. |
| `atlasent-policy test [dir]` | no | Run `*.tests.yaml` cases through the real rule engine. |
| `atlasent-policy plan [dir]` | read | Diff each policy against what's live. No writes. |
| `atlasent-policy apply [dir]` | write | Publish every policy whose rules differ from what's live. |
| `atlasent-policy pull [--out dir]` | read | Download live policies as YAML (adopting existing policies). |
| `atlasent-policy convert [dir]` | no | Rewrite JSON policy/test files as YAML (or back with `--to json`). |

Set `ATLASENT_API_KEY` for `plan`, `apply` and `pull`. `ATLASENT_BASE_URL` defaults to `https://api.atlasent.io/functions/v1`.

### `plan`

```
$ atlasent-policy plan
~ deployment.production.yaml (deployment.production) — will publish a new version (replaces v3)
      require_approvals:
    -   count: 1
    +   count: 2
    +   exclude_actor: true
      templates:
        - decision: allow
= payments.transfer.yaml (payments.transfer) — no change (matches published v7)
Plan: 1 to publish, 1 unchanged, 0 error(s).
```

- Compares each file's rules to the live published version, ignoring key order and formatting, and asks the server to validate changed rules (dry run, nothing written).
- `--format markdown` prints a PR-comment-ready plan with `diff` blocks.
- Exit codes: `0` no errors, `1` any file failed to parse, lint, or validate. With `--detailed-exitcode`, `2` means there are changes.
- A file that doesn't parse is an error, never skipped: a silently skipped file would make `plan` report "no change" while stale rules stay live.

### `apply`

- Lints and plans **every** file first. If any file has an error, nothing is written.
- Publishes only files whose rules changed; unchanged files are left alone, so re-running `apply` is a no-op.
- Each publish records provenance: `source_digest` (the commit — `--source-digest`, or `$GITHUB_SHA` in Actions) and a `reason`.
- Publishing is governed server-side. If the action class has an approval chain, the atomic publish is refused (use the draft + transition flow in the console); the job exits 1 with the reason.

## CI

`policy-pr.yml` — validate, test, and post the plan on every PR:

```yaml
name: AtlaSent policy plan
on:
  pull_request:
    paths: ["policies/**"]

permissions:
  contents: read
  pull-requests: write

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: atlasent
        uses: Atlasent/atlasent-policies/actions/policy@v1
        with:
          mode: plan
          api_key: ${{ secrets.ATLASENT_POLICY_READ_KEY }}   # policy:read
      - name: Comment the plan on the PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          header: atlasent-policy-plan
          message: ${{ steps.atlasent.outputs.plan }}
```

`policy-apply.yml` — publish on merge:

```yaml
name: AtlaSent policy apply
on:
  push:
    branches: [main]
    paths: ["policies/**"]

concurrency:
  group: atlasent-policy-apply
  cancel-in-progress: false      # never cancel a publish midway

jobs:
  apply:
    runs-on: ubuntu-latest
    environment: production      # add required reviewers here if your plan allows
    steps:
      - uses: actions/checkout@v4
      - uses: Atlasent/atlasent-policies/actions/policy@v1
        with:
          mode: apply
          api_key: ${{ secrets.ATLASENT_POLICY_WRITE_KEY }}  # policy:write
```

Use two keys: a `policy:read` key for PR plans (safe to expose to more workflows) and a `policy:write` key only on the apply job. Pin `cli_version` for reproducible runs.

## Tests

Put cases next to the policy as `<action_type>.tests.yaml`. They run through the real rule engine with no network. These cases pass against the example policy above :

```yaml
bundle: deployment.production
tests:
  - name: two recent approvals incl. security, inside the window, is allowed
    actor_id: alice
    now: "2026-04-14T18:00:00Z"            # Tuesday, 11:00 in Los Angeles
    context:
      approvers:
        - { id: bob, role: security, timestamp: "2026-04-14T17:00:00Z" }
        - { id: carol, role: engineering, timestamp: "2026-04-14T17:30:00Z" }
    expect: allow
  - name: the requester approving their own deploy does not count
    actor_id: alice
    now: "2026-04-14T18:00:00Z"
    context:
      approvers:
        - { id: bob, role: security, timestamp: "2026-04-14T17:00:00Z" }
        - { id: alice, role: engineering, timestamp: "2026-04-14T17:30:00Z" }
    expect: deny
    expect_deny_code: INSUFFICIENT_APPROVALS
  - name: Friday is outside the change window
    actor_id: alice
    now: "2026-04-17T18:00:00Z"
    expect: deny
    expect_deny_code: OUTSIDE_CHANGE_WINDOW
  - name: holiday freeze denies
    actor_id: alice
    now: "2026-12-23T18:00:00Z"
    expect: deny
    expect_deny_code: FROZEN
```

Local tests cover the policy's `rules`. They don't exercise action-class gate flags (MFA, verified actor, human approval) or approval verification, which the runtime enforces separately — a passing test is not a guarantee of a live allow.

## Adopting existing policies

If your org already has policies authored in the console:

```sh
export ATLASENT_API_KEY=ask_live_...        # policy:read
atlasent-policy pull --out policies         # writes YAML
atlasent-policy plan                        # should report 0 to publish
git add policies && git commit -m "Adopt policy as code"
```

Already on JSON policy files? `atlasent-policy convert policies` rewrites them (and their `.tests.json`) as YAML in place. Content is checked to round-trip before each original is removed, so `plan` afterwards reports no changes.

## Rollback

Revert the commit and merge: `apply` publishes the previous rules as a new version. Published versions are immutable, so every past evaluation can still replay against the exact rules it ran with.

## API key scopes

- `plan`, `pull`: `policy:read`
- `apply`: `policy:write`

Create keys in the AtlaSent console → API Keys.

## Safety

- **Nothing is skipped silently.** Unparseable files, duplicate `action_type`s and unknown keys are errors.
- **`apply` is all-or-nothing on errors.** Any lint, parse, or validation error aborts the run before any write.
- **Published bundles are immutable.** `apply` publishes a new version via the runtime's atomic publication path; the previous version stays intact.
- **Rules are hash-chained into the audit trail.** Every evaluation records the `rules_hash` it ran against.
