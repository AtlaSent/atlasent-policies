# Contributing

Thanks for helping make these policies better.

## What we accept

- **New policies** for common controls, one action type per file.
- **Improvements** to existing policies: tighter defaults, clearer comments, more
  test cases.
- **Fixes** where a policy doesn't do what its description says.

We don't accept policies that name a specific company, customer, internal system or
person, or that claim compliance with a specific regulation.

## Requirements for every policy

1. **One file per action type:** `policies/<action_type>.yaml`. `action_type` is
   dot-notation (`resource.verb`), lower case.
2. **A test suite next to it:** `policies/<action_type>.tests.yaml`, with at least one
   case per decision the policy can return (allow, deny, escalate, hold) and one per
   custom `deny_code`.
3. **A header comment** saying what the policy enforces and which runtime settings to
   turn on alongside it.
4. **It passes:**

   ```sh
   node dist/atlasent-policy.mjs validate policies
   node dist/atlasent-policy.mjs test policies
   ./scripts/check-public-safety.sh
   ```

   CI runs the same checks on every pull request.

## Suggestions without code

Not ready to write YAML? Open an issue with the **Suggest a new policy** or
**Suggest an improvement** form. Concrete example requests and the decision you'd
expect for each are the most useful part: they become the test suite.

## Improving the CLI

The `atlasent-policy` CLI lives in `cli/src` and is bundled into
`dist/atlasent-policy.mjs`, which is committed so the GitHub Action and
`npx github:Atlasent/atlasent-policies` work with no install.

```sh
npm ci
npm run typecheck
npm test
npm run build        # regenerates dist/atlasent-policy.mjs; commit it with your change
```

CI rebuilds `dist/` from source and fails if the committed file differs.

**The rule engine is a synced copy.** `cli/src/engine/` mirrors the engine the
AtlaSent runtime uses to make live decisions, so local test results match production.
Don't edit those files here; a change would be overwritten on the next sync. If you
think the engine behaves wrongly, open an issue with a failing test case.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. Add a sign-off line to every commit:

```sh
git commit -s -m "Add policy for secret rotation"
```

This adds `Signed-off-by: Your Name <you@example.com>`, certifying that you wrote the
change or otherwise have the right to submit it under the Apache License 2.0. CI
rejects pull requests with unsigned commits.

## Review

A maintainer reviews every pull request. Expect questions about edge cases: what
happens when a context field is missing, whether a deny can be bypassed by omitting a
field, and whether the tests prove it.
