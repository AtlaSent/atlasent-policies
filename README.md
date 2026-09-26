# AtlaSent Policies

Open-source starter policies for [AtlaSent](https://atlasent.io): execution-time
authorization for deploys, data exports, payments, privileged access and AI agent
tool calls.

Each policy is a YAML file in the format `atlasent-policy` plans and applies, with
a test suite that runs against the real AtlaSent rule engine. Copy one into your own
`policies/` directory, edit it for your organization, and ship it with the same
`plan` on PR / `apply` on merge loop you use for infrastructure.

| Policy | What it enforces |
|---|---|
| [`production.deploy`](policies/production.deploy.yaml) | Two fresh approvals incl. security, weekdays only, no deploys during a freeze |
| [`database.migrate`](policies/database.migrate.yaml) | DBA approval, a pinned migration digest, human review for destructive changes |
| [`data.export`](policies/data.export.yaml) | Approval, no direct identifiers, human review for large exports |
| [`finance.wire.transfer`](policies/finance.wire.transfer.yaml) | Dual authorization, verified beneficiary, human review for large wires |
| [`identity.privileged.grant`](policies/identity.privileged.grant.yaml) | Security approval, just-in-time grants only (8 hours max) |
| [`agent.tool.invoke`](policies/agent.tool.invoke.yaml) | Tool allowlist, human review for risky tools, rate limit, deny everything else |

## Use a policy

```sh
cp atlasent-policies/policies/production.deploy.* your-repo/policies/

npx github:Atlasent/atlasent-policies validate policies   # schema + lint, offline
npx github:Atlasent/atlasent-policies test policies       # run the test cases, offline
npx github:Atlasent/atlasent-policies plan policies       # diff against what's live (needs ATLASENT_API_KEY)
npx github:Atlasent/atlasent-policies apply policies      # publish (usually from CI on merge)
```

The CLI (`atlasent-policy`) ships in this repo as one bundled file,
[`dist/atlasent-policy.mjs`](dist/atlasent-policy.mjs), so there is nothing else to install. It needs
Node 20+. Its source is in [`cli/`](cli/). Pin a tag (`github:Atlasent/atlasent-policies#v1`) for reproducible runs.

In CI, the action in this repo runs `plan` on pull requests and `apply` on merge:

```yaml
- uses: Atlasent/atlasent-policies/actions/policy@v1
  with:
    mode: plan                     # or: check (offline), apply
    api_key: ${{ secrets.ATLASENT_POLICY_READ_KEY }}
```

The full workflow, CI setup and file format are in the
[policy-as-code guide](docs/policy-as-code.md).
Every file starts with a `yaml-language-server` schema line, so editors that read it
give you autocomplete and inline errors.

## What these policies are, and aren't

- **Starting points, not compliance claims.** A policy here encodes a reasonable
  default for a common control. Whether it meets a specific framework or regulation
  is for you and your auditors to decide.
- **The rules layer only.** Some protections (human approval, MFA, verified caller
  identity) are enforced by the AtlaSent runtime on the action class, not by a policy
  file. Each policy's header says which of those to turn on alongside it.
- **Approvals in `rules` are counted from the request.** `require_approvals` reads the
  approvers the caller sends. Pair it with runtime-verified approval so a caller can't
  approve itself by sending a list.

## Contributing

This is a community library: anyone can add a policy, improve one, or improve the
CLI itself.

- **Suggest a policy or an improvement, no code needed.** Open an issue with
  [Suggest a new policy](../../issues/new?template=new-policy.yml) or
  [Suggest an improvement](../../issues/new?template=improvement.yml). Describe the
  control and a few example requests; a maintainer or another contributor can turn it
  into YAML and tests.
- **Found a policy that decides wrong?** Use
  [Report a policy that's wrong](../../issues/new?template=policy-bug.yml). For
  anything exploitable, follow [SECURITY.md](SECURITY.md) instead.
- **Add or change a policy.** Open a pull request with the policy and its test suite.
- **Improve the CLI.** Its source is in [`cli/src`](cli/src); `npm ci && npm test`
  builds and tests it, and `npm run build` regenerates `dist/`.

Every pull request is checked by CI (validate, test, CLI build and a public-safety
scan) and every commit needs a DCO sign-off. Details in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
