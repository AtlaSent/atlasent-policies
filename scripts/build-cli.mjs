#!/usr/bin/env node
// Bundles cli/src into dist/atlasent-policy.mjs: one file, Node 20+, no
// install needed to run it. CI rebuilds and fails if the committed file
// differs, so dist/ always matches the source.
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

await build({
  entryPoints: [join(root, "cli/src/bin.ts")],
  outfile: join(root, "dist/atlasent-policy.mjs"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  minifyWhitespace: true,
  legalComments: "none",
  banner: {
    js: [
      "// atlasent-policy CLI (Apache-2.0). Built from cli/src by scripts/build-cli.mjs.",
      "// Generated file: do not edit. Third-party licenses: THIRD_PARTY_NOTICES.md.",
      'import { createRequire as __cr } from "node:module"; const require = __cr(import.meta.url);',
    ].join("\n"),
  },
  logLevel: "warning",
});
