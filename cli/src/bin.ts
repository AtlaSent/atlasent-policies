#!/usr/bin/env node
/**
 * Thin CLI entry point. Dispatches to the unified cmd functions in
 * commands.ts; those handle argv parsing, env-based output, and exit
 * codes themselves. The wrapper just turns process.argv into the
 * (args, env) shape and surfaces uncaught errors.
 */
import { run } from "./run.js";

run(process.argv.slice(2), {
  cwd: () => process.cwd(),
  stdout: (l: string) => { console.log(l); },
  stderr: (l: string) => { console.error(l); },
  exit: ((code: number): never => {
    process.exit(code);
    throw new Error(`exit(${code})`); // unreachable; keeps TS happy
  }),
  env: process.env as Record<string, string | undefined>,
}).catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
