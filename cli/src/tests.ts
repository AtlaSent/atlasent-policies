/**
 * Small fs helpers shared across commands. Kept in their own module so
 * we don't re-implement walk() in three places.
 */
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";

export async function walk(path: string, fn: (file: string) => Promise<void>): Promise<void> {
  let s;
  try { s = await stat(path); } catch { return; }
  if (s.isFile()) return fn(path);
  if (!s.isDirectory()) return;
  // Avoid walking into obvious non-policy directories.
  if (/\/(node_modules|dist|\.git)(\/|$)/.test(path)) return;
  const entries = await readdir(path);
  for (const e of entries) await walk(join(path, e), fn);
}

export async function walkForSuffix(
  root: string,
  suffix: string,
  fn: (file: string) => Promise<void>,
): Promise<void> {
  await walk(root, async (p) => {
    if (p.endsWith(suffix)) await fn(p);
  });
}
