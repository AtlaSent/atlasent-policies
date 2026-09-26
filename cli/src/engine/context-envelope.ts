// SYNCED COPY — do not edit here. Source of truth: the AtlaSent runtime's packages/sdk/src/context-envelope.ts.
// Change it there; the runtime's CI fails if this copy drifts. Propose engine changes as an issue.
/**
 * Canonical V1 context envelope — SDK-side replay verifier.
 *
 * Companion modules (kept in lockstep — same canonical form, same hash):
 *   packages/types/src/context-envelope-v1.ts            (typed wire contract)
 *   supabase/functions/_shared/context-envelope-v1.ts    (edge-side helper)
 *
 * Offline consumers (CI builds, evidence-export tooling, replay harnesses)
 * use this module to verify that a supplied envelope canonical-hashes to the
 * `envelope_hash` claim on a signed permit, an audit-chain row, or a
 * `context_envelopes` record — without an AtlaSent round-trip.
 *
 * The wire types are re-declared here rather than imported from
 * `@atlasent/types`. The types-package `context-envelope-v1.ts` is a
 * standalone module and is intentionally not re-exported from its `index.ts`
 * (that would force the `_shared/types.ts` mirror through types-sync and
 * couple SDK consumers to types-package internals). Mirroring locally keeps
 * the SDK self-contained for npm consumers and matches the edge-side
 * pattern.
 */

export type EnvelopeVersion = "atlasent.v1";

export interface ContextEnvelopeV1 {
  envelope_version: EnvelopeVersion;
  request_id: string;
  issued_at: string;
  protected_action: string;
  intent: { summary: string; operation: "execute" | "simulate" | "replay"; idempotency_key?: string };
  actor: {
    kind: "human" | "service_account" | "autonomous_agent";
    principal: string;
    identity_assertions?: ReadonlyArray<Record<string, unknown>>;
    attestation_ref?: string;
  };
  resource: {
    kind: string;
    ref: string;
    environment?: string;
    labels?: Record<string, string>;
  };
  environment: {
    tenant_id: string;
    runtime_window?: string;
    freeze_in_effect?: boolean;
    incident_state?: string;
  };
  history?: Record<string, unknown>;
  evidence_refs?: ReadonlyArray<{
    kind: string;
    uri: string;
    content_hash?: string;
    evidence_id?: string;
  }>;
  signals?: Record<string, Record<string, SignalEntry>>;
  compatibility_overrides?: {
    shadow_only?: boolean;
    emergency_basis?: string | null;
  };
}

export interface SignalEntry {
  value: unknown;
  source: string;
  confidence?: number;
  produced_at?: string;
  ttl_seconds?: number;
}

/**
 * Canonical JSON serialization — sorted keys at every depth.
 *
 * Two envelopes with the same logical content always serialize to the same
 * byte sequence, so `envelope_hash` is reproducible across producers
 * (edge function, audit chain, SDK consumer).
 */
export function canonicalizeEnvelope(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(v).sort()) sorted[k] = (v as Record<string, unknown>)[k];
      return sorted;
    }
    return v;
  });
}

/** sha256 hex of a canonical-JSON string. */
export async function envelopeHashOf(canonical: string): Promise<string> {
  const buf = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const bytes = new Uint8Array(digest);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

/**
 * Outcome of {@link verifyContextEnvelope}. `ok: true` means the supplied
 * envelope canonical-hashed to `expectedHash`; `ok: false` carries a stable
 * `reason` slug and the actual hash so callers can surface the specific
 * failure mode (and operators can diff the bytes).
 */
export type EnvelopeVerifyResult =
  | { ok: true; actualHash: string }
  | {
      ok: false;
      reason: "hash_mismatch" | "bad_expected_hash_format" | "build_error";
      actualHash?: string;
      buildError?: string;
    };

/**
 * Verify that the supplied envelope's canonical-JSON SHA-256 equals
 * `expectedHash`. Mirrors the edge-side enforcement at
 * `v1-verify-permit`, so offline tools can validate the
 * permit/audit-row/envelope-record binding without an AtlaSent round-trip.
 *
 * Side-channel-safe: hex comparison is constant-time (length-prefix +
 * XOR-accumulating loop). Format check (`^[a-f0-9]{64}$`) runs first so a
 * malformed `expectedHash` is rejected before any hashing work.
 *
 * The envelope is NOT structurally validated here — the hash check is
 * intentionally orthogonal to shape validation. A malformed envelope still
 * produces a deterministic hash; this verifier's job is tamper detection.
 */
export async function verifyContextEnvelope(
  envelope: ContextEnvelopeV1,
  expectedHash: string,
): Promise<EnvelopeVerifyResult> {
  if (typeof expectedHash !== "string" || !/^[a-f0-9]{64}$/.test(expectedHash)) {
    return { ok: false, reason: "bad_expected_hash_format" };
  }
  let actualHash: string;
  try {
    actualHash = await envelopeHashOf(canonicalizeEnvelope(envelope));
  } catch (err) {
    return {
      ok: false,
      reason: "build_error",
      buildError: err instanceof Error ? err.message : String(err),
    };
  }
  if (actualHash.length !== expectedHash.length) {
    return { ok: false, reason: "hash_mismatch", actualHash };
  }
  let diff = 0;
  for (let i = 0; i < actualHash.length; i++) {
    diff |= actualHash.charCodeAt(i) ^ expectedHash.charCodeAt(i);
  }
  if (diff !== 0) {
    return { ok: false, reason: "hash_mismatch", actualHash };
  }
  return { ok: true, actualHash };
}
