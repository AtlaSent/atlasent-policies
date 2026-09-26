// SYNCED COPY — do not edit here. Source of truth: the AtlaSent runtime's packages/sdk/src/export-bundle.ts.
// Change it there; the runtime's CI fails if this copy drifts. Propose engine changes as an issue.
/**
 * Offline export-bundle verifier — five-point check on a signed
 * /v1/export-audit response.
 *
 * Companion modules (kept in lockstep):
 *   supabase/functions/v1-export-audit/handler.ts                  (mint)
 *   supabase/migrations-runtime/20260522140000_export_audit_envelope_bundle.sql
 *   packages/sdk/src/context-envelope.ts                           (envelope hash check)
 *
 * Consumers (CI evidence collectors, regulator-facing offline auditors,
 * proof-of-decision harnesses) call `verifyAuditExportBundle(bundle)` and
 * get a single deterministic verdict covering every claim the bundle makes
 * about itself — no AtlaSent round-trip, no extra crypto code to write.
 *
 * Five points of verification (numbered the same way they're documented on
 * the handler):
 *
 *   1. sha256_hex(canonical_payload) === eval_row.entry_hash             [chain]
 *   2. canonical_payload prev-hash slot = previous row's entry_hash      [chain adjacency]
 *   3. sha256(canonicalize(env.envelope)) === env.envelope_hash          [envelope integrity]
 *   4. env.envelope_hash === eval_row.envelope_hash                      [chain↔envelope binding]
 *   5. Ed25519 signature of the bundle (minus the signature field) verifies
 *      against bundle.public_key_pem                                     [bundle provenance]
 *
 * Each failure is captured in a stable `failures[]` shape so an auditor can
 * report `(row_id, check, reason, expected, actual)` to operators without
 * inspecting the bundle by eye.
 */

import {
  canonicalizeEnvelope,
  envelopeHashOf,
  verifyContextEnvelope,
  type ContextEnvelopeV1,
} from "./context-envelope.js";

// ─── Bundle shape (mirrors the v1-export-audit response) ───────────────────

export interface ExportBundleEvalRow {
  readonly id: string;
  readonly request_id: string;
  readonly actor_id: string;
  readonly decision: string;
  readonly created_at: string;
  readonly prev_hash: string | null;
  readonly entry_hash: string;
  readonly payload_version: number;
  /** sha256 hex of the V1 context envelope that produced this decision. v4 rows only. */
  readonly envelope_hash?: string | null;
  /** Recomputed via evaluation_canonical_payload(payload_version, ...). */
  readonly canonical_payload: string;
  // Other columns (deny_code, request_context, bundle_*, etc.) are present
  // on the wire but not consulted by the verifier; left off the type so
  // additions to the export shape do not force a bump here.
}

export interface ExportBundleContextEnvelopeRow {
  readonly request_id: string;
  readonly envelope_version: string;
  readonly protected_action: string;
  readonly envelope: ContextEnvelopeV1;
  readonly envelope_hash: string;
  readonly evidence_refs?: ReadonlyArray<string>;
  readonly recorded_by?: string;
  readonly received_at?: string;
}

/** governance_change_transitions row exported alongside an opt-in bundle.
 *  Hash chain walks per (change_id, seq); each row carries event_hash +
 *  prev_event_hash + the eight fields that compose the canonical payload
 *  the verifier recomputes (see governance_record_transition's hash
 *  formula in 20260520140000_governance_release_state_architecture.sql). */
export interface ExportBundleGovernanceTransitionRow {
  readonly id: string;
  readonly change_id: string;
  readonly subject_kind?: string;
  readonly subject_ref?: string;
  readonly seq: number;
  readonly from_state: string;
  readonly to_state: string;
  readonly actor_kind: string;
  readonly actor_id: string;
  readonly authority_domain?: string | null;
  readonly authority_basis?: string | null;
  readonly justification: string;
  readonly evidence_refs?: ReadonlyArray<string>;
  readonly gate_snapshot?: unknown;
  readonly prev_event_hash: string | null;
  readonly event_hash: string;
  readonly transitioned_at: string;
}

export interface ExportBundleAuditChainSpec {
  readonly spec_id: string;
  readonly spec_version: string;
  readonly adr: string;
  readonly evaluation_chain_versions: ReadonlyArray<string>;
}

/**
 * Current producers include this signed provenance stamp. It remains optional
 * in the SDK input type so older archived bundles can still be verified.
 */
export interface ExportBundle {
  readonly version: number;
  readonly org_id: string;
  readonly generated_at: string;
  readonly range: { since: string | null; until: string | null; limit: number };
  readonly evaluations: ReadonlyArray<ExportBundleEvalRow>;
  readonly audit_chain_spec?: ExportBundleAuditChainSpec;
  readonly execution_head: { id: string; entry_hash: string } | null;
  readonly context_envelopes?: ReadonlyArray<ExportBundleContextEnvelopeRow>;
  readonly governance_transitions?: ReadonlyArray<ExportBundleGovernanceTransitionRow>;
  readonly admin_log?: ReadonlyArray<unknown>;
  readonly admin_head?: { id: string; entry_hash: string } | null;
  readonly public_key_pem: string;
  readonly signature: string;
}

// ─── Result shape ──────────────────────────────────────────────────────────

export type ExportFailureCheck =
  | "entry_hash_recompute"
  | "chain_adjacency"
  | "envelope_hash_recompute"
  | "envelope_chain_binding"
  | "governance_event_hash_recompute"
  | "governance_chain_adjacency"
  | "bundle_signature";

export interface ExportFailure {
  /** Which of the five checks failed. */
  readonly check: ExportFailureCheck;
  /**
   * Stable diagnostic slug per check. Examples:
   *   entry_hash_recompute   → "hash_mismatch"
   *   chain_adjacency        → "prev_hash_mismatch" | "first_row_not_genesis"
   *   envelope_hash_recompute→ "hash_mismatch" | "envelope_build_error"
   *   envelope_chain_binding → "missing_envelope_row" | "hash_mismatch"
   *   bundle_signature       → "bad_signature" | "bad_public_key"
   */
  readonly reason: string;
  /** Subject the failure applies to (eval row id / envelope request_id / bundle). */
  readonly subject_id: string;
  readonly expected?: string;
  readonly actual?: string;
  readonly detail?: string;
}

export interface ExportVerifyOk {
  readonly ok: true;
  readonly checks: {
    readonly evaluations: number;
    readonly envelopes: number;
    readonly signature_verified: true;
    readonly chain_adjacent: true;
    readonly envelopes_matched: number;
    /** When governance_transitions[] was present, number of rows verified
     *  (both event_hash recompute AND chain adjacency per change_id).
     *  Zero when no governance_transitions array was supplied. */
    readonly governance_transitions: number;
  };
}

export interface ExportVerifyFail {
  readonly ok: false;
  readonly failures: ReadonlyArray<ExportFailure>;
}

export type ExportVerifyResult = ExportVerifyOk | ExportVerifyFail;

// ─── Helpers ───────────────────────────────────────────────────────────────

const GENESIS = "GENESIS";

/** Extract the prev_hash slot recorded inside a canonical_payload string.
 *  The last `|`-delimited field is always the previous row's entry_hash
 *  (or the literal "GENESIS" for the chain head). All four dispatcher
 *  arms (v1/v2/v3/v4) share this trailing slot — see
 *  supabase/migrations/20260504040000_audit_chain_payload_v3.sql and
 *  20260522130000_audit_chain_payload_v4_envelope_bound.sql. */
function trailingPrevHash(canonicalPayload: string): string | null {
  const idx = canonicalPayload.lastIndexOf("|");
  if (idx < 0) return null;
  return canonicalPayload.slice(idx + 1);
}

/** sha256 hex of a UTF-8 string. */
async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const bytes = new Uint8Array(digest);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

/** Constant-time hex compare; mirrors {@link verifyContextEnvelope}. */
function hexEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Canonical JSON for the bundle's signed payload — sorted keys, signature
 *  field excluded. Mirrors the mint side (`canonicalize(envelope)` over the
 *  bundle minus `signature`). */
function canonicalizeBundle(bundle: ExportBundle): string {
  const { signature: _sig, ...rest } = bundle;
  return canonicalizeEnvelope(rest);
}

/** Decode base64 (standard or url-safe) → Uint8Array. */
function base64Decode(s: string): Uint8Array {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = std.length % 4 === 0 ? std : std + "=".repeat(4 - (std.length % 4));
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Import the public-key PEM emitted on the bundle into a Web Crypto key. */
async function importPublicKey(pem: string): Promise<CryptoKey> {
  const spkiB64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, "");
  const spki = base64Decode(spkiB64);
  return await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "Ed25519" },
    true,
    ["verify"],
  );
}

// ─── Main entry ────────────────────────────────────────────────────────────

export interface VerifyOptions {
  /**
   * Trusted public key PEM. When provided, the verifier requires the bundle's
   * own `public_key_pem` to match exactly — protects against a tampered
   * bundle that includes its own attacker-controlled key. Recommended for
   * production use; tooling that's intentionally pinning to a key bundle
   * should supply this.
   *
   * When omitted, the verifier signature-checks against the key the bundle
   * itself emits. That confirms the bundle is internally consistent (the
   * signer minted both the payload AND the embedded public key) but does
   * NOT prove the signer is AtlaSent. Most callers should pin.
   */
  readonly trustedPublicKeyPem?: string;
}

/**
 * Verify a signed `/v1/export-audit` bundle against all five canonical-hash
 * invariants. Returns a single `ok: true | false` result with detailed
 * failures on every broken row.
 *
 * Failure modes are accumulated, not short-circuited: a bundle with a
 * tampered envelope AND a snapped chain reports both. This matches
 * `verify_audit_chain`'s philosophy — surface every break so the operator
 * sees the full damage radius.
 */
export async function verifyAuditExportBundle(
  bundle: ExportBundle,
  options: VerifyOptions = {},
): Promise<ExportVerifyResult> {
  const failures: ExportFailure[] = [];

  // ── Check 5 — bundle signature first (cheapest sanity gate). Mint-side
  //    re-canonicalizes envelope minus the signature field, then Ed25519-signs.
  //    Order: signature first, then row-level checks. If the bundle was
  //    rewritten in transit the signature breaks; we still continue so the
  //    caller sees the row-level damage too.
  try {
    if (
      options.trustedPublicKeyPem &&
      options.trustedPublicKeyPem.trim() !== bundle.public_key_pem.trim()
    ) {
      failures.push({
        check: "bundle_signature",
        reason: "trusted_key_mismatch",
        subject_id: "bundle",
        expected: options.trustedPublicKeyPem.trim(),
        actual: bundle.public_key_pem.trim(),
        detail: "Bundle's emitted public_key_pem does not match the trusted key",
      });
    }
    const pubKey = await importPublicKey(bundle.public_key_pem);
    const canonicalBytes = new TextEncoder().encode(canonicalizeBundle(bundle));
    const sigBytes = base64Decode(bundle.signature);
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      pubKey,
      sigBytes,
      canonicalBytes,
    );
    if (!valid) {
      failures.push({
        check: "bundle_signature",
        reason: "bad_signature",
        subject_id: "bundle",
        detail: "Ed25519 verify returned false against the bundle's public_key_pem",
      });
    }
  } catch (err) {
    failures.push({
      check: "bundle_signature",
      reason: "bad_public_key",
      subject_id: "bundle",
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // ── Check 1+2 — chain integrity + adjacency, per eval row.
  let prevEntry: string | null = null;
  for (const row of bundle.evaluations) {
    // 1. recomputed entry_hash must match.
    const recomputed = await sha256Hex(row.canonical_payload);
    if (!hexEq(recomputed, row.entry_hash)) {
      failures.push({
        check: "entry_hash_recompute",
        reason: "hash_mismatch",
        subject_id: row.id,
        expected: row.entry_hash,
        actual: recomputed,
      });
    }
    // 2. trailing |-slot in canonical_payload is the prev_hash. The very
    //    first row's prev_hash is `null` on the wire and "GENESIS" in the
    //    canonical payload. Every subsequent row should pin to the prior
    //    row's entry_hash.
    const trailing = trailingPrevHash(row.canonical_payload);
    const expectedTrailing = prevEntry ?? GENESIS;
    if (trailing !== expectedTrailing) {
      failures.push({
        check: "chain_adjacency",
        reason: prevEntry === null ? "first_row_not_genesis" : "prev_hash_mismatch",
        subject_id: row.id,
        expected: expectedTrailing,
        actual: trailing ?? "(none)",
      });
    }
    prevEntry = row.entry_hash;
  }

  // ── Check 3+4 — envelope integrity + chain↔envelope binding.
  // Index context_envelopes by request_id for O(1) lookup.
  const envByReq = new Map<string, ExportBundleContextEnvelopeRow>();
  for (const env of bundle.context_envelopes ?? []) {
    envByReq.set(env.request_id, env);
  }

  let envelopesMatched = 0;
  for (const env of bundle.context_envelopes ?? []) {
    // 3. sha256(canonicalize(envelope.envelope)) must equal env.envelope_hash.
    const r = await verifyContextEnvelope(env.envelope, env.envelope_hash);
    if (!r.ok) {
      failures.push({
        check: "envelope_hash_recompute",
        reason: r.reason,
        subject_id: env.request_id,
        expected: env.envelope_hash,
        actual: r.actualHash,
        detail: r.reason === "build_error" ? r.buildError : undefined,
      });
    } else {
      envelopesMatched += 1;
    }
  }

  // 4. For every eval row that committed to an envelope_hash, there must be
  //    a matching context_envelopes row, and the two hashes must match.
  for (const row of bundle.evaluations) {
    if (!row.envelope_hash) continue;
    const env = envByReq.get(row.request_id);
    if (!env) {
      failures.push({
        check: "envelope_chain_binding",
        reason: "missing_envelope_row",
        subject_id: row.id,
        expected: row.envelope_hash,
        detail: `No context_envelopes row for request_id=${row.request_id}`,
      });
      continue;
    }
    if (!hexEq(row.envelope_hash, env.envelope_hash)) {
      failures.push({
        check: "envelope_chain_binding",
        reason: "hash_mismatch",
        subject_id: row.id,
        expected: row.envelope_hash,
        actual: env.envelope_hash,
      });
    }
  }

  // ── Check 6+7 — governance_change_transitions hash chain (opt-in).
  // Each row carries event_hash + prev_event_hash; the canonical payload is
  // a deterministic pipe-delimited string of (change_id, seq, from, to,
  // actor_kind, actor_id, justification, prev||"genesis"). See
  // governance_record_transition() in 20260520140000.
  // Adjacency walks per change_id, not globally — the substrate chains
  // within each governed_change independently.
  const govTransitions = bundle.governance_transitions ?? [];
  let governanceVerified = 0;
  // Sort the verifier's view by (change_id, seq) so a caller that supplied
  // an out-of-order array still gets a deterministic per-change walk.
  const sortedGov = [...govTransitions].sort((a, b) => {
    if (a.change_id !== b.change_id) return a.change_id < b.change_id ? -1 : 1;
    return a.seq - b.seq;
  });
  const prevByChange = new Map<string, string | null>();
  const lastSeqByChange = new Map<string, number>();
  for (const row of sortedGov) {
    const canonical = [
      row.change_id ?? "",
      String(row.seq),
      row.from_state ?? "",
      row.to_state ?? "",
      row.actor_kind ?? "",
      row.actor_id ?? "",
      row.justification ?? "",
      row.prev_event_hash ?? "genesis",
    ].join("|");
    const recomputed = await sha256Hex(canonical);
    if (!hexEq(recomputed, row.event_hash)) {
      failures.push({
        check: "governance_event_hash_recompute",
        reason: "hash_mismatch",
        subject_id: `${row.change_id}#${row.seq}`,
        expected: row.event_hash,
        actual: recomputed,
      });
    }
    // Per-change adjacency: row N's prev_event_hash must equal row N-1's
    // event_hash; the first row in each chain (seq 1) must have null.
    const expectedPrev = prevByChange.get(row.change_id) ?? null;
    if (row.prev_event_hash !== expectedPrev) {
      failures.push({
        check: "governance_chain_adjacency",
        reason: expectedPrev === null
          ? "first_row_prev_not_null"
          : "prev_hash_mismatch",
        subject_id: `${row.change_id}#${row.seq}`,
        expected: expectedPrev ?? "(null)",
        actual: row.prev_event_hash ?? "(null)",
      });
    }
    // Per-change seq must be strictly monotonic +1. First row of a chain
    // (no prior seq seen in this bundle) is permitted at any seq value —
    // the bundle may legitimately start mid-chain because of a since/until
    // window. The hash chain still walks correctly across the bundle's
    // visible window even when it doesn't start at seq 1; the prev_hash
    // check above is the binding contract.
    const lastSeq = lastSeqByChange.get(row.change_id);
    if (lastSeq !== undefined && row.seq !== lastSeq + 1) {
      failures.push({
        check: "governance_chain_adjacency",
        reason: "seq_gap",
        subject_id: `${row.change_id}#${row.seq}`,
        expected: String(lastSeq + 1),
        actual: String(row.seq),
        detail: "Per-change seq must increase by 1 — bundle is missing a transition row",
      });
    }
    lastSeqByChange.set(row.change_id, row.seq);
    prevByChange.set(row.change_id, row.event_hash);
    governanceVerified += 1;
  }

  if (failures.length > 0) {
    return { ok: false, failures };
  }

  return {
    ok: true,
    checks: {
      evaluations: bundle.evaluations.length,
      envelopes: bundle.context_envelopes?.length ?? 0,
      signature_verified: true,
      chain_adjacent: true,
      envelopes_matched: envelopesMatched,
      governance_transitions: governanceVerified,
    },
  };
}
