// S4: Error Message Leakage
// Sends 8 malformed requests to record error surfaces.
// No bonds, no actions, nothing enters resolution.

import type { ReconFile } from "../recon-schema.js";
import { signedPost, signedPostWithCustomHeaders, type ScoutKeys } from "./scout-client.js";

export const hypothesis = "error_surface_exploitation";

interface ErrorRecord {
  input_type: string;
  status_code: number;
  error_code: string;
  error_message: string;
  leaks_internal_info: boolean;
}

function leaksInfo(msg: string): boolean {
  const leakPatterns = [/stack/i, /at \w+\.\w+/, /node_modules/, /internal/i, /Error:/, /\.ts:/, /\.js:/];
  return leakPatterns.some((p) => p.test(msg));
}

export async function probe(
  targetUrl: string,
  apiKey: string,
  scoutKeys: ScoutKeys,
  scoutIdentityId: string,
): Promise<ReconFile["error_surface"]> {
  const errors: ErrorRecord[] = [];

  // Test 1: Missing x-nonce header
  const r1 = await signedPostWithCustomHeaders(targetUrl, "/v1/bonds/lock", { identityId: scoutIdentityId, amountCents: 100 }, {
    "x-agentgate-key": apiKey,
    "x-agentgate-timestamp": Date.now().toString(),
    "x-agentgate-signature": "invalid",
  });
  errors.push({
    input_type: "missing_nonce",
    status_code: r1.status,
    error_code: String(r1.data.code ?? r1.data.error ?? "UNKNOWN"),
    error_message: String(r1.data.message ?? r1.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r1.data.message ?? "")),
  });

  // Test 2: Missing x-signature header
  const r2 = await signedPostWithCustomHeaders(targetUrl, "/v1/bonds/lock", { identityId: scoutIdentityId, amountCents: 100 }, {
    "x-agentgate-key": apiKey,
    "x-nonce": "test-nonce-1",
    "x-agentgate-timestamp": Date.now().toString(),
  });
  errors.push({
    input_type: "missing_signature",
    status_code: r2.status,
    error_code: String(r2.data.code ?? r2.data.error ?? "UNKNOWN"),
    error_message: String(r2.data.message ?? r2.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r2.data.message ?? "")),
  });

  // Test 3: Missing x-timestamp header
  const r3 = await signedPostWithCustomHeaders(targetUrl, "/v1/bonds/lock", { identityId: scoutIdentityId, amountCents: 100 }, {
    "x-agentgate-key": apiKey,
    "x-nonce": "test-nonce-2",
    "x-agentgate-signature": "invalid",
  });
  errors.push({
    input_type: "missing_timestamp",
    status_code: r3.status,
    error_code: String(r3.data.code ?? r3.data.error ?? "UNKNOWN"),
    error_message: String(r3.data.message ?? r3.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r3.data.message ?? "")),
  });

  // Test 4: Expired timestamp (10 minutes in the past)
  const r4 = await signedPost(targetUrl, apiKey, scoutKeys, "/v1/bonds/lock", { identityId: scoutIdentityId, amountCents: 100 });
  // This uses a valid signature but we need to test with a stale timestamp
  // Use signedPostWithCustomHeaders with a manually crafted old timestamp
  const oldTimestamp = (Date.now() - 600_000).toString();
  const r4b = await signedPostWithCustomHeaders(targetUrl, "/v1/bonds/lock", { identityId: scoutIdentityId, amountCents: 100 }, {
    "x-agentgate-key": apiKey,
    "x-nonce": "test-nonce-3",
    "x-agentgate-timestamp": oldTimestamp,
    "x-agentgate-signature": "invalid-sig-for-old-ts",
  });
  errors.push({
    input_type: "expired_timestamp",
    status_code: r4b.status,
    error_code: String(r4b.data.code ?? r4b.data.error ?? "UNKNOWN"),
    error_message: String(r4b.data.message ?? r4b.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r4b.data.message ?? "")),
  });

  // Test 5: Negative bond amount
  const r5 = await signedPost(targetUrl, apiKey, scoutKeys, "/v1/bonds/lock", {
    identityId: scoutIdentityId,
    amountCents: -100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "test",
  });
  errors.push({
    input_type: "negative_bond_amount",
    status_code: r5.status,
    error_code: String(r5.data.code ?? r5.data.error ?? "UNKNOWN"),
    error_message: String(r5.data.message ?? r5.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r5.data.message ?? "")),
  });

  // Test 6: Oversized payload
  const oversizedPayload = { identityId: scoutIdentityId, amountCents: 100, junk: "x".repeat(100_000) };
  const r6 = await signedPost(targetUrl, apiKey, scoutKeys, "/v1/bonds/lock", oversizedPayload);
  errors.push({
    input_type: "oversized_payload",
    status_code: r6.status,
    error_code: String(r6.data.code ?? r6.data.error ?? "UNKNOWN"),
    error_message: String(r6.data.message ?? r6.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r6.data.message ?? "")),
  });

  // Test 7: Invalid JSON (send raw string)
  const r7 = await signedPostWithCustomHeaders(targetUrl, "/v1/bonds/lock", "not-valid-json" as any, {
    "x-agentgate-key": apiKey,
    "x-nonce": "test-nonce-4",
    "x-agentgate-timestamp": Date.now().toString(),
    "x-agentgate-signature": "invalid",
  });
  errors.push({
    input_type: "invalid_json",
    status_code: r7.status,
    error_code: String(r7.data.code ?? r7.data.error ?? "UNKNOWN"),
    error_message: String(r7.data.message ?? r7.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r7.data.message ?? "")),
  });

  // Test 8: Zero-length bond amount
  const r8 = await signedPost(targetUrl, apiKey, scoutKeys, "/v1/bonds/lock", {
    identityId: scoutIdentityId,
    amountCents: 0,
    currency: "USD",
    ttlSeconds: 300,
    reason: "test",
  });
  errors.push({
    input_type: "zero_bond_amount",
    status_code: r8.status,
    error_code: String(r8.data.code ?? r8.data.error ?? "UNKNOWN"),
    error_message: String(r8.data.message ?? r8.data.error ?? ""),
    leaks_internal_info: leaksInfo(String(r8.data.message ?? "")),
  });

  return { errors };
}
