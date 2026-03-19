// Attack registry — maps scenario IDs to metadata and execute functions

import type { AttackResult } from "./log";
import type { AttackClient } from "./attacks/replay";
import { replayAttacks } from "./attacks/replay";
import { bondCapacityAttacks } from "./attacks/bond-capacity";
import { signatureAttacks } from "./attacks/signature";
import { authorizationAttacks } from "./attacks/authorization";
import { inputValidationAttacks } from "./attacks/input-validation";
import { rateLimitAttacks } from "./attacks/rate-limit";
import { timingAttacks } from "./attacks/timing";
import { protocolAttacks } from "./attacks/protocol";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegistryEntry {
  id: string;
  name: string;
  category: string;
  description: string;
  defenseTargeted: string;
  difficultyTier: "low" | "medium" | "high";
  execute: (client: AttackClient) => Promise<AttackResult>;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const registry = new Map<string, RegistryEntry>();

function register(entry: RegistryEntry): void {
  if (registry.has(entry.id)) {
    throw new Error(`Duplicate registry entry: ${entry.id}`);
  }
  registry.set(entry.id, entry);
}

// ---------------------------------------------------------------------------
// Register existing Stage 1 scenarios (15 total)
// ---------------------------------------------------------------------------

// Category 1: Replay Attacks
register({
  id: "1.1",
  name: "Exact duplicate request",
  category: "Replay Attacks",
  description: "Replay an identical signed request with the same nonce",
  defenseTargeted: "Nonce deduplication",
  difficultyTier: "low",
  execute: replayAttacks[0].execute,
});

register({
  id: "1.2",
  name: "Same signature, fresh nonce",
  category: "Replay Attacks",
  description: "Send a request with a fresh nonce but reuse the old signature",
  defenseTargeted: "Signature-nonce binding",
  difficultyTier: "low",
  execute: replayAttacks[1].execute,
});

register({
  id: "1.3",
  name: "Expired timestamp",
  category: "Replay Attacks",
  description: "Send a signed request with a timestamp 120 seconds in the past",
  defenseTargeted: "Timestamp staleness check",
  difficultyTier: "low",
  execute: replayAttacks[2].execute,
});

register({
  id: "1.4",
  name: "Timestamp at exact boundary",
  category: "Replay Attacks",
  description: "Send a signed request with a timestamp at the exact 60s staleness boundary",
  defenseTargeted: "Off-by-one in staleness check",
  difficultyTier: "medium",
  execute: replayAttacks[3].execute,
});

register({
  id: "1.5",
  name: "Future timestamp",
  category: "Replay Attacks",
  description: "Send a signed request with a timestamp 10s in the future (>5s tolerance)",
  defenseTargeted: "Future timestamp rejection",
  difficultyTier: "medium",
  execute: replayAttacks[4].execute,
});

// Category 2: Bond Capacity
register({
  id: "2.1",
  name: "Over-commit exposure",
  category: "Bond Capacity",
  description: "Execute an action with exposure exceeding bond capacity (1.2x multiplier)",
  defenseTargeted: "Bond capacity enforcement",
  difficultyTier: "low",
  execute: bondCapacityAttacks[0].execute,
});

register({
  id: "2.2",
  name: "Double-resolve",
  category: "Bond Capacity",
  description: "Resolve an already-resolved action a second time",
  defenseTargeted: "Action state machine",
  difficultyTier: "low",
  execute: bondCapacityAttacks[1].execute,
});

register({
  id: "2.3",
  name: "Act on expired bond",
  category: "Bond Capacity",
  description: "Execute an action against a bond after its TTL has expired",
  defenseTargeted: "Bond TTL enforcement",
  difficultyTier: "medium",
  execute: bondCapacityAttacks[2].execute,
});

register({
  id: "2.4",
  name: "Zero-amount bond",
  category: "Bond Capacity",
  description: "Lock a bond with amountCents = 0",
  defenseTargeted: "Zod + CHECK constraint on amount_cents",
  difficultyTier: "medium",
  execute: bondCapacityAttacks[3].execute,
});

register({
  id: "2.5",
  name: "Exhaust bond via 1.2x multiplier rounding",
  category: "Bond Capacity",
  description: "Probe the exact boundary of the 1.2x capacity rule (83 vs 84 cents on 100-cent bond)",
  defenseTargeted: "Capacity rounding boundary",
  difficultyTier: "high",
  execute: bondCapacityAttacks[4].execute,
});

register({
  id: "2.6",
  name: "Multi-action bond exhaustion",
  category: "Bond Capacity",
  description: "Execute action A at near-max exposure, then try action B with the same exposure",
  defenseTargeted: "Multi-action capacity accounting",
  difficultyTier: "high",
  execute: bondCapacityAttacks[5].execute,
});

register({
  id: "2.7",
  name: "Resolve then re-execute on released bond",
  category: "Bond Capacity",
  description: "Execute, resolve as success (releasing bond), then try to execute again on the same bond",
  defenseTargeted: "Bond lifecycle state machine",
  difficultyTier: "high",
  execute: bondCapacityAttacks[6].execute,
});

// Category 3: Signature Tampering
register({
  id: "3.1",
  name: "Wrong private key",
  category: "Signature Tampering",
  description: "Sign a request with a different keypair than the registered identity",
  defenseTargeted: "Ed25519 signature verification",
  difficultyTier: "low",
  execute: signatureAttacks[0].execute,
});

register({
  id: "3.2",
  name: "Malformed signature",
  category: "Signature Tampering",
  description: "Send a request with a garbage signature string",
  defenseTargeted: "Signature format validation",
  difficultyTier: "low",
  execute: signatureAttacks[1].execute,
});

register({
  id: "3.3",
  name: "Missing signature headers",
  category: "Signature Tampering",
  description: "Send a request with no signature, timestamp, or nonce headers",
  defenseTargeted: "Required header validation",
  difficultyTier: "low",
  execute: signatureAttacks[2].execute,
});

register({
  id: "3.4",
  name: "Valid signature for different endpoint",
  category: "Signature Tampering",
  description: "Sign a request for /v1/bonds/lock but send it to /v1/actions/execute",
  defenseTargeted: "Path bound into signed message",
  difficultyTier: "high",
  execute: signatureAttacks[3].execute,
});

register({
  id: "3.5",
  name: "Header canonicalization abuse",
  category: "Signature Tampering",
  description: "Duplicate x-signature headers, whitespace-padded values, or mixed-case header names",
  defenseTargeted: "Header parsing robustness",
  difficultyTier: "medium",
  execute: signatureAttacks[4].execute,
});

// Category 4: Authorization Boundaries
register({
  id: "4.1",
  name: "Admin endpoint without admin key",
  category: "Authorization Boundaries",
  description: "Access /admin/ban-identity with a regular REST key instead of admin key",
  defenseTargeted: "Admin key separation",
  difficultyTier: "low",
  execute: authorizationAttacks[0].execute,
});

register({
  id: "4.2",
  name: "Resolve another identity's action",
  category: "Authorization Boundaries",
  description: "Identity B tries to resolve an action belonging to identity A",
  defenseTargeted: "Cross-identity authorization",
  difficultyTier: "medium",
  execute: authorizationAttacks[1].execute,
});

register({
  id: "4.3",
  name: "Execute on another identity's bond",
  category: "Authorization Boundaries",
  description: "Identity B tries to execute an action on a bond locked by identity A",
  defenseTargeted: "Bond-to-identity binding",
  difficultyTier: "high",
  execute: authorizationAttacks[2].execute,
});

register({
  id: "4.4",
  name: "Register duplicate public key",
  category: "Authorization Boundaries",
  description: "Register a new identity using a public key that's already registered",
  defenseTargeted: "UNIQUE constraint on public key",
  difficultyTier: "medium",
  execute: authorizationAttacks[3].execute,
});

register({
  id: "4.5",
  name: "Trigger auto-ban then try to act",
  category: "Authorization Boundaries",
  description: "Accumulate malicious resolutions to trigger auto-ban, then try to lock a bond",
  defenseTargeted: "Auto-ban after 3 malicious resolutions",
  difficultyTier: "high",
  execute: authorizationAttacks[4].execute,
});

// Category 5: Input Validation
register({
  id: "5.1",
  name: "Oversized payload",
  category: "Input Validation",
  description: "Execute a bonded action with a payload string over 4096 bytes",
  defenseTargeted: "Payload size limit",
  difficultyTier: "low",
  execute: inputValidationAttacks[0].execute,
});

register({
  id: "5.2",
  name: "TTL exceeding cap",
  category: "Input Validation",
  description: "Lock a bond with ttlSeconds = 100000 (exceeds 86400s cap)",
  defenseTargeted: "TTL maximum validation",
  difficultyTier: "low",
  execute: inputValidationAttacks[1].execute,
});

register({
  id: "5.3",
  name: "Negative bond amount",
  category: "Input Validation",
  description: "Lock a bond with amountCents = -100",
  defenseTargeted: "Numeric range validation",
  difficultyTier: "low",
  execute: inputValidationAttacks[2].execute,
});

register({
  id: "5.4",
  name: "Type coercion — string where number expected",
  category: "Input Validation",
  description: "Send a string like 'abc' where amountCents (number) is expected",
  defenseTargeted: "Zod type coercion handling",
  difficultyTier: "high",
  execute: inputValidationAttacks[3].execute,
});

register({
  id: "5.5",
  name: "String fields at max-length boundary",
  category: "Input Validation",
  description: "Send actionType at 128/129 chars to probe max-length enforcement",
  defenseTargeted: "Zod max-length validation",
  difficultyTier: "medium",
  execute: inputValidationAttacks[4].execute,
});

register({
  id: "5.6",
  name: "Payload at 4096-byte boundary with multi-byte UTF-8",
  category: "Input Validation",
  description: "Payload of emoji chars near 4096 bytes — tests Buffer.byteLength vs char count",
  defenseTargeted: "Payload byte-length validation with multi-byte chars",
  difficultyTier: "high",
  execute: inputValidationAttacks[5].execute,
});

// Category 6: Rate Limiting
register({
  id: "6.1",
  name: "Exceed execution rate limit",
  category: "Rate Limiting",
  description: "Fire 11 execute requests in rapid succession from one identity (limit is 10/60s)",
  defenseTargeted: "Per-identity rate limiter",
  difficultyTier: "medium",
  execute: rateLimitAttacks[0].execute,
});

register({
  id: "6.2",
  name: "Sybil rate-limit bypass",
  category: "Rate Limiting",
  description: "Create N identities, burst executes from each, all under per-identity limit",
  defenseTargeted: "Aggregate rate limiting across identities",
  difficultyTier: "high",
  execute: rateLimitAttacks[1].execute,
});

register({
  id: "6.3",
  name: "Bucket expiry and re-burst",
  category: "Rate Limiting",
  description: "Hit rate limit, wait for bucket expiry, burst again",
  defenseTargeted: "Rate limit bucket cleanup",
  difficultyTier: "medium",
  execute: rateLimitAttacks[2].execute,
});

// Category 7: Timing & Race Conditions
register({
  id: "7.1",
  name: "Resolve just before sweeper auto-slashes",
  category: "Timing & Race Conditions",
  description: "Race the sweeper — resolve an action just before bond TTL expires",
  defenseTargeted: "Resolution vs sweeper race condition",
  difficultyTier: "high",
  execute: timingAttacks[0].execute,
});

register({
  id: "7.2",
  name: "Parallel resolve attempts",
  category: "Timing & Race Conditions",
  description: "Fire multiple simultaneous resolve requests on the same action",
  defenseTargeted: "WHERE status='open' atomicity",
  difficultyTier: "high",
  execute: timingAttacks[1].execute,
});

register({
  id: "7.3",
  name: "Rapid identity creation (Sybil flood)",
  category: "Timing & Race Conditions",
  description: "Create many identities in rapid succession to test for rate limiting",
  defenseTargeted: "Identity creation rate limiting",
  difficultyTier: "high",
  execute: timingAttacks[2].execute,
});

// Category 8: Protocol Abuse
register({
  id: "8.1",
  name: "Malformed request shape",
  category: "Protocol Abuse",
  description: "GET to POST-only endpoint, or POST with absent body",
  defenseTargeted: "HTTP method and body validation",
  difficultyTier: "low",
  execute: protocolAttacks[0].execute,
});

register({
  id: "8.2",
  name: "Wrong Content-Type",
  category: "Protocol Abuse",
  description: "Valid JSON body with Content-Type: text/plain or application/xml",
  defenseTargeted: "Content-Type validation",
  difficultyTier: "low",
  execute: protocolAttacks[1].execute,
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function getScenario(id: string): RegistryEntry | undefined {
  return registry.get(id);
}

export function getAllScenarioIds(): string[] {
  return Array.from(registry.keys());
}

export function getAllScenarios(): RegistryEntry[] {
  return Array.from(registry.values());
}
