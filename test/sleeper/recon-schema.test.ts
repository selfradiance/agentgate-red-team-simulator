import { describe, it, expect } from "vitest";
import {
  ReconFileSchema,
  RECON_VERSION,
  type ReconFile,
} from "../../src/sleeper/recon-schema.js";

const validMetadata = {
  version: RECON_VERSION,
  scout_identity_id: "scout-abc-123",
  resolver_identity_id: "resolver-def-456",
  target_url: "http://127.0.0.1:3000",
  created_at: "2026-03-31T12:00:00.000Z",
};

const fullReconFile: ReconFile = {
  ...validMetadata,
  rate_limit: {
    max_executes_before_429: 10,
    window_seconds: 60,
    recovery_observed: true,
  },
  bond_capacity: {
    risk_multiplier: 1.2,
    tier_1_cap: 100,
    max_declared_at_tier_1: 83,
    boundary_error_code: "INSUFFICIENT_BOND_CAPACITY",
  },
  tier_promotion: {
    qualifying_successes_to_tier_2: 5,
    distinct_resolvers_required: 2,
    tier_2_bond_cap: 500,
    promotion_trigger: "reputation_threshold",
  },
  error_surface: {
    errors: [
      {
        input_type: "missing_nonce",
        status_code: 400,
        error_code: "MISSING_NONCE",
        error_message: "x-nonce header is required",
        leaks_internal_info: false,
      },
    ],
  },
  nonce_behavior: {
    duplicate_error_code: "DUPLICATE_NONCE",
    ttl_seconds: 300,
    nonce_reuse_after_ttl: true,
  },
  endpoint_shape: {
    endpoints: [
      {
        path: "/health",
        status_code: 200,
        response_keys: ["status"],
        exposes_identity_data: false,
        exposes_bond_data: false,
        exposes_action_data: false,
      },
    ],
  },
  timestamp_window: {
    past_limit_seconds: 60,
    future_limit_seconds: 5,
    boundary_behavior: "reject_with_400",
  },
};

describe("ReconFileSchema", () => {
  it("accepts a fully populated recon file", () => {
    const result = ReconFileSchema.safeParse(fullReconFile);
    expect(result.success).toBe(true);
  });

  it("accepts a partial recon file (metadata only, no probe sections)", () => {
    const result = ReconFileSchema.safeParse(validMetadata);
    expect(result.success).toBe(true);
  });

  it("accepts a partial recon file with some probe sections", () => {
    const partial = {
      ...validMetadata,
      rate_limit: {
        max_executes_before_429: 10,
        window_seconds: 60,
        recovery_observed: false,
      },
      error_surface: {
        errors: [],
      },
    };
    const result = ReconFileSchema.safeParse(partial);
    expect(result.success).toBe(true);
  });

  it("rejects a file with wrong version", () => {
    const bad = { ...validMetadata, version: "2.0" };
    const result = ReconFileSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("rejects a file missing required metadata", () => {
    const { scout_identity_id, ...missing } = validMetadata;
    const result = ReconFileSchema.safeParse(missing);
    expect(result.success).toBe(false);
  });

  it("rejects a file with invalid created_at format", () => {
    const bad = { ...validMetadata, created_at: "not-a-date" };
    const result = ReconFileSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("rejects a probe section with missing required fields", () => {
    const bad = {
      ...validMetadata,
      rate_limit: {
        max_executes_before_429: 10,
        // missing window_seconds and recovery_observed
      },
    };
    const result = ReconFileSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("rejects a probe section with wrong field types", () => {
    const bad = {
      ...validMetadata,
      bond_capacity: {
        risk_multiplier: "not_a_number",
        tier_1_cap: 100,
        max_declared_at_tier_1: 83,
        boundary_error_code: "INSUFFICIENT_BOND_CAPACITY",
      },
    };
    const result = ReconFileSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("accepts tier_promotion with null tier_2_bond_cap", () => {
    const withNull = {
      ...validMetadata,
      tier_promotion: {
        qualifying_successes_to_tier_2: 5,
        distinct_resolvers_required: 2,
        tier_2_bond_cap: null,
        promotion_trigger: "not_triggered",
      },
    };
    const result = ReconFileSchema.safeParse(withNull);
    expect(result.success).toBe(true);
  });

  it("exports RECON_VERSION as 1.0", () => {
    expect(RECON_VERSION).toBe("1.0");
  });
});
