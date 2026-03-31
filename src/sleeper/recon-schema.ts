import { z } from "zod";

export const RECON_VERSION = "1.0" as const;

export const ReconFileSchema = z.object({
  version: z.literal(RECON_VERSION),

  // Metadata
  scout_identity_id: z.string(),
  resolver_identity_id: z.string(),
  target_url: z.string(),
  created_at: z.string().datetime(),

  // S1: Rate Limit Boundary
  rate_limit: z
    .object({
      max_executes_before_429: z.number(),
      window_seconds: z.number(),
      recovery_observed: z.boolean(),
    })
    .optional(),

  // S2: Bond Capacity Boundaries
  bond_capacity: z
    .object({
      risk_multiplier: z.number(),
      tier_1_cap: z.number(),
      max_declared_at_tier_1: z.number(),
      boundary_error_code: z.string(),
    })
    .optional(),

  // S3: Tier Promotion Observation
  tier_promotion: z
    .object({
      qualifying_successes_to_tier_2: z.number(),
      distinct_resolvers_required: z.number(),
      tier_2_bond_cap: z.number().nullable(),
      promotion_trigger: z.string(),
    })
    .optional(),

  // S4: Error Message Leakage
  error_surface: z
    .object({
      errors: z.array(
        z.object({
          input_type: z.string(),
          status_code: z.number(),
          error_code: z.string(),
          error_message: z.string(),
          leaks_internal_info: z.boolean(),
        })
      ),
    })
    .optional(),

  // S5: Nonce and Replay Behavior
  nonce_behavior: z
    .object({
      duplicate_error_code: z.string(),
      ttl_seconds: z.number(),
      nonce_reuse_after_ttl: z.boolean(),
    })
    .optional(),

  // S6: Endpoint Shape Discovery
  endpoint_shape: z
    .object({
      endpoints: z.array(
        z.object({
          path: z.string(),
          status_code: z.number(),
          response_keys: z.array(z.string()),
          exposes_identity_data: z.boolean(),
          exposes_bond_data: z.boolean(),
          exposes_action_data: z.boolean(),
        })
      ),
    })
    .optional(),

  // S7: Timestamp Window Boundary
  timestamp_window: z
    .object({
      past_limit_seconds: z.number(),
      future_limit_seconds: z.number(),
      boundary_behavior: z.string(),
    })
    .optional(),
});

export type ReconFile = z.infer<typeof ReconFileSchema>;
