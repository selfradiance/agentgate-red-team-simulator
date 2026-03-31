// S7: Timestamp Window Boundary
// Sends signed requests with timestamp offsets to map acceptance window.
// Requests fail at validation — no bonds or actions created.

import type { ReconFile } from "../recon-schema.js";
import { generateKeypair, signedPostWithTimestamp, type ScoutKeys } from "./scout-client.js";

export const hypothesis = "timestamp_window_exploitation";

export async function probe(
  targetUrl: string,
  apiKey: string,
  scoutKeys: ScoutKeys,
  scoutIdentityId: string,
): Promise<ReconFile["timestamp_window"]> {
  const offsets = [-55, -60, -65, 3, 5, 7]; // seconds
  const results: { offsetSeconds: number; accepted: boolean; statusCode: number }[] = [];

  for (const offsetSec of offsets) {
    const timestampMs = Date.now() + offsetSec * 1000;
    const ephemeral = generateKeypair();
    const body = { publicKey: ephemeral.publicKey };
    const r = await signedPostWithTimestamp(targetUrl, apiKey, scoutKeys, "/v1/identities", body, timestampMs);
    const accepted = r.status >= 200 && r.status < 300;
    results.push({ offsetSeconds: offsetSec, accepted, statusCode: r.status });
  }

  // Derive limits from results
  const pastResults = results.filter((r) => r.offsetSeconds < 0).sort((a, b) => a.offsetSeconds - b.offsetSeconds);
  const futureResults = results.filter((r) => r.offsetSeconds > 0).sort((a, b) => a.offsetSeconds - b.offsetSeconds);

  // Past limit: the boundary where requests start failing
  let pastLimit = 60; // default
  for (const r of pastResults) {
    if (r.accepted) {
      pastLimit = Math.abs(r.offsetSeconds);
    }
  }
  // If the most permissive past offset succeeded, the limit is at or beyond it
  // If none succeeded, use the smallest absolute offset as the limit
  const lastAcceptedPast = pastResults.filter((r) => r.accepted).pop();
  const firstRejectedPast = pastResults.find((r) => !r.accepted);
  if (lastAcceptedPast && firstRejectedPast) {
    pastLimit = Math.abs(lastAcceptedPast.offsetSeconds);
  } else if (!lastAcceptedPast && firstRejectedPast) {
    pastLimit = Math.abs(firstRejectedPast.offsetSeconds) - 1;
  }

  // Future limit: similar logic
  let futureLimit = 5; // default
  const lastAcceptedFuture = futureResults.filter((r) => r.accepted).pop();
  const firstRejectedFuture = futureResults.find((r) => !r.accepted);
  if (lastAcceptedFuture && firstRejectedFuture) {
    futureLimit = lastAcceptedFuture.offsetSeconds;
  } else if (!lastAcceptedFuture && firstRejectedFuture) {
    futureLimit = firstRejectedFuture.offsetSeconds - 1;
  } else if (lastAcceptedFuture && !firstRejectedFuture) {
    futureLimit = lastAcceptedFuture.offsetSeconds;
  }

  // Determine boundary behavior
  const anyRejected = results.some((r) => !r.accepted);
  const boundaryBehavior = anyRejected
    ? `reject_outside_window_past_${pastLimit}s_future_${futureLimit}s`
    : "all_timestamps_accepted";

  return {
    past_limit_seconds: pastLimit,
    future_limit_seconds: futureLimit,
    boundary_behavior: boundaryBehavior,
  };
}
