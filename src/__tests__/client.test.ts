/**
 * Tests for Abnormal Security API client utilities.
 *
 * Key security properties verified:
 * 1. Request-scoped credentials (ALS) take priority over env fallback.
 * 2. No cross-request contamination — one tenant's token cannot leak to another.
 * 3. Stdio mode env fallback still works when no ALS context is active.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getCredentials, buildAuthHeader, runWithCredentials } from "../utils/client.js";

// ── Env fallback (stdio / single-tenant mode) ─────────────────────────────────

describe("getCredentials - env fallback", () => {
  const originalToken = process.env.ABNORMAL_API_TOKEN;

  beforeEach(() => {
    delete process.env.ABNORMAL_API_TOKEN;
  });

  afterEach(() => {
    if (originalToken !== undefined) {
      process.env.ABNORMAL_API_TOKEN = originalToken;
    } else {
      delete process.env.ABNORMAL_API_TOKEN;
    }
  });

  it("returns null when ABNORMAL_API_TOKEN is not set and no ALS context", () => {
    expect(getCredentials()).toBeNull();
  });

  it("returns env credentials when ABNORMAL_API_TOKEN is set and no ALS context", () => {
    process.env.ABNORMAL_API_TOKEN = "env-token-abc123";
    const creds = getCredentials();
    expect(creds).not.toBeNull();
    expect(creds?.apiToken).toBe("env-token-abc123");
  });
});

// ── Request-scoped credentials (gateway / HTTP mode) ─────────────────────────

describe("runWithCredentials + getCredentials - ALS scope", () => {
  beforeEach(() => {
    delete process.env.ABNORMAL_API_TOKEN;
  });

  it("scoped token takes priority over env token", () => {
    process.env.ABNORMAL_API_TOKEN = "env-token-should-not-be-used";
    let seenToken: string | undefined;
    runWithCredentials({ apiToken: "scoped-token-xyz" }, () => {
      seenToken = getCredentials()?.apiToken;
    });
    expect(seenToken).toBe("scoped-token-xyz");
  });

  it("scoped token is available inside the async context", async () => {
    let seenToken: string | undefined;
    await runWithCredentials({ apiToken: "async-scoped-token" }, async () => {
      // Simulate an async hop (like an awaited fetch inside a tool handler)
      await Promise.resolve();
      seenToken = getCredentials()?.apiToken;
    });
    expect(seenToken).toBe("async-scoped-token");
  });

  it("no cross-request contamination — two concurrent contexts stay isolated", async () => {
    const results: string[] = [];

    // Simulate two concurrent requests with different tenant tokens
    await Promise.all([
      runWithCredentials({ apiToken: "tenant-A-token" }, async () => {
        await new Promise((r) => setTimeout(r, 5)); // yield to let tenant-B start
        results.push(`A:${getCredentials()?.apiToken}`);
      }),
      runWithCredentials({ apiToken: "tenant-B-token" }, async () => {
        await new Promise((r) => setTimeout(r, 1));
        results.push(`B:${getCredentials()?.apiToken}`);
      }),
    ]);

    expect(results).toContain("A:tenant-A-token");
    expect(results).toContain("B:tenant-B-token");
    // Neither tenant should see the other's token
    expect(results.find((r) => r.startsWith("A:") && r !== "A:tenant-A-token")).toBeUndefined();
    expect(results.find((r) => r.startsWith("B:") && r !== "B:tenant-B-token")).toBeUndefined();
  });

  it("getCredentials returns null outside an ALS context with no env var", () => {
    // Verify that after runWithCredentials completes, the context is gone
    runWithCredentials({ apiToken: "temporary-token" }, () => { /* no-op */ });
    delete process.env.ABNORMAL_API_TOKEN;
    expect(getCredentials()).toBeNull();
  });
});

// ── buildAuthHeader ───────────────────────────────────────────────────────────

describe("buildAuthHeader", () => {
  it("prepends Bearer prefix to a bare token", () => {
    expect(buildAuthHeader("mytoken123")).toBe("Bearer mytoken123");
  });

  it("passes through an already-prefixed Bearer token unchanged", () => {
    expect(buildAuthHeader("Bearer mytoken123")).toBe("Bearer mytoken123");
  });
});
