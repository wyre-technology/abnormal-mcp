/**
 * Tests for Abnormal Security API client utilities
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { getCredentials, buildAuthHeader, resetCredentials } from "../utils/client.js";

describe("getCredentials", () => {
  const originalToken = process.env.ABNORMAL_API_TOKEN;

  beforeEach(() => {
    resetCredentials();
    delete process.env.ABNORMAL_API_TOKEN;
  });

  afterEach(() => {
    if (originalToken !== undefined) {
      process.env.ABNORMAL_API_TOKEN = originalToken;
    } else {
      delete process.env.ABNORMAL_API_TOKEN;
    }
    resetCredentials();
  });

  it("returns null when ABNORMAL_API_TOKEN is not set", () => {
    expect(getCredentials()).toBeNull();
  });

  it("returns credentials object when ABNORMAL_API_TOKEN is set", () => {
    process.env.ABNORMAL_API_TOKEN = "test-token-abc123";
    const creds = getCredentials();
    expect(creds).not.toBeNull();
    expect(creds?.apiToken).toBe("test-token-abc123");
  });
});

describe("buildAuthHeader", () => {
  it("prepends Bearer prefix to a bare token", () => {
    expect(buildAuthHeader("mytoken123")).toBe("Bearer mytoken123");
  });

  it("passes through an already-prefixed Bearer token unchanged", () => {
    expect(buildAuthHeader("Bearer mytoken123")).toBe("Bearer mytoken123");
  });
});
