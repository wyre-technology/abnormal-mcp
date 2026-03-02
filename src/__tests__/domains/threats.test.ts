/**
 * Tests for threats domain tools
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { threatTools, handleThreatTool } from "../../domains/threats.js";

// Mock the client module
vi.mock("../../utils/client.js", () => ({
  abnormalRequest: vi.fn(),
  getCredentials: vi.fn(() => ({ apiToken: "test-token" })),
  resetCredentials: vi.fn(),
}));

import { abnormalRequest } from "../../utils/client.js";

describe("threatTools", () => {
  it("exports the correct tool names", () => {
    const names = threatTools.map((t) => t.name);
    expect(names).toContain("abnormal_threats_list");
    expect(names).toContain("abnormal_threats_get");
  });

  it("abnormal_threats_list has correct input schema", () => {
    const tool = threatTools.find((t) => t.name === "abnormal_threats_list");
    expect(tool).toBeDefined();
    expect(tool?.inputSchema.type).toBe("object");
  });

  it("abnormal_threats_get requires threatId", () => {
    const tool = threatTools.find((t) => t.name === "abnormal_threats_get");
    expect(tool?.inputSchema.required).toContain("threatId");
  });
});

describe("handleThreatTool", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("lists threats with default pagination", async () => {
    const mockResponse = {
      threats: [{ threatId: "abc-123" }],
      total: 1,
    };
    vi.mocked(abnormalRequest).mockResolvedValueOnce(mockResponse);

    const result = await handleThreatTool("abnormal_threats_list", {});

    expect(abnormalRequest).toHaveBeenCalledWith("/threats", {
      params: { pageSize: 100, pageNumber: 1 },
    });
    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.threats).toHaveLength(1);
  });

  it("gets a specific threat by ID", async () => {
    const mockThreat = { threatId: "abc-123", attackType: "Phishing" };
    vi.mocked(abnormalRequest).mockResolvedValueOnce(mockThreat);

    const result = await handleThreatTool("abnormal_threats_get", {
      threatId: "abc-123",
    });

    expect(abnormalRequest).toHaveBeenCalledWith("/threats/abc-123");
    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.threatId).toBe("abc-123");
  });

  it("returns error for unknown tool name", async () => {
    const result = await handleThreatTool("abnormal_unknown", {});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown tool");
  });

  it("propagates API errors as error responses", async () => {
    vi.mocked(abnormalRequest).mockRejectedValueOnce(
      new Error("API authentication failed (401)")
    );

    // handleThreatTool itself throws; the outer handler catches it
    await expect(
      handleThreatTool("abnormal_threats_get", { threatId: "bad" })
    ).rejects.toThrow("API authentication failed");
  });
});
