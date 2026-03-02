/**
 * Tests for cases domain tools
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { caseTools, handleCaseTool } from "../../domains/cases.js";

vi.mock("../../utils/client.js", () => ({
  abnormalRequest: vi.fn(),
  getCredentials: vi.fn(() => ({ apiToken: "test-token" })),
  resetCredentials: vi.fn(),
}));

import { abnormalRequest } from "../../utils/client.js";

describe("caseTools", () => {
  it("exports the correct tool names", () => {
    const names = caseTools.map((t) => t.name);
    expect(names).toContain("abnormal_cases_list");
    expect(names).toContain("abnormal_cases_get");
  });

  it("abnormal_cases_get requires caseId", () => {
    const tool = caseTools.find((t) => t.name === "abnormal_cases_get");
    expect(tool?.inputSchema.required).toContain("caseId");
  });
});

describe("handleCaseTool", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("lists cases with default pagination", async () => {
    const mockResponse = {
      cases: [{ caseId: 42 }],
      total: 1,
    };
    vi.mocked(abnormalRequest).mockResolvedValueOnce(mockResponse);

    const result = await handleCaseTool("abnormal_cases_list", {});

    expect(abnormalRequest).toHaveBeenCalledWith("/cases", {
      params: { pageSize: 100, pageNumber: 1 },
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.cases).toHaveLength(1);
  });

  it("gets a specific case by ID", async () => {
    const mockCase = { caseId: 42, status: "open" };
    vi.mocked(abnormalRequest).mockResolvedValueOnce(mockCase);

    const result = await handleCaseTool("abnormal_cases_get", { caseId: 42 });

    expect(abnormalRequest).toHaveBeenCalledWith("/cases/42");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.caseId).toBe(42);
  });
});
