/**
 * Cases domain — security investigation cases.
 *
 * Covers list_cases tool.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { abnormalRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";

export const caseTools: Tool[] = [
  {
    name: "abnormal_cases_list",
    description:
      "List all active security investigation cases in Abnormal Security. Cases group related threats for analyst review and workflow management.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: {
          type: "number",
          description: "Number of results per page (default: 100, max: 100)",
        },
        pageNumber: {
          type: "number",
          description: "Page number to retrieve (1-indexed, default: 1)",
        },
        filter: {
          type: "string",
          description:
            "OData filter expression (e.g. 'createdTime gt 2024-01-01T00:00:00Z')",
        },
      },
    },
  },
  {
    name: "abnormal_cases_get",
    description:
      "Get detailed information about a specific security case by ID. Returns case status, analyst notes, associated threats, and timeline.",
    inputSchema: {
      type: "object",
      properties: {
        caseId: {
          type: "number",
          description: "The numeric case ID to retrieve",
        },
      },
      required: ["caseId"],
    },
  },
];

export async function handleCaseTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  switch (name) {
    case "abnormal_cases_list": {
      const pageSize = (args.pageSize as number) || 100;
      const pageNumber = (args.pageNumber as number) || 1;
      const filter = args.filter as string | undefined;

      logger.info("API call: cases.list", { pageSize, pageNumber, filter });

      const params: Record<string, string | number | boolean | undefined> = {
        pageSize,
        pageNumber,
      };
      if (filter) params.filter = filter;

      const response = await abnormalRequest<{
        cases: Array<{ caseId: number; [key: string]: unknown }>;
        nextPageNumber?: number;
        total?: number;
      }>("/cases", { params });

      const cases = Array.isArray(response) ? response : (response?.cases ?? []);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                cases,
                nextPageNumber: response?.nextPageNumber,
                total: response?.total,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    case "abnormal_cases_get": {
      const caseId = args.caseId as number;
      logger.info("API call: cases.get", { caseId });

      const caseDetail = await abnormalRequest<Record<string, unknown>>(
        `/cases/${caseId}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(caseDetail, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}
