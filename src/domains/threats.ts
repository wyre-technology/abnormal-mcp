/**
 * Threats domain — detected threats and cases.
 *
 * Covers list_threats and get_threat tools.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { abnormalRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";

export const threatTools: Tool[] = [
  {
    name: "abnormal_threats_list",
    description:
      "List detected threats and cases from Abnormal Security. Returns a paginated list of threat IDs with summary information.",
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
            "OData filter expression (e.g. 'receivedTime gt 2024-01-01T00:00:00Z')",
        },
      },
    },
  },
  {
    name: "abnormal_threats_get",
    description:
      "Get detailed information about a specific threat case by ID. Returns threat details including classification, severity, and related message IDs.",
    inputSchema: {
      type: "object",
      properties: {
        threatId: {
          type: "string",
          description: "The unique threat ID (UUID format)",
        },
      },
      required: ["threatId"],
    },
  },
];

export async function handleThreatTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  switch (name) {
    case "abnormal_threats_list": {
      const pageSize = (args.pageSize as number) || 100;
      const pageNumber = (args.pageNumber as number) || 1;
      const filter = args.filter as string | undefined;

      logger.info("API call: threats.list", { pageSize, pageNumber, filter });

      const params: Record<string, string | number | boolean | undefined> = {
        pageSize,
        pageNumber,
      };
      if (filter) params.filter = filter;

      const response = await abnormalRequest<{
        threats: Array<{ threatId: string }>;
        nextPageNumber?: number;
        total?: number;
      }>("/threats", { params });

      const threats = Array.isArray(response)
        ? response
        : (response?.threats ?? []);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                threats,
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

    case "abnormal_threats_get": {
      const threatId = args.threatId as string;
      logger.info("API call: threats.get", { threatId });

      const threat = await abnormalRequest<Record<string, unknown>>(
        `/threats/${encodeURIComponent(threatId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(threat, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}
