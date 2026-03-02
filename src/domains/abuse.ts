/**
 * Abuse reports domain — user-reported phishing emails.
 *
 * Covers get_abuse_reports tool.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { abnormalRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";

export const abuseTools: Tool[] = [
  {
    name: "abnormal_abuse_list",
    description:
      "List phishing emails reported by users via the Abuse Mailbox. Returns user-submitted reports with analysis results indicating whether Abnormal confirmed the threat.",
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
            "OData filter expression (e.g. 'firstReportedTime gt 2024-01-01T00:00:00Z')",
        },
      },
    },
  },
];

export async function handleAbuseTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  switch (name) {
    case "abnormal_abuse_list": {
      const pageSize = (args.pageSize as number) || 100;
      const pageNumber = (args.pageNumber as number) || 1;
      const filter = args.filter as string | undefined;

      logger.info("API call: abuse.list", { pageSize, pageNumber, filter });

      const params: Record<string, string | number | boolean | undefined> = {
        pageSize,
        pageNumber,
      };
      if (filter) params.filter = filter;

      const response = await abnormalRequest<{
        campaigns: Array<Record<string, unknown>>;
        nextPageNumber?: number;
        total?: number;
      }>("/abuse-mailbox", { params });

      const campaigns = Array.isArray(response)
        ? response
        : (response?.campaigns ?? []);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                campaigns,
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

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}
