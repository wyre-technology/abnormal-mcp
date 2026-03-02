/**
 * Messages domain — messages within threat cases.
 *
 * Covers list_messages and get_message tools.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { abnormalRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";

export const messageTools: Tool[] = [
  {
    name: "abnormal_messages_list",
    description:
      "List messages contained within a specific threat case. Returns message IDs and summary data for all emails associated with the threat.",
    inputSchema: {
      type: "object",
      properties: {
        threatId: {
          type: "string",
          description: "The threat ID (UUID) to list messages for",
        },
      },
      required: ["threatId"],
    },
  },
  {
    name: "abnormal_messages_get",
    description:
      "Get detailed analysis of a specific message within a threat case. Returns full message metadata, headers, URLs, attachments, and AI-based threat analysis.",
    inputSchema: {
      type: "object",
      properties: {
        threatId: {
          type: "string",
          description: "The threat ID (UUID) that contains the message",
        },
        messageId: {
          type: "string",
          description: "The message ID to retrieve (URL-encoded email message ID)",
        },
      },
      required: ["threatId", "messageId"],
    },
  },
];

export async function handleMessageTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  switch (name) {
    case "abnormal_messages_list": {
      const threatId = args.threatId as string;
      logger.info("API call: messages.list", { threatId });

      const response = await abnormalRequest<{
        messages: Array<{ abxMessageId: string; [key: string]: unknown }>;
      }>(`/threats/${encodeURIComponent(threatId)}`);

      // The threat detail endpoint includes messages inline
      const messages = Array.isArray(response)
        ? response
        : (response?.messages ?? []);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ threatId, messages }, null, 2),
          },
        ],
      };
    }

    case "abnormal_messages_get": {
      const threatId = args.threatId as string;
      const messageId = args.messageId as string;
      logger.info("API call: messages.get", { threatId, messageId });

      const message = await abnormalRequest<Record<string, unknown>>(
        `/threats/${encodeURIComponent(threatId)}/messages/${encodeURIComponent(messageId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(message, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}
