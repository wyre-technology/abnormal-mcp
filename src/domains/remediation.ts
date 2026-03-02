/**
 * Remediation domain — trigger and check remediation actions.
 *
 * Covers manage_remediation tool.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { abnormalRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";

export const remediationTools: Tool[] = [
  {
    name: "abnormal_remediation_manage",
    description:
      "Trigger or check the status of a remediation action for a specific threat message. Supports requesting remediation (removal from mailboxes) or checking current remediation status.",
    inputSchema: {
      type: "object",
      properties: {
        threatId: {
          type: "string",
          description: "The threat ID (UUID) containing the message to remediate",
        },
        messageId: {
          type: "string",
          description: "The message ID to remediate",
        },
        action: {
          type: "string",
          enum: ["remediate", "unremediate", "status"],
          description:
            "Action to perform: 'remediate' removes the message, 'unremediate' restores it, 'status' checks current state",
        },
      },
      required: ["threatId", "messageId", "action"],
    },
  },
];

export async function handleRemediationTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  switch (name) {
    case "abnormal_remediation_manage": {
      const threatId = args.threatId as string;
      const messageId = args.messageId as string;
      const action = args.action as "remediate" | "unremediate" | "status";

      logger.info("API call: remediation.manage", { threatId, messageId, action });

      const basePath = `/threats/${encodeURIComponent(threatId)}/messages/${encodeURIComponent(messageId)}`;

      if (action === "status") {
        // GET to check remediation status
        const status = await abnormalRequest<Record<string, unknown>>(
          `${basePath}/remediation`
        );
        return {
          content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
        };
      }

      // POST to trigger or undo remediation
      const result = await abnormalRequest<Record<string, unknown>>(
        `${basePath}/remediation`,
        {
          method: "POST",
          body: { action },
        }
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}
