#!/usr/bin/env node
/**
 * Abnormal Security MCP Server
 *
 * MCP server for Abnormal Security — AI-powered threat detection, case
 * management, and email remediation.
 *
 * Implements a decision-tree architecture where tools are dynamically
 * presented based on the selected domain.
 *
 * Transport:  Set MCP_TRANSPORT=http for HTTP Streamable transport (default: stdio).
 * Auth:       Set AUTH_MODE=gateway for header-based credential injection from
 *             the MCP gateway (gateway injects Authorization: Bearer {token}).
 *             Set AUTH_MODE=env (default) and ABNORMAL_API_TOKEN for standalone use.
 */

import { createServer as createHttpServer, IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";

import { threatTools, handleThreatTool } from "./domains/threats.js";
import { messageTools, handleMessageTool } from "./domains/messages.js";
import { remediationTools, handleRemediationTool } from "./domains/remediation.js";
import { abuseTools, handleAbuseTool } from "./domains/abuse.js";
import { caseTools, handleCaseTool } from "./domains/cases.js";
import { resetCredentials } from "./utils/client.js";
import { logger } from "./utils/logger.js";

// ── Types ────────────────────────────────────────────────────────────────────

type TransportType = "stdio" | "http";
type AuthMode = "env" | "gateway";
type Domain = "threats" | "messages" | "remediation" | "abuse" | "cases";

// ── Domain registry ──────────────────────────────────────────────────────────

const domainDescriptions: Record<Domain, string> = {
  threats: "Threat detection — list and inspect detected threat cases",
  messages: "Message analysis — list and inspect individual emails within a threat",
  remediation: "Remediation — trigger or check email remediation actions",
  abuse: "Abuse mailbox — list phishing emails reported by users",
  cases: "Security cases — list and inspect analyst investigation cases",
};

function getDomainTools(domain: Domain): Tool[] {
  switch (domain) {
    case "threats":
      return threatTools;
    case "messages":
      return messageTools;
    case "remediation":
      return remediationTools;
    case "abuse":
      return abuseTools;
    case "cases":
      return caseTools;
  }
}

async function dispatchDomainTool(
  domain: Domain,
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  switch (domain) {
    case "threats":
      return handleThreatTool(name, args);
    case "messages":
      return handleMessageTool(name, args);
    case "remediation":
      return handleRemediationTool(name, args);
    case "abuse":
      return handleAbuseTool(name, args);
    case "cases":
      return handleCaseTool(name, args);
  }
}

// ── Navigation tools ─────────────────────────────────────────────────────────

const navigateTool: Tool = {
  name: "abnormal_navigate",
  description:
    "Navigate to a specific domain in Abnormal Security. Call this first to select which area you want to work with. After navigation, domain-specific tools will be available.",
  inputSchema: {
    type: "object",
    properties: {
      domain: {
        type: "string",
        enum: ["threats", "messages", "remediation", "abuse", "cases"],
        description: `The domain to navigate to:
- threats: ${domainDescriptions.threats}
- messages: ${domainDescriptions.messages}
- remediation: ${domainDescriptions.remediation}
- abuse: ${domainDescriptions.abuse}
- cases: ${domainDescriptions.cases}`,
      },
    },
    required: ["domain"],
  },
};

const backTool: Tool = {
  name: "abnormal_back",
  description:
    "Return to domain selection. Use this to switch to a different area of Abnormal Security.",
  inputSchema: {
    type: "object",
    properties: {},
  },
};

// ── Server state ─────────────────────────────────────────────────────────────

interface ServerState {
  currentDomain: Domain | null;
}

const state: ServerState = {
  currentDomain: null,
};

// ── MCP server ────────────────────────────────────────────────────────────────

const server = new Server(
  { name: "abnormal-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  if (state.currentDomain === null) {
    return { tools: [navigateTool] };
  }
  return { tools: [backTool, ...getDomainTools(state.currentDomain)] };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    // Navigation
    if (name === "abnormal_navigate") {
      const { domain } = args as { domain: Domain };
      state.currentDomain = domain;
      const toolNames = getDomainTools(domain)
        .map((t) => t.name)
        .join(", ");
      return {
        content: [
          {
            type: "text",
            text: `Navigated to ${domain} domain. Available tools: ${toolNames}`,
          },
        ],
      };
    }

    if (name === "abnormal_back") {
      state.currentDomain = null;
      return {
        content: [
          {
            type: "text",
            text: "Returned to domain selection. Use abnormal_navigate to select a domain: threats, messages, remediation, abuse, cases",
          },
        ],
      };
    }

    // Domain tool dispatch
    const toolArgs = (args ?? {}) as Record<string, unknown>;

    if (name.startsWith("abnormal_threats_")) {
      return dispatchDomainTool("threats", name, toolArgs);
    }
    if (name.startsWith("abnormal_messages_")) {
      return dispatchDomainTool("messages", name, toolArgs);
    }
    if (name.startsWith("abnormal_remediation_")) {
      return dispatchDomainTool("remediation", name, toolArgs);
    }
    if (name.startsWith("abnormal_abuse_")) {
      return dispatchDomainTool("abuse", name, toolArgs);
    }
    if (name.startsWith("abnormal_cases_")) {
      return dispatchDomainTool("cases", name, toolArgs);
    }

    return {
      content: [
        {
          type: "text",
          text: `Unknown tool: ${name}. Use abnormal_navigate to select a domain first.`,
        },
      ],
      isError: true,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error("Tool call failed", { tool: name, error: message });
    return {
      content: [{ type: "text", text: `Error: ${message}` }],
      isError: true,
    };
  }
});

// ── Transports ────────────────────────────────────────────────────────────────

async function startStdioTransport(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Abnormal Security MCP server running on stdio");
}

async function startHttpTransport(): Promise<void> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const host = process.env.MCP_HTTP_HOST || "0.0.0.0";
  const authMode = (process.env.AUTH_MODE as AuthMode) || "env";
  const isGatewayMode = authMode === "gateway";

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
  });

  const httpServer = createHttpServer(
    (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(
        req.url || "/",
        `http://${req.headers.host || "localhost"}`
      );

      // Health check — no auth required
      if (url.pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "ok",
            transport: "http",
            authMode: isGatewayMode ? "gateway" : "env",
            timestamp: new Date().toISOString(),
          })
        );
        return;
      }

      // MCP endpoint
      if (url.pathname === "/mcp") {
        if (isGatewayMode) {
          // Gateway injects Authorization: Bearer {token} directly
          const authorization = req.headers["authorization"] as string | undefined;

          if (!authorization) {
            logger.error("Gateway mode: missing Authorization header");
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                error: "Missing credentials",
                message: "Gateway mode requires Authorization header (Bearer token)",
                required: ["Authorization"],
              })
            );
            return;
          }

          // Strip "Bearer " prefix when storing as the raw token env var
          const token = authorization.startsWith("Bearer ")
            ? authorization.slice(7)
            : authorization;

          resetCredentials();
          process.env.ABNORMAL_API_TOKEN = token;
        }

        transport.handleRequest(req, res);
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] })
      );
    }
  );

  await server.connect(transport);

  await new Promise<void>((resolve) => {
    httpServer.listen(port, host, () => {
      logger.info(`Abnormal Security MCP server listening on http://${host}:${port}/mcp`);
      logger.info(`Health check: http://${host}:${port}/health`);
      logger.info(
        `Auth mode: ${isGatewayMode ? "gateway (Authorization header)" : "env (ABNORMAL_API_TOKEN)"}`
      );
      resolve();
    });
  });

  const shutdown = async () => {
    logger.info("Shutting down Abnormal Security MCP server...");
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
    await server.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const transportType =
    (process.env.MCP_TRANSPORT as TransportType) || "stdio";

  if (transportType === "http") {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled rejection", { promise: String(promise), reason: String(reason) });
  process.exit(1);
});

process.on("uncaughtException", (error) => {
  logger.error("Uncaught exception", { error: error.message });
  process.exit(1);
});

main().catch((err) => {
  logger.error("Startup failed", { error: (err as Error).message });
  process.exit(1);
});
