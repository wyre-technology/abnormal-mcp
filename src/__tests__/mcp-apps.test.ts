/**
 * MCP Apps (SEP-1865) contract tests — mirrors the checks an MCP Apps host
 * performs to render the threat card:
 *   1. the renderable tool advertises the UI resource via _meta
 *   2. the ui:// resource lists and reads back as profile=mcp-app HTML
 *   3. buildThreatCard normalizes an Abnormal threat into the card payload
 *      the iframe renders from — read-only by policy, best-effort by design
 */

import { describe, it, expect, vi } from "vitest";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Mock the client so the _card-attachment tests can drive handleThreatTool
// without a live API.
vi.mock("../utils/client.js", () => ({
  abnormalRequest: vi.fn(),
  getCredentials: vi.fn(() => ({ apiToken: "test-token" })),
}));

import { abnormalRequest } from "../utils/client.js";
import { threatTools, handleThreatTool } from "../domains/threats.js";
import { messageTools } from "../domains/messages.js";
import { remediationTools } from "../domains/remediation.js";
import { abuseTools } from "../domains/abuse.js";
import { caseTools } from "../domains/cases.js";
import { listResources, readResource } from "../resources.js";
import {
  buildThreatCard,
  applyBrandInjection,
  THREAT_CARD_RESOURCE_URI,
  MCP_APP_RESOURCE_MIME,
} from "../card.builder.js";
import { THREAT_CARD_HTML } from "../generated/threat-card-html.js";

const RENDERABLE_TOOLS = ["abnormal_threats_get"];

function getAllTools(): Tool[] {
  return [
    ...threatTools,
    ...messageTools,
    ...remediationTools,
    ...abuseTools,
    ...caseTools,
  ];
}

describe("MCP Apps threat card", () => {
  describe("tool _meta advertisement", () => {
    it.each(RENDERABLE_TOOLS)("%s links the card via _meta", (name) => {
      const tool = getAllTools().find((t) => t.name === name);
      expect(tool).toBeDefined();
      // Canonical flat key (ext-apps RESOURCE_URI_META_KEY) …
      expect(tool?._meta?.["ui/resourceUri"]).toBe(THREAT_CARD_RESOURCE_URI);
      // … and the nested form registerAppTool also emits.
      expect((tool?._meta?.ui as { resourceUri?: string })?.resourceUri).toBe(
        THREAT_CARD_RESOURCE_URI
      );
    });

    it("no other tools carry UI metadata", () => {
      const others = getAllTools().filter(
        (t) => t._meta && !RENDERABLE_TOOLS.includes(t.name)
      );
      expect(others).toEqual([]);
    });
  });

  describe("ui:// resource", () => {
    it("is listed with the MCP Apps MIME type", () => {
      const card = listResources().find(
        (r) => r.uri === THREAT_CARD_RESOURCE_URI
      );
      expect(card?.mimeType).toBe(MCP_APP_RESOURCE_MIME);
    });

    it("reads back as profile=mcp-app HTML containing the card app", () => {
      const content = readResource(THREAT_CARD_RESOURCE_URI);
      expect(content.mimeType).toBe(MCP_APP_RESOURCE_MIME);
      // No MCP_BRAND_* env set → the embedded HTML is served byte-identical.
      expect(content.text).toBe(THREAT_CARD_HTML);
      expect(content.text).toContain("card__bar");
      // The injection marker must survive the vite build exactly once.
      expect(content.text.match(/BRAND_INJECT/g)).toHaveLength(1);
      // The vite build must have inlined the bridge script — a bare <script src>
      // would be unloadable from a resources/read HTML string.
      expect(content.text).not.toContain('src="./threat-card.ts"');
    });

    it("serves neutral defaults with no operator identity", () => {
      const { text } = readResource(THREAT_CARD_RESOURCE_URI);
      expect(text).not.toMatch(/WYRE/i);
      expect(text).not.toContain("00c9db"); // WYRE cyan
      expect(text).not.toContain("ede947"); // WYRE yellow
      expect(text).not.toContain("fonts.googleapis.com"); // no external fetches
    });

    it("injects MCP_BRAND_* env vars into the served HTML", () => {
      vi.stubEnv("MCP_BRAND_NAME", "Acme MSP");
      vi.stubEnv("MCP_BRAND_PRIMARY_COLOR", "#ff0000");
      try {
        const { text } = readResource(THREAT_CARD_RESOURCE_URI);
        expect(text).toContain(
          '<script>window.__BRAND__={"name":"Acme MSP","primaryColor":"#ff0000"}</script>'
        );
        expect(text).not.toContain("BRAND_INJECT");
      } finally {
        vi.unstubAllEnvs();
      }
    });

    it("rejects unknown resource URIs", () => {
      expect(() => readResource("ui://abnormal/nope.html")).toThrow(
        /Unknown resource/
      );
    });
  });

  describe("applyBrandInjection", () => {
    const html = THREAT_CARD_HTML;

    it("replaces the marker with an inline window.__BRAND__ script", () => {
      const out = applyBrandInjection(html, {
        name: "Acme",
        primaryColor: "#123456",
      });
      expect(out).toContain(
        'window.__BRAND__={"name":"Acme","primaryColor":"#123456"}'
      );
      expect(out).not.toContain("BRAND_INJECT");
    });

    it("escapes < so brand values cannot break out of the script tag", () => {
      const out = applyBrandInjection(html, { name: "</script><script>alert(1)" });
      expect(out).not.toContain("</script><script>alert(1)");
      expect(out).toContain("\\u003c/script>\\u003cscript>alert(1)");
    });

    it("returns the HTML unchanged for an empty brand", () => {
      expect(applyBrandInjection(html, {})).toBe(html);
      expect(applyBrandInjection(html, { name: "" })).toBe(html);
    });
  });

  describe("buildThreatCard", () => {
    const threat = {
      threatId: "184712ab-6d8b-47b3-89d7-a314f8c1e9bc",
      messages: [
        {
          abxMessageId: "4551618356913732000",
          subject: "Urgent: wire transfer needed today",
          fromAddress: "ceo-spoof@evil.example",
          fromName: "Jane CEO",
          recipientAddress: "controller@acme.example",
          receivedTime: "2026-07-17T09:14:00Z",
          attackType: "Business Email Compromise",
          attackStrategy: "Name Impersonation",
          attackVector: "Text",
          impersonatedParty: "VIP",
          remediationStatus: "Auto-Remediated",
        },
        {
          abxMessageId: "4551618356913732001",
          subject: "Re: wire transfer",
          fromAddress: "ceo-spoof@evil.example",
          recipientAddress: "ap@acme.example",
          attackType: "Business Email Compromise",
          remediationStatus: "Auto-Remediated",
        },
      ],
    };

    it("normalizes the threat detail into a flat, label-resolved card", () => {
      const card = buildThreatCard(threat);
      expect(card).toMatchObject({
        threatId: "184712ab-6d8b-47b3-89d7-a314f8c1e9bc",
        subject: "Urgent: wire transfer needed today",
        from: "Jane CEO <ceo-spoof@evil.example>",
        recipient: "controller@acme.example",
        attackType: "Business Email Compromise",
        attackStrategy: "Name Impersonation",
        attackVector: "Text",
        impersonatedParty: "VIP",
        remediationStatus: "Auto-Remediated",
        receivedTime: "2026-07-17T09:14:00Z",
        messageCount: 2,
      });
      expect(card?.messages).toHaveLength(2);
      expect(card?.messages[1]).toMatchObject({
        subject: "Re: wire transfer",
        from: "ceo-spoof@evil.example",
        recipient: "ap@acme.example",
      });
    });

    it("is read-only: the card carries no write-action defaults", () => {
      const keys = Object.keys(buildThreatCard(threat) ?? {});
      expect(keys.length).toBeGreaterThan(0);
      expect(keys.some((k) => /default|action|remediate/i.test(k))).toBe(false);
    });

    it("caps the messages list and truncates long attacker-controlled text", () => {
      const many = {
        threatId: "t-1",
        messages: Array.from({ length: 8 }, (_, i) => ({
          subject: `${"x".repeat(400)}-${i}`,
        })),
      };
      const card = buildThreatCard(many);
      expect(card?.messageCount).toBe(8);
      expect(card?.messages).toHaveLength(5);
      expect(card?.messages[0].subject).toHaveLength(300);
    });

    it("builds a minimal card when messages are absent", () => {
      const card = buildThreatCard({ threatId: "t-2" });
      expect(card).toEqual({ threatId: "t-2", messageCount: 0, messages: [] });
    });

    it("tolerates malformed message entries (best-effort)", () => {
      const card = buildThreatCard({
        threatId: "t-3",
        messages: [null, "junk", 42, { subject: "ok" }],
      });
      expect(card?.messageCount).toBe(1);
      expect(card?.messages).toEqual([{ subject: "ok" }]);
    });

    it("returns null for payloads that are not a threat", () => {
      expect(buildThreatCard({})).toBeNull();
      expect(buildThreatCard({ threatId: 42 })).toBeNull();
      expect(buildThreatCard(null)).toBeNull();
      expect(buildThreatCard([{ threatId: "t" }])).toBeNull();
      expect(buildThreatCard("nope")).toBeNull();
    });
  });

  describe("abnormal_threats_get _card attachment", () => {
    it("attaches _card to the result without touching the threat payload", async () => {
      const mockThreat = {
        threatId: "abc-123",
        messages: [{ subject: "Phish", fromAddress: "a@b.c" }],
      };
      vi.mocked(abnormalRequest).mockResolvedValueOnce(mockThreat);

      const result = await handleThreatTool("abnormal_threats_get", {
        threatId: "abc-123",
      });
      const parsed = JSON.parse(result.content[0].text);
      // Model-visible payload unchanged apart from the additive _card field.
      const { _card, ...rest } = parsed;
      expect(rest).toEqual(mockThreat);
      expect(_card).toMatchObject({
        threatId: "abc-123",
        subject: "Phish",
        messageCount: 1,
      });
    });

    it("degrades to the plain payload when the card cannot be built", async () => {
      const notACard = { unexpected: "shape" };
      vi.mocked(abnormalRequest).mockResolvedValueOnce(notACard);

      const result = await handleThreatTool("abnormal_threats_get", {
        threatId: "abc-123",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).toEqual(notACard);
      expect(parsed._card).toBeUndefined();
    });
  });
});
