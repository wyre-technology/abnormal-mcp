/**
 * Threat-card payload builder for the MCP Apps (SEP-1865) UI surface.
 *
 * abnormal_threats_get results get a normalized `_card` object attached
 * (see domains/threats.ts) that the ui:// threat card renders from. The card
 * is progressive enhancement: every step here is best-effort, and a null
 * return simply means the host renders no card while the JSON payload is
 * unchanged.
 *
 * The card is READ-ONLY by policy — email-security remediation is a
 * deliberate, model-mediated action (abnormal_remediation_manage), never a
 * one-click card button.
 */

export const THREAT_CARD_RESOURCE_URI = "ui://abnormal/threat-card.html";

/** MCP Apps resource MIME (RESOURCE_MIME_TYPE in @modelcontextprotocol/ext-apps). */
export const MCP_APP_RESOURCE_MIME = "text/html;profile=mcp-app";

/**
 * Tool `_meta` advertising the card. Carries both the canonical flat key
 * (RESOURCE_URI_META_KEY in ext-apps) and the nested form ext-apps'
 * registerAppTool emits, so any MCP Apps host revision finds it.
 */
export const THREAT_CARD_META = {
  "ui/resourceUri": THREAT_CARD_RESOURCE_URI,
  ui: { resourceUri: THREAT_CARD_RESOURCE_URI },
} as const;

/** Mirror of Brand in ui/threat-card.ts — keep in sync. */
export interface CardBrand {
  name?: string;
  logoUrl?: string;
  primaryColor?: string;
  accentColor?: string;
  bg?: string;
  text?: string;
}

/** The BRAND_INJECT comment marker baked into the card HTML (see ui/index.html). */
const BRAND_INJECT_RE = /<!--\s*BRAND_INJECT:[\s\S]*?-->/;

/**
 * Serve-time brand injection: replace the BRAND_INJECT marker with an inline
 * `window.__BRAND__` script so self-hosters can theme the card without
 * rebuilding the bundle. An empty brand returns the HTML unchanged (the card
 * renders its neutral defaults). `<` is escaped so brand values can never
 * break out of the script tag.
 */
export function applyBrandInjection(html: string, brand: CardBrand): string {
  if (!brand || Object.values(brand).every((v) => !v)) return html;
  const json = JSON.stringify(brand).replace(/</g, "\\u003c");
  return html.replace(BRAND_INJECT_RE, `<script>window.__BRAND__=${json}</script>`);
}

/**
 * Resolve brand overrides from MCP_BRAND_* environment variables. Guarded for
 * runtimes without `process`, where this returns an empty brand and the card
 * serves its neutral defaults.
 */
export function resolveBrandFromEnv(): CardBrand {
  if (typeof process === "undefined" || !process.env) return {};
  const env = process.env;
  const brand: CardBrand = {};
  if (env.MCP_BRAND_NAME) brand.name = env.MCP_BRAND_NAME;
  if (env.MCP_BRAND_LOGO_URL) brand.logoUrl = env.MCP_BRAND_LOGO_URL;
  if (env.MCP_BRAND_PRIMARY_COLOR) brand.primaryColor = env.MCP_BRAND_PRIMARY_COLOR;
  if (env.MCP_BRAND_ACCENT_COLOR) brand.accentColor = env.MCP_BRAND_ACCENT_COLOR;
  if (env.MCP_BRAND_BG) brand.bg = env.MCP_BRAND_BG;
  if (env.MCP_BRAND_TEXT) brand.text = env.MCP_BRAND_TEXT;
  return brand;
}

/** Mirror of ThreatCardMessage in ui/threat-card.ts — keep in sync. */
export interface ThreatCardMessage {
  subject?: string;
  from?: string;
  recipient?: string;
  attackType?: string;
  remediationStatus?: string;
  receivedTime?: string;
}

/** Mirror of ThreatCard in ui/threat-card.ts — keep in sync. */
export interface ThreatCard {
  threatId: string;
  subject?: string;
  from?: string;
  recipient?: string;
  attackType?: string;
  attackStrategy?: string;
  attackVector?: string;
  impersonatedParty?: string;
  remediationStatus?: string;
  receivedTime?: string;
  messageCount: number;
  messages: ThreatCardMessage[];
}

const CARD_MESSAGE_LIMIT = 5;
const CARD_TEXT_MAX_LENGTH = 300;

/** Coerce to a trimmed, length-capped display string, or undefined. */
function str(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const s = value.trim();
  return s ? s.slice(0, CARD_TEXT_MAX_LENGTH) : undefined;
}

/** "Name <address>" when both are present; otherwise whichever exists. */
function fromLabel(name: unknown, address: unknown): string | undefined {
  const n = str(name);
  const a = str(address);
  if (n && a) return `${n} <${a}>`;
  return n ?? a;
}

/** Recipient: prefer the resolved recipientAddress, fall back to toAddresses. */
function recipientLabel(message: Record<string, unknown>): string | undefined {
  const recipient = str(message.recipientAddress);
  if (recipient) return recipient;
  const to = message.toAddresses;
  if (Array.isArray(to)) return str(to[0]);
  return str(to);
}

function toCardMessage(message: Record<string, unknown>): ThreatCardMessage {
  const card: ThreatCardMessage = {};
  const subject = str(message.subject);
  const from = fromLabel(message.fromName, message.fromAddress);
  const recipient = recipientLabel(message);
  const attackType = str(message.attackType);
  const remediationStatus = str(message.remediationStatus);
  const receivedTime = str(message.receivedTime);
  if (subject) card.subject = subject;
  if (from) card.from = from;
  if (recipient) card.recipient = recipient;
  if (attackType) card.attackType = attackType;
  if (remediationStatus) card.remediationStatus = remediationStatus;
  if (receivedTime) card.receivedTime = receivedTime;
  return card;
}

/**
 * Build the renderable card from an abnormal_threats_get payload. The threat
 * detail endpoint returns `{ threatId, messages: [...] }` — Abnormal already
 * resolves everything to flat strings (attackType, remediationStatus, sender
 * names), so no extra lookups are needed. The card headline comes from the
 * first message in the threat; the messages section lists up to
 * CARD_MESSAGE_LIMIT entries.
 */
export function buildThreatCard(threat: unknown): ThreatCard | null {
  if (typeof threat !== "object" || threat === null || Array.isArray(threat)) {
    return null;
  }
  const record = threat as Record<string, unknown>;
  const threatId = str(record.threatId);
  if (!threatId) return null;

  const rawMessages = Array.isArray(record.messages)
    ? record.messages.filter(
        (m): m is Record<string, unknown> =>
          typeof m === "object" && m !== null && !Array.isArray(m)
      )
    : [];

  const card: ThreatCard = {
    threatId,
    messageCount: rawMessages.length,
    messages: rawMessages.slice(0, CARD_MESSAGE_LIMIT).map(toCardMessage),
  };

  // Headline fields from the first message (the threat's representative email).
  const first = rawMessages[0];
  if (first) {
    const subject = str(first.subject);
    const from = fromLabel(first.fromName, first.fromAddress);
    const recipient = recipientLabel(first);
    const attackType = str(first.attackType);
    const attackStrategy = str(first.attackStrategy);
    const attackVector = str(first.attackVector);
    const impersonatedParty = str(first.impersonatedParty);
    const remediationStatus = str(first.remediationStatus);
    const receivedTime = str(first.receivedTime);
    if (subject) card.subject = subject;
    if (from) card.from = from;
    if (recipient) card.recipient = recipient;
    if (attackType) card.attackType = attackType;
    if (attackStrategy) card.attackStrategy = attackStrategy;
    if (attackVector) card.attackVector = attackVector;
    if (impersonatedParty) card.impersonatedParty = impersonatedParty;
    if (remediationStatus) card.remediationStatus = remediationStatus;
    if (receivedTime) card.receivedTime = receivedTime;
  }

  return card;
}
