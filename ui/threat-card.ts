/**
 * Iframe bridge + renderer for the Abnormal Security threat card
 * (MCP Apps, SEP-1865).
 *
 * Runs inside the host's sandboxed iframe. Uses the official MCP Apps client
 * (`App`) to receive the abnormal_threats_get tool result from the host.
 * The card is READ-ONLY by policy: it renders the threat, it never writes
 * back (remediation is a deliberate, model-mediated action).
 *
 * The server attaches a normalized `_card` payload to abnormal_threats_get
 * results (see src/card.builder.ts) so this renderer never needs to dig
 * through raw API shapes itself.
 *
 * Rendering uses DOM construction (no innerHTML) — subjects, sender names,
 * and addresses are attacker-controlled data, so text only ever lands in
 * text nodes.
 *
 * White-label: the card is neutral by default (no operator identity) and
 * applies an injected `window.__BRAND__` override (set by the MCP server via
 * MCP_BRAND_* env vars, or a gateway per-org) so the same card can render in
 * any operator's brand.
 */
import { App } from "@modelcontextprotocol/ext-apps";

interface Brand {
  name?: string;
  logoUrl?: string;
  primaryColor?: string;
  accentColor?: string;
  bg?: string;
  text?: string;
}
declare global {
  interface Window {
    __BRAND__?: Brand;
  }
}

/** Mirror of ThreatCard in src/card.builder.ts — keep in sync. */
interface ThreatCardMessage {
  subject?: string;
  from?: string;
  recipient?: string;
  attackType?: string;
  remediationStatus?: string;
  receivedTime?: string;
}
interface ThreatCard {
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

const brand: Brand = window.__BRAND__ ?? {};
const brandName = brand.name ?? "";

// Apply any injected brand overrides onto the CSS custom properties.
function applyBrand(): void {
  const root = document.documentElement.style;
  if (brand.primaryColor) root.setProperty("--brand-primary", brand.primaryColor);
  if (brand.accentColor) root.setProperty("--brand-accent", brand.accentColor);
  if (brand.bg) root.setProperty("--brand-bg", brand.bg);
  if (brand.text) root.setProperty("--brand-text", brand.text);
}

const app = new App({ name: "Abnormal Security Threat Card", version: "1.0.0" });

/** Create an element with a class and (safe, text-node) children. */
function el(
  tag: string,
  className = "",
  ...children: Array<Node | string | null>
): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  for (const child of children) {
    if (child == null) continue;
    node.append(child); // strings become text nodes — never parsed as HTML
  }
  return node;
}

function fmtDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function field(label: string, value: string | undefined): HTMLElement | null {
  if (!value) return null;
  return el(
    "div",
    "field",
    el("div", "field__label", label),
    el("div", "field__value", value),
  );
}

function badge(text: string | undefined, cls: string): HTMLElement | null {
  return text ? el("span", `badge ${cls}`, text) : null;
}

function messageEl(m: ThreatCardMessage): HTMLElement {
  const meta = [m.attackType, m.remediationStatus, m.receivedTime && fmtDate(m.receivedTime)]
    .filter(Boolean)
    .join(" · ");
  return el(
    "div",
    "message",
    m.from ? el("div", "message__from", m.from) : null,
    m.subject ?? "(no subject)",
    meta ? el("div", "message__meta", meta) : null,
  );
}

function render(t: ThreatCard): void {
  // Brand identity only renders when a brand was injected — the neutral
  // default shows just the threat id/vendor context in the header.
  let brandId: HTMLElement | null = null;
  if (brandName || brand.logoUrl) {
    brandId = el("span", "brandid");
    if (brand.logoUrl) {
      const logo = document.createElement("img");
      logo.src = brand.logoUrl;
      logo.alt = brandName;
      logo.style.display = "inline-block";
      brandId.append(logo);
    }
    if (brandName) brandId.append(el("span", "brand", brandName));
  }

  const shortId = t.threatId.slice(0, 8);
  const messagesSection = el(
    "div",
    "messages",
    el("div", "messages__h", `Messages (${t.messageCount})`),
  );
  for (const m of t.messages) messagesSection.append(messageEl(m));

  const body = el(
    "div",
    "card__body",
    el("div", "brandrow", brandId, el("span", "threatno", `${shortId} · Abnormal Security`)),
    el("h1", "", t.subject ?? `Threat ${shortId}`),
    el(
      "div",
      "badges",
      badge(t.attackType, "badge--attack"),
      badge(t.remediationStatus, "badge--remediation"),
    ),
    el(
      "div",
      "grid",
      field("From", t.from),
      field("Recipient", t.recipient),
      field("Attack vector", t.attackVector),
      field("Strategy", t.attackStrategy),
      field("Impersonates", t.impersonatedParty),
      field("Received", t.receivedTime && fmtDate(t.receivedTime)),
    ),
    messagesSection,
  );

  const root = document.getElementById("root")!;
  root.replaceChildren(el("div", "card", el("div", "card__bar"), body));
}

// abnormal-mcp returns the threat JSON directly and attaches the normalized
// card to abnormal_threats_get results as _card.
function extractCard(obj: unknown): ThreatCard | null {
  const card = (obj as { _card?: ThreatCard })?._card;
  return card && typeof card.threatId === "string" ? card : null;
}

applyBrand();

// Must be set before connect() so the initial tool-result isn't missed.
app.ontoolresult = (result: { content?: Array<{ type: string; text?: string }> }) => {
  const payload = (result.content ?? []).find((c) => c.type === "text");
  if (!payload?.text) return;
  try {
    const card = extractCard(JSON.parse(payload.text));
    if (card) render(card);
  } catch {
    /* ignore malformed payloads */
  }
};

app.connect();
