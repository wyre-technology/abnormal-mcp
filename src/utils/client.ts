/**
 * Abnormal Security HTTP client utility.
 *
 * Abnormal Security uses Bearer token auth. In gateway mode the gateway
 * injects the pre-built Authorization header directly (e.g. "Bearer <token>").
 * The env var ABNORMAL_API_TOKEN holds the raw token; the client prepends
 * "Bearer " when building the Authorization header.
 */

import { logger } from "./logger.js";

export interface AbnormalCredentials {
  apiToken: string;
}

/** Base URL for the Abnormal Security API */
export const ABNORMAL_BASE_URL = "https://api.abnormalplatform.com/v1";

let _credentials: AbnormalCredentials | null = null;

/**
 * Resolve credentials from environment variables.
 * Returns null if the required variable is absent.
 */
export function getCredentials(): AbnormalCredentials | null {
  const apiToken = process.env.ABNORMAL_API_TOKEN;
  if (!apiToken) {
    logger.warn("Missing ABNORMAL_API_TOKEN environment variable");
    return null;
  }
  return { apiToken };
}

/**
 * Build the Authorization header value from the raw token.
 * Accepts either a bare token ("abc123") or an already-prefixed
 * value ("Bearer abc123") so gateway-injected headers work transparently.
 */
export function buildAuthHeader(apiToken: string): string {
  if (apiToken.startsWith("Bearer ")) return apiToken;
  return `Bearer ${apiToken}`;
}

/**
 * Make an authenticated request to the Abnormal Security API.
 *
 * @throws Error when credentials are missing or the API returns an error.
 */
export async function abnormalRequest<T>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    params?: Record<string, string | number | boolean | undefined>;
  } = {}
): Promise<T> {
  const creds = getCredentials();
  if (!creds) {
    throw new Error(
      "ABNORMAL_API_TOKEN is required. Set this environment variable to your Abnormal Security API token."
    );
  }

  // Build query string
  let url = `${ABNORMAL_BASE_URL}${path}`;
  if (options.params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(options.params)) {
      if (value !== undefined && value !== null) {
        searchParams.set(key, String(value));
      }
    }
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
  }

  const headers: Record<string, string> = {
    Authorization: buildAuthHeader(creds.apiToken),
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  const fetchOptions: RequestInit = {
    method: options.method || "GET",
    headers,
    signal: AbortSignal.timeout(30_000),
  };

  if (options.body !== undefined) {
    fetchOptions.body = JSON.stringify(options.body);
  }

  logger.debug(`API request: ${fetchOptions.method} ${url}`);

  const response = await fetch(url, fetchOptions);

  if (response.ok) {
    if (response.status === 204) return {} as T;
    const contentType = response.headers.get("content-type");
    if (contentType?.includes("application/json")) {
      return response.json() as Promise<T>;
    }
    return {} as T;
  }

  // Safe error body reading — read text once, then try JSON.parse
  const rawText = await response.text();
  let responseBody: unknown;
  try {
    responseBody = JSON.parse(rawText);
  } catch {
    responseBody = rawText;
  }

  const errorMessage =
    typeof responseBody === "object" &&
    responseBody !== null &&
    "message" in responseBody
      ? String((responseBody as Record<string, unknown>).message)
      : rawText || `HTTP ${response.status}`;

  logger.error(`API error: ${response.status} ${url}`, { body: responseBody });

  if (response.status === 401) {
    throw new Error(
      `Abnormal Security authentication failed (401). Check your ABNORMAL_API_TOKEN. ${errorMessage}`
    );
  }
  if (response.status === 403) {
    throw new Error(
      `Abnormal Security authorization denied (403). Verify your token has the required permissions. ${errorMessage}`
    );
  }
  if (response.status === 404) {
    throw new Error(`Resource not found (404): ${path}. ${errorMessage}`);
  }
  if (response.status === 429) {
    throw new Error(
      `Abnormal Security rate limit exceeded (429). Please retry after a moment. ${errorMessage}`
    );
  }
  if (response.status >= 500) {
    throw new Error(
      `Abnormal Security server error (${response.status}): ${errorMessage}`
    );
  }

  throw new Error(`Abnormal Security API error (${response.status}): ${errorMessage}`);
}

/**
 * Reset cached credentials (useful for testing or credential rotation).
 */
export function resetCredentials(): void {
  _credentials = null;
}
