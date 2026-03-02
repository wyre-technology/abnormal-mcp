# abnormal-mcp

MCP server for [Abnormal Security](https://abnormalsecurity.com/) — AI-powered threat detection, case management, and email remediation.

## Tools

This server uses a decision-tree architecture. Start by calling `abnormal_navigate` to select a domain, then use the domain-specific tools.

### Navigation

| Tool | Description |
|------|-------------|
| `abnormal_navigate` | Navigate to a domain (threats, messages, remediation, abuse, cases) |
| `abnormal_back` | Return to domain selection |

### Threats domain

| Tool | Description |
|------|-------------|
| `abnormal_threats_list` | List detected threat cases (paginated) |
| `abnormal_threats_get` | Get full details of a specific threat by ID |

### Messages domain

| Tool | Description |
|------|-------------|
| `abnormal_messages_list` | List messages within a threat case |
| `abnormal_messages_get` | Get detailed message analysis (headers, URLs, attachments, AI analysis) |

### Remediation domain

| Tool | Description |
|------|-------------|
| `abnormal_remediation_manage` | Trigger or check remediation actions for a message |

### Abuse domain

| Tool | Description |
|------|-------------|
| `abnormal_abuse_list` | List phishing emails reported via the Abuse Mailbox |

### Cases domain

| Tool | Description |
|------|-------------|
| `abnormal_cases_list` | List active security investigation cases |
| `abnormal_cases_get` | Get details of a specific case |

## Authentication

Abnormal Security uses Bearer token authentication.

### Standalone (env mode)

```bash
export ABNORMAL_API_TOKEN=your-api-token
node dist/index.js
```

Generate your token in the Abnormal portal under **Settings > Integrations > API**.

### Gateway mode

When deployed behind the MCP gateway, set `AUTH_MODE=gateway`. The gateway injects the `Authorization: Bearer {token}` header automatically on each request.

## Running

### stdio (for Claude Desktop)

```bash
npm install
npm run build
node dist/index.js
```

### HTTP Streamable (for hosted/gateway deployment)

```bash
MCP_TRANSPORT=http AUTH_MODE=gateway node dist/index.js
```

### Docker

```bash
docker compose up
```

## Development

```bash
npm install
npm run dev          # watch mode
npm test             # run tests
npm run typecheck    # TypeScript type check
```

## License

Apache-2.0
