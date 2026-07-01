# 1.0.0 (2026-04-07)


### Bug Fixes

* **ci:** deploy :latest tag, force revision via env var bump ([6bdfc63](https://github.com/wyre-technology/abnormal-mcp/commit/6bdfc6378848815eb7ebd3981412b8fbf4c9324e))


### Features

* **init:** scaffold Abnormal Security MCP server ([a9df46f](https://github.com/wyre-technology/abnormal-mcp/commit/a9df46f30e7741963e2c4ffa3f6ef2232cbf323a))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Close cross-tenant credential leak: convert HTTP transport from stateful (shared `StreamableHTTPServerTransport` with `sessionIdGenerator: randomUUID()`) to stateless (fresh Server + transport per request, `sessionIdGenerator: undefined`). Replace `process.env.ABNORMAL_API_TOKEN` mutation per request with `AsyncLocalStorage`-based request-scoped credentials via `runWithCredentials()`. Concurrent multi-tenant requests are now fully isolated.
