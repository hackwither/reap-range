# reap-range

A purpose-built, deliberately vulnerable MCP (streamable HTTP) target for [`reap`](https://github.com/hackwither/reap).

## Quick start

```bash
docker build -t reap-range .
docker run --rm -p 8080:8080 -p 8090:8090 reap-range
```

Two listeners come up:

| Target | Port | Paths | Posture |
|---|---|---|---|
| `bad` | `8080` | `/mcp`, `/mcp/gated` | Deliberately insecure |
| `good` | `8090` | `/mcp` | Correctly configured mirror |

## Demo scans

The fully-open bad target — this is the one to GIF, it lights up a High/Medium/Info spread plus a confirmed handshake in a single scan:

```bash
reap -t http://localhost:8080/mcp --authorized
```

The auth-gated bad target — shows reap reporting `auth_state: auth-gated` with an empty error list and **exit 0**, because an endpoint that correctly requires credentials is a recon result rather than a tool failure. Also the one check that only fires against a 401:

```bash
reap -t http://localhost:8080/mcp/gated --authorized
```

The good target — proves the low false-positive rate. `transport-plaintext` is excluded here on purpose (see "Known limitation" below); everything else should be silent except one expected, benign `info` finding:

```bash
reap -t http://localhost:8090/mcp --authorized --exclude transport-plaintext
```

## Range features

| Rule ID | ASI | Bad severity | Fires on | Good behavior |
|---|---|---|---|---|
| `mcp-http-streamable` (protocol confirm) | — | — | `bad/mcp` → high confidence | `good/mcp` → high confidence |
| `mcp-auth-posture` (`auth_state`) | — | — | `bad/mcp` → `open` | `good/mcp` and `bad/mcp/gated` → `auth-gated` |
| `mcp-enumeration-blocked` | — | Info | `bad/mcp/gated`, `good/mcp` (401 on `tools/list`) | expected; records that enumeration was refused rather than unreachable |
| `mcp-unauth-tools-list` | ASI02, ASI03 | High (`exec_shell`) | `bad/mcp` | `good/mcp` gates `tools/list` behind auth |
| `mcp-tool-capability-surface` | ASI09 | Info (full inventory) | `bad/mcp` | silent on `good/mcp`; surface counts appear in the report header |
| `mcp-tmpl-high-risk-tool-names` | ASI02, ASI07 | Medium | `bad/mcp` (`exec_shell`) | `good/mcp` tool names are generic |
| `mcp-dynamic-dispatch` | ASI09 | High | `bad/mcp` (`search_tools` + `run_tool`) | `good/mcp` has no dispatcher-shaped tool |
| `http-cors-wildcard` | ASI03 | High | `bad/mcp` (`ACAO:*` + credentials, seen on the POST response) | `good/mcp` sends no ACAO header |
| `mcp-host-header-validation` | ASI03 | High on loopback, Medium otherwise | `bad/mcp` (any Host accepted) | `good/mcp` 400s on Host mismatch |
| `http-rate-limit-absence` | ASI06 | Low | `bad/mcp` (no headers on either verb) | `good/mcp` sends `Retry-After` |
| `mcp-session-id-entropy` | ASI03 | Medium (`sess001`) | `bad/mcp` | `good/mcp` sends a `secrets.token_urlsafe(32)` ID |
| `mcp-instructions-exposure` | ASI09 | Low | `bad/mcp` (long, "never reveal"/"internal"/"api key") | `good/mcp` instructions are short & generic |
| `mcp-resources-prompts-exposure` (×2) | ASI02 | Low each | `bad/mcp` (200 unauth) | `bad/mcp/gated` and `good/mcp` both 401 |
| `mcp-tmpl-server-header-fingerprint` | ASI09 | Info | `bad/mcp` (`Server: Werkzeug/3.0 Python/3.12.3`) | `good/mcp` sends no `Server` header |
| `mcp-oauth-metadata-posture` (PKCE only) | ASI03 | Low | `bad` host well-known (no `code_challenge_methods_supported`) | `good` host well-known advertises `["S256"]` |
| `mcp-redirect-uri-laxity` | ASI03 | Medium | `bad` host well-known (`https://evil.example/*`) | `good` host well-known has an exact scoped URI |
| `mcp-oauth-bearer-challenge-missing` | ASI03 | Medium | `bad/mcp/gated` only (401 w/o `WWW-Authenticate: Bearer`) | `good/mcp` 401 includes the challenge |
| `transport-plaintext` | ASI04 | Medium | every target (see limitation below) | — |
| `tls-cert-health` | ASI09 | — | not exercised (see limitation below) | — |
| `transport-downgrade` | ASI04 | — | not exercised (see limitation below) | — |

Two notes on where the OAuth checks look. `mcp-oauth-bearer-challenge-missing` reads `WWW-Authenticate` off the **protected resource's own 401**, not off the `/.well-known/*` response, a 200 metadata document has no reason to carry a challenge, and reading it there made the check fire on correctly-configured servers. `mcp-oauth-metadata-posture` now covers PKCE advertisement only.

The OAuth checks (`mcp-oauth-metadata-posture`, `mcp-redirect-uri-laxity`) try the RFC 9728 path-aware location (`/.well-known/oauth-protected-resource/<path>`) first and then fall back to the host root. This range only serves the root documents, so both checks still fire identically whether you point reap at `bad/mcp` or `bad/mcp/gated`. That's why "bad" and "good" OAuth postures live on separate ports rather than separate paths on one host.


### Known limitation: TLS-only checks not covered

`tls-cert-health` and `transport-downgrade` only evaluate `https://` targets. A locally-trusted cert for a bare `docker run` demo would need a local CA (mkcert-style) or a TLS-terminating sidecar — and a self-signed cert would itself trip `tls-cert-health`'s "certificate is self-signed" finding, so it can't demonstrate a *clean* result either way. Not built here; front this range with real TLS if you want to exercise those two checks.

Both report `not-applicable` rather than passing silently, so a scan of this range shows them in the probe tally as declined rather than clean.

Because the whole range is plain HTTP, `transport-plaintext` (ASI04, Medium) fires on every target, including the good one — that's expected, not a false positive on reap's part, and the good-target demo command above excludes it explicitly for that reason.

## Configuration

```
python3 server.py --bad-port 8080 --good-port 8090 [--good-allowed-host HOST:PORT ...]
```

Or via environment variables (used as defaults by the Docker image): `BAD_PORT`, `GOOD_PORT`, `GOOD_ALLOWED_HOST` (comma-separated). `--good-allowed-host` is only needed if you're reaching the good target through a hostname other than `localhost`/`127.0.0.1` (e.g. a custom Docker network alias) — the good listener 400s on any Host header it doesn't recognize, which is the behavior `mcp-host-header-validation` is checking for.
