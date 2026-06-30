# chat-service

Consumer back-end for **chat.privasys.org**. It runs as a Privasys container
app (PostgreSQL on the per-app sealed `/data` volume) and owns the user-scoped
state the chat front-end needs:

- **Per-user MCP tools** — the tools a user adds, persisted across sessions and
  devices (`user_tools`). On/off is server-side here, not browser-only.
- **Fleet-governed resolution** — turns a user's tools into the set authorised
  for a given instance, enforcing the fleet's `tool_policy`
  (`locked` | `enclave_only` | `open`).
- **The tool-grant** — a short-TTL ES256 JWT carrying the resolved tool specs
  (base_url included), bound to `{user, instance}`. The chat front-end forwards
  it to the confidential-ai enclave, which verifies it against the JWKS below
  and builds a per-request tool catalogue from it. The browser never dictates a
  `base_url`.

It is deliberately **not** the chat app's only dependency: management-service
stays the control plane (fleets, the admin tool whitelist, app registry,
instance discovery, attestation) and confidential-ai stays inference-only.
chat-service calls management-service service-to-service to read instance
discovery and to validate that a user-added enclave tool is a real Privasys app.

## Tool kinds & governance

- **enclave** — an attestable Privasys app (the default, preferred path). Carries
  `app_id`/`expected_digest`; the enclave attests it (green badge).
- **external** — an off-platform MCP server. Allowed only under `tool_policy=open`
  and only after the user acknowledges that data leaving the enclave to it is
  not attested or protected. Marked `verified:false`.

## API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | none | liveness (platform readiness probe) |
| `GET` | `/healthz` | none | deep check: reports any degraded subsystem |
| `GET` | `/.well-known/jwks.json` | none | grant-signing public keys |
| `POST` | `/configure` | user | deliver runtime config (e.g. `mgmt_base_url`) |
| `GET` | `/api/v1/me/tools` | user | list the caller's tools |
| `POST` | `/api/v1/me/tools` | user | add a tool (enclave or external) |
| `PATCH` | `/api/v1/me/tools/{id}` | user | enable/disable |
| `DELETE` | `/api/v1/me/tools/{id}` | user | remove |
| `POST` | `/api/v1/instances/{id}/tool-grant` | user | mint the tool-grant |

Auth is the end-user Privasys ID bearer, validated against `OIDC_ISSUER` via
JWKS (same scheme as management-service).

## Configuration

| Env | Default | Notes |
| --- | --- | --- |
| `PORT` | _(required)_ | listen port (`/healthz` probed here); the platform injects it, there is no fallback |
| `DATABASE_URL` | local TCP | set by the entrypoint to the on-`/data` Postgres |
| `OIDC_ISSUER` | `https://privasys.id` | the shared Privasys IdP |
| `OIDC_AUDIENCE` | — | comma-separated; optional |
| `MGMT_BASE_URL` | `https://api.developer.privasys.org` | control-plane base; override per-env via `/configure` |
| `GRANT_KEY_PEM` | — | EC P-256 private key (PEM) override |
| `GRANT_KEY_FILE` | `/data/grant-key.pem` | key path; generated + sealed here on first boot (stable JWKS) |
| `GRANT_KID` | `chat-grant-1` | key id in JWKS + grant header |
| `GRANT_TTL` | `5m` | grant lifetime |
| `GRANT_ISSUER` | `https://api.chat.privasys.org` | grant `iss` |
| `CORS_ORIGINS` | chat.privasys.org, chat-test.privasys.org | allowed browser origins |
| `CONFIG_FILE` | `/data/chat-config.json` | where `/configure` persists runtime config |

As a container app it receives no env beyond `$PORT`: the grant key is generated
once and sealed to `/data`, and environment-specific values (`mgmt_base_url`)
arrive via `POST /configure` (persisted to `/data`, reloaded on restart) — the
configure-then-freeze pattern.

## Build & run

```sh
go build ./...
go test ./...

# container (Postgres + service in one image)
docker build -t chat-service .
```

The grant key is generated once and sealed to `GRANT_KEY_FILE` on the per-app
`/data` volume, so the JWKS is stable across restarts. Set `GRANT_KEY_PEM` only
to supply a specific key. With no `/data` volume (e.g. local `go run`) the key
is ephemeral and the JWKS rotates per restart.

## Status

Standalone for now. Future: it will integrate with the private-rag and drive
apps as enclave-kind tools (no special-casing — they slot into the same
catalogue), and grow conversation persistence.
