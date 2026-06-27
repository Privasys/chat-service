# chat-service: a Go HTTP back-end with its own PostgreSQL, in one container.
#
# Postgres keeps its data directory on the per-app sealed /data volume, so all
# user state (the per-user MCP tool list) is encrypted at rest under a key only
# the app owner controls — the host, the operator, and Privasys never see the
# plaintext. The platform builds this image reproducibly from the Git commit,
# so the running measurement is verifiable from source.

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/chat-service ./cmd/chat-service

FROM postgres:16-bookworm
# The postgres base ships no CA bundle, so the Go service's outbound HTTPS
# (OIDC discovery/JWKS, management-service) would fail "unknown authority".
# Install ca-certificates so it has a trust store.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /out/chat-service /usr/local/bin/chat-service
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# The platform runs containers on the host network and injects a unique $PORT;
# the service MUST listen on it (the manager's health probe hits
# localhost:$PORT/healthz). 8080 is only a default for local runs.
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
