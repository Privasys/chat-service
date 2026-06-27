# Contributing to chat-service

Thank you for your interest in contributing to chat-service, the consumer
back-end for chat.privasys.org.

## Getting Started

1. Fork and clone the repository
2. Install [Go 1.24+](https://go.dev/dl/)
3. Build: `go build ./...`
4. Run tests: `go test ./...`

## Project Structure

| Path | Description |
|------|-------------|
| `cmd/chat-service/` | CLI entrypoint and server lifecycle |
| `internal/config/` | Configuration loading (env + `/configure`) |
| `internal/auth/` | End-user OIDC bearer validation (JWKS) |
| `internal/store/` | Postgres persistence (`user_tools`) |
| `internal/grant/` | ES256 tool-grant minting + JWKS |
| `internal/mgmt/` | management-service client (instance + app resolution) |
| `internal/governance/` | Fleet-policy tool resolution |
| `internal/handler/` | HTTP API |
| `Dockerfile`, `entrypoint.sh` | Container app (Postgres on sealed `/data`) |

## Making Changes

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages
- All commits must be GPG-signed
- Add tests for new functionality

## Submitting a Pull Request

1. Create a feature branch from `main`
2. Make your changes with clear, focused commits
3. Ensure `go test ./...` passes
4. Open a PR against `main` with a description of the change

## Reporting Issues

Please use [GitHub Issues](https://github.com/Privasys/chat-service/issues) to report bugs or request features.

## License

By contributing, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE).
