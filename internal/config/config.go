// Package config loads chat-service runtime configuration from the
// environment. The service runs as a Privasys container app, so secrets
// (DATABASE_URL, the grant-signing key) arrive as env injected by the
// launcher; sensible localhost defaults keep `go run` workable in dev.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	// Addr is the listen address. The container app binds the platform-injected
	// $PORT; it is required (no hard-coded fallback port).
	Addr string

	// DatabaseURL is the Postgres DSN. In the container app Postgres runs
	// on the sealed /data volume; the default targets the local socket the
	// entrypoint starts.
	DatabaseURL string

	// OIDCIssuer / OIDCAudience validate the end-user bearer (Privasys ID).
	// Comma-separated for multi-issuer rollouts (mirrors management-service).
	OIDCIssuer   string
	OIDCAudience string

	// MgmtBaseURL is the management-service control-plane base. chat-service
	// reads instance discovery (incl. the fleet tool_policy) and validates
	// enclave apps from here. It never writes consumer state there.
	MgmtBaseURL string

	// Grant* configure the signed tool-grant minted for the enclave.
	GrantIssuer  string        // iss claim (this service's identity)
	GrantTTL     time.Duration // grant lifetime (short)
	GrantKeyPEM  string        // EC P-256 private key (PEM). Empty → use GrantKeyFile.
	GrantKeyFile string        // PEM path; generated + sealed here on first boot.
	GrantKID     string        // key id advertised in JWKS + grant header

	// CORSOrigins is the allowed browser origin list for the chat front-end.
	CORSOrigins []string

	// ConfigFile is where POST /configure persists runtime-delivered config
	// (on the sealed /data volume) so it survives restarts. Container apps get
	// no env injection beyond $PORT, so env-specific values like MgmtBaseURL
	// arrive via configure-then-freeze.
	ConfigFile string
}

func Load() (*Config, error) {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		return nil, fmt.Errorf("PORT is required")
	}
	c := &Config{
		Addr:        ":" + port,
		DatabaseURL: getenv("DATABASE_URL", "postgres://postgres@127.0.0.1:5432/chat?sslmode=disable"),
		// The Privasys IdP is shared across environments, so it is a safe
		// default — container apps receive no env, and a required-but-unset
		// issuer would stop the app booting. Override via OIDC_ISSUER.
		OIDCIssuer:   getenv("OIDC_ISSUER", "https://privasys.id"),
		OIDCAudience: os.Getenv("OIDC_AUDIENCE"),
		MgmtBaseURL:  strings.TrimRight(getenv("MGMT_BASE_URL", "https://api.developer.privasys.org"), "/"),
		GrantIssuer:  getenv("GRANT_ISSUER", "https://api.chat.privasys.org"),
		GrantTTL:     getdur("GRANT_TTL", 5*time.Minute),
		GrantKeyPEM:  os.Getenv("GRANT_KEY_PEM"),
		GrantKeyFile: getenv("GRANT_KEY_FILE", "/data/grant-key.pem"),
		GrantKID:     getenv("GRANT_KID", "chat-grant-1"),
		CORSOrigins:  splitList(getenv("CORS_ORIGINS", "https://chat.privasys.org,https://chat-test.privasys.org")),
		ConfigFile:   getenv("CONFIG_FILE", "/data/chat-config.json"),
	}
	if c.OIDCIssuer == "" {
		return nil, fmt.Errorf("OIDC_ISSUER is required")
	}
	return c, nil
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getdur(k string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
