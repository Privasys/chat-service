// Package auth validates the end-user Privasys ID bearer against the
// configured OIDC issuer(s) via JWKS, mirroring the management-service
// verifier so tokens are accepted identically across the platform.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// User is the authenticated identity extracted from the JWT.
type User struct {
	Sub   string
	Email string
	Name  string
}

type ctxKey string

const userKey ctxKey = "chatUser"

// FromContext returns the authenticated user, or nil.
func FromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userKey).(*User)
	return u
}

type issuer struct {
	name      string
	audiences []string
	jwks      keyfunc.Keyfunc
	cancel    context.CancelFunc
}

// Auth validates bearer tokens against one or more OIDC issuers.
type Auth struct {
	issuers []*issuer
	// trustRelaySub accepts the enclave session-relay's X-Privasys-Sub
	// header as the authenticated identity. The relay sets it only for
	// EncAuth-vouched (wallet-signed) sealed sessions and strips any
	// inbound value on every other path, so inside an enclave whose only
	// ingress is the relay it is as strong as the voucher chain — and the
	// browser bearer never has to travel at all. Enable ONLY when this
	// service is exclusively reachable through the relay (TRUST_RELAY_SUB).
	trustRelaySub bool
}

// relaySubHeader is the relay-asserted identity header (see enclave-os
// sessionrelay). Never trusted unless trustRelaySub is enabled.
const relaySubHeader = "X-Privasys-Sub"

// SetTrustRelaySub toggles acceptance of the relay-injected identity.
func (a *Auth) SetTrustRelaySub(v bool) { a.trustRelaySub = v }

type discovery struct {
	JWKSURI string `json:"jwks_uri"`
}

// New resolves each issuer's JWKS via OIDC discovery and returns a verifier.
func New(issuersCSV, audiencesCSV string) (*Auth, error) {
	var auds []string
	for _, a := range strings.Split(audiencesCSV, ",") {
		if a = strings.TrimSpace(a); a != "" {
			auds = append(auds, a)
		}
	}
	a := &Auth{}
	for _, iss := range strings.Split(issuersCSV, ",") {
		iss = strings.TrimSpace(iss)
		if iss == "" {
			continue
		}
		jwksURI, err := discoverJWKS(iss)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		k, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURI}, keyfunc.Override{
			RefreshUnknownKID: rate.NewLimiter(rate.Every(10*time.Second), 1),
		})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("jwks keyfunc for %s: %w", iss, err)
		}
		a.issuers = append(a.issuers, &issuer{name: iss, audiences: auds, jwks: k, cancel: cancel})
	}
	if len(a.issuers) == 0 {
		return nil, fmt.Errorf("no OIDC issuers configured")
	}
	return a, nil
}

// Close stops the background JWKS refreshers.
func (a *Auth) Close() {
	for _, i := range a.issuers {
		if i.cancel != nil {
			i.cancel()
		}
	}
}

// Middleware authenticates the request and stores the User in the context.
// Two accepted identities, in order:
//  1. the session relay's X-Privasys-Sub (wallet-vouched sealed session),
//     when trustRelaySub is enabled;
//  2. a Bearer JWT from the configured OIDC issuer(s).
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.trustRelaySub {
			if sub := strings.TrimSpace(r.Header.Get(relaySubHeader)); sub != "" {
				u := &User{Sub: sub}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
				return
			}
		}
		bearer := r.Header.Get("Authorization")
		if !strings.HasPrefix(bearer, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing Bearer token")
			return
		}
		tok := strings.TrimPrefix(bearer, "Bearer ")

		candidates := a.issuers
		if iss, ok := unsafeIssuer(tok); ok {
			for _, i := range a.issuers {
				if i.name == iss {
					candidates = []*issuer{i}
					break
				}
			}
		}
		var user *User
		var lastErr error
		for _, i := range candidates {
			u, err := i.verify(tok)
			if err == nil {
				user = u
				break
			}
			lastErr = err
		}
		if user == nil {
			writeErr(w, http.StatusUnauthorized, errString(lastErr))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	})
}

func (i *issuer) verify(tok string) (*User, error) {
	opts := []jwt.ParserOption{
		jwt.WithIssuer(i.name),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30 * time.Second),
	}
	var token *jwt.Token
	var err error
	if len(i.audiences) == 0 {
		token, err = jwt.Parse(tok, i.jwks.Keyfunc, opts...)
	} else {
		for _, aud := range i.audiences {
			token, err = jwt.Parse(tok, i.jwks.Keyfunc, append(slices.Clone(opts), jwt.WithAudience(aud))...)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	u := &User{}
	if v, ok := claims["sub"].(string); ok {
		u.Sub = v
	}
	if u.Sub == "" {
		return nil, fmt.Errorf("token missing sub")
	}
	if v, ok := claims["email"].(string); ok {
		u.Email = v
	}
	for _, key := range []string{"name", "preferred_username", "nickname"} {
		if v, ok := claims[key].(string); ok && v != "" {
			u.Name = v
			break
		}
	}
	return u, nil
}

func discoverJWKS(iss string) (string, error) {
	url := strings.TrimRight(iss, "/") + "/.well-known/openid-configuration"
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", fmt.Errorf("oidc discovery %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery %s: status %d", url, resp.StatusCode)
	}
	var d discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", fmt.Errorf("parse discovery: %w", err)
	}
	if d.JWKSURI == "" {
		return "", fmt.Errorf("discovery %s missing jwks_uri", url)
	}
	return d.JWKSURI, nil
}

// unsafeIssuer reads the iss claim without verifying the signature, used
// only to route to the right issuer's keyfunc.
func unsafeIssuer(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return "", false
		}
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Iss == "" {
		return "", false
	}
	return c.Iss, true
}

func errString(err error) string {
	if err == nil {
		return "unauthorized"
	}
	return err.Error()
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
