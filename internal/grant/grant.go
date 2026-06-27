// Package grant mints the signed tool-grant the chat front-end presents
// to the confidential-ai enclave. The grant carries the user's authorised
// MCP tool specs (resolved, base_url included) so the enclave never takes
// a base_url from the browser. It is signed ES256 with this service's key;
// the enclave verifies it against the JWKS published at
// /.well-known/jwks.json (and, because chat-service is itself an enclave
// app, can additionally attest the signer).
package grant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Tool is one authorised MCP server in the grant. Mirrors the enclave's
// agent.Server fields that matter for dispatch + attestation.
type Tool struct {
	Name                     string   `json:"name"`
	Transport                string   `json:"transport"`
	BaseURL                  string   `json:"base_url"`
	AuthMode                 string   `json:"auth_mode"`
	AuthAudience             string   `json:"auth_audience,omitempty"`
	AuthScopes               []string `json:"auth_scopes,omitempty"`
	ExpectedDigest           string   `json:"expected_digest,omitempty"`
	// Verified is true for attestable enclave tools, false for
	// user-supplied off-platform servers (outside attestation).
	Verified                 bool `json:"verified"`
	RequiresUserConfirmation bool `json:"requires_user_confirmation,omitempty"`
}

// Claims is the grant body: standard registered claims + the tool set.
type Claims struct {
	jwt.RegisteredClaims
	Tools []Tool `json:"tools"`
}

// Signer mints and exposes the verification material for tool-grants.
type Signer struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
	ttl    time.Duration
}

// NewSigner loads an EC P-256 key from PEM (inline or file). When both are
// empty it generates an ephemeral key — fine for `go run`, but a restart
// rotates the JWKS, so production must supply GRANT_KEY_PEM/FILE.
func NewSigner(pemInline, pemFile, kid, issuer string, ttl time.Duration) (*Signer, bool, error) {
	var keyPEM []byte
	switch {
	case pemInline != "":
		keyPEM = []byte(pemInline)
	case pemFile != "":
		b, err := os.ReadFile(pemFile)
		if err != nil {
			return nil, false, fmt.Errorf("read grant key file: %w", err)
		}
		keyPEM = b
	default:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, err
		}
		return &Signer{key: key, kid: kid, issuer: issuer, ttl: ttl}, true, nil
	}
	key, err := parseECPrivateKey(keyPEM)
	if err != nil {
		return nil, false, err
	}
	return &Signer{key: key, kid: kid, issuer: issuer, ttl: ttl}, false, nil
}

// Sign returns a compact JWS grant bound to audience (the enclave/instance)
// and subject (the user).
func (s *Signer) Sign(audience, subject string, tools []Tool) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
		Tools: tools,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = s.kid
	return t.SignedString(s.key)
}

// JWKS returns the public verification set as a JWKS document.
func (s *Signer) JWKS() map[string]any {
	pub := s.key.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "EC",
			"crv": "P-256",
			"use": "sig",
			"alg": "ES256",
			"kid": s.kid,
			"x":   b64(pub.X, byteLen),
			"y":   b64(pub.Y, byteLen),
		}},
	}
}

func b64(i *big.Int, size int) string {
	b := i.Bytes()
	if len(b) < size {
		pad := make([]byte, size-len(b))
		b = append(pad, b...)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("grant key: not PEM")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("grant key: not an EC key")
	}
	return ec, nil
}
