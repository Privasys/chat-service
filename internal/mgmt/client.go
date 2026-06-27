// Package mgmt is a thin client for the management-service control plane.
// chat-service reads instance discovery (including the fleet's tool_policy)
// and validates that a user-added enclave tool is a real Privasys app. It
// never writes consumer state to management-service.
package mgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	base string
	http *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: 8 * time.Second},
	}
}

// Instance mirrors the relevant fields of
// GET /api/v1/ai/instances/{idOrAlias}. ToolPolicy is the fleet governance
// mode added on the management-service side (locked|enclave_only|open);
// older deployments omit it → treated as "locked" by the caller.
type Instance struct {
	ID         string `json:"id"`
	FleetID    string `json:"fleet_id"`
	Endpoint   string `json:"endpoint"`
	ToolPolicy string `json:"tool_policy"`
}

// App is the subset of an app record needed to admit it as an enclave tool.
type App struct {
	ID             string `json:"id"`
	IsEnclave      bool   `json:"is_enclave"`
	GatewayHost    string `json:"gateway_host"`
	Endpoint       string `json:"endpoint"`
	ExpectedDigest string `json:"expected_digest"`
	HasMCP         bool   `json:"has_mcp"`
}

// GetInstance fetches a chat instance by id or alias (public endpoint).
func (c *Client) GetInstance(ctx context.Context, idOrAlias string) (*Instance, error) {
	var inst Instance
	if err := c.getJSON(ctx, "/api/v1/ai/instances/"+url.PathEscape(idOrAlias), &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

// ResolveEnclaveApp looks up an app by id/alias and reports whether it is
// an attestable enclave exposing MCP, plus the base_url + expected digest
// the grant needs. Used to admit user-added enclave tools.
//
// NOTE: depends on management-service exposing the resolved fields below on
// GET /api/v1/apps/{idOrAlias}. Until that lands, a lookup that cannot
// prove enclave-ness returns IsEnclave=false so enclave_only safely rejects.
func (c *Client) ResolveEnclaveApp(ctx context.Context, idOrAlias string) (*App, error) {
	var app App
	if err := c.getJSON(ctx, "/api/v1/apps/"+url.PathEscape(idOrAlias), &app); err != nil {
		return nil, err
	}
	if app.ID == "" {
		app.ID = idOrAlias
	}
	return &app, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("mgmt %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("mgmt %s: not found", path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mgmt %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
