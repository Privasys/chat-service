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
	"sync"
	"time"
)

type Client struct {
	mu   sync.RWMutex
	base string
	http *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: 8 * time.Second},
	}
}

// SetBase swaps the control-plane base URL at runtime (POST /configure).
func (c *Client) SetBase(baseURL string) {
	c.mu.Lock()
	c.base = strings.TrimRight(baseURL, "/")
	c.mu.Unlock()
}

// Base returns the current control-plane base URL.
func (c *Client) Base() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.base
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

// appResolution mirrors management-service's public AppResolution
// (GET /api/v1/apps/by-name/{name}/resolve): deployment coordinates plus
// the attested image digest, which are public, verifiable facts.
type appResolution struct {
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	ImageDigest string `json:"image_digest"`
	IsEnclave   bool   `json:"is_enclave"`
	HasMCP      bool   `json:"has_mcp"`
}

// GetInstance fetches a chat instance by id or alias (public endpoint).
func (c *Client) GetInstance(ctx context.Context, idOrAlias string) (*Instance, error) {
	var inst Instance
	if err := c.getJSON(ctx, "/api/v1/ai/instances/"+url.PathEscape(idOrAlias), &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

// ResolveEnclaveApp looks up a deployed app by name and reports whether it
// is an attestable enclave exposing MCP, plus the base_url + expected digest
// the grant needs. Used to admit user-added enclave tools.
//
// It uses the public resolution endpoint (no auth): a deployed app's
// hostname and attested image digest are public, verifiable facts. A name
// that does not resolve to a deployed app yields IsEnclave=false so the
// enclave_only policy safely rejects it.
func (c *Client) ResolveEnclaveApp(ctx context.Context, name string) (*App, error) {
	var r appResolution
	if err := c.getJSON(ctx, "/api/v1/apps/by-name/"+url.PathEscape(name)+"/resolve", &r); err != nil {
		return nil, err
	}
	app := &App{
		ID:             name,
		IsEnclave:      r.IsEnclave,
		HasMCP:         r.HasMCP,
		ExpectedDigest: r.ImageDigest,
	}
	if r.Hostname != "" {
		app.GatewayHost = r.Hostname
		app.Endpoint = "https://" + r.Hostname
	}
	return app, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base()+path, nil)
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
