// Package handler wires chat-service's HTTP API: per-user tool CRUD, the
// tool-grant endpoint, and the public JWKS. Authentication is the end-user
// Privasys ID bearer; the grant is what the chat front-end forwards to the
// confidential-ai enclave.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	"github.com/Privasys/chat-service/internal/auth"
	"github.com/Privasys/chat-service/internal/governance"
	"github.com/Privasys/chat-service/internal/grant"
	"github.com/Privasys/chat-service/internal/mgmt"
	"github.com/Privasys/chat-service/internal/store"
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// Deps are the collaborators the handlers need.
type Deps struct {
	Store  *store.Store
	Mgmt   *mgmt.Client
	Signer *grant.Signer
	Auth   *auth.Auth
	CORS   []string
}

// Router builds the chi router.
func Router(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   d.CORS,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/healthz", d.healthz)
	r.Get("/.well-known/jwks.json", d.jwks)

	r.Group(func(r chi.Router) {
		r.Use(d.Auth.Middleware)
		r.Get("/api/v1/me/tools", d.listTools)
		r.Post("/api/v1/me/tools", d.addTool)
		r.Patch("/api/v1/me/tools/{id}", d.patchTool)
		r.Delete("/api/v1/me/tools/{id}", d.deleteTool)
		r.Post("/api/v1/instances/{id}/tool-grant", d.toolGrant)
	})
	return r
}

func (d Deps) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := d.Store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (d Deps) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, d.Signer.JWKS())
}

func (d Deps) listTools(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	tools, err := d.Store.List(r.Context(), u.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tools == nil {
		tools = []store.UserTool{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

type addToolReq struct {
	Kind                     string   `json:"kind"`
	Ref                      string   `json:"ref"`
	Name                     string   `json:"name"`
	Label                    string   `json:"label"`
	Description              string   `json:"description"`
	Icon                     string   `json:"icon"`
	Transport                string   `json:"transport"`
	AuthMode                 string   `json:"auth_mode"`
	AuthAudience             string   `json:"auth_audience"`
	AuthScopes               []string `json:"auth_scopes"`
	RequiresUserConfirmation bool     `json:"requires_user_confirmation"`
	// Acknowledged must be true to add an external (off-platform) tool.
	Acknowledged bool `json:"acknowledged"`
	// InstanceID, when set, enforces the fleet tool_policy at add time.
	InstanceID string `json:"instance_id"`
}

func (d Deps) addTool(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	var req addToolReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)
	req.Name = strings.TrimSpace(req.Name)
	req.Ref = strings.TrimSpace(req.Ref)
	if req.Kind != "enclave" && req.Kind != "external" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be 'enclave' or 'external'"})
		return
	}
	if !nameRe.MatchString(req.Name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must match [a-zA-Z0-9_]+"})
		return
	}
	if req.Ref == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ref is required"})
		return
	}

	// Enforce the fleet governance mode when an instance is supplied.
	if req.InstanceID != "" {
		inst, err := d.Mgmt.GetInstance(r.Context(), req.InstanceID)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "instance lookup failed"})
			return
		}
		if !governance.Admits(inst.ToolPolicy, req.Kind) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "the fleet policy does not allow adding this kind of tool",
			})
			return
		}
	}

	t := &store.UserTool{
		UserSub:                  u.Sub,
		Kind:                     req.Kind,
		Ref:                      req.Ref,
		Name:                     req.Name,
		Label:                    orStr(req.Label, req.Name),
		Description:              req.Description,
		Icon:                     req.Icon,
		Transport:                orStr(req.Transport, "mcp_sse"),
		AuthMode:                 req.AuthMode,
		AuthAudience:             req.AuthAudience,
		AuthScopes:               req.AuthScopes,
		RequiresUserConfirmation: req.RequiresUserConfirmation,
		Enabled:                  true,
	}

	switch req.Kind {
	case "enclave":
		app, err := d.Mgmt.ResolveEnclaveApp(r.Context(), req.Ref)
		if err != nil || app == nil || !app.IsEnclave {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "referenced app is not a verifiable Privasys enclave",
			})
			return
		}
		t.ExpectedDigest = app.ExpectedDigest
	case "external":
		if !req.Acknowledged {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "external tools require acknowledgement that data leaves the platform unprotected",
			})
			return
		}
		now := time.Now()
		t.AcknowledgedAt = &now
		if t.AuthMode == "" {
			t.AuthMode = "none"
		}
	}

	created, err := d.Store.Insert(r.Context(), t)
	if err != nil {
		if isUniqueViolation(err) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a tool with that name already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

type patchToolReq struct {
	Enabled *bool `json:"enabled"`
}

func (d Deps) patchTool(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req patchToolReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing to update"})
		return
	}
	updated, err := d.Store.SetEnabled(r.Context(), u.Sub, id, *req.Enabled)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tool not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (d Deps) deleteTool(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	err = d.Store.Delete(r.Context(), u.Sub, id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tool not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) toolGrant(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	instID := chi.URLParam(r, "id")
	inst, err := d.Mgmt.GetInstance(r.Context(), instID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "instance lookup failed"})
		return
	}
	tools, err := d.Store.List(r.Context(), u.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	authorised := governance.Resolve(r.Context(), d.Mgmt, inst, tools)
	token, err := d.Signer.Sign(inst.ID, u.Sub, authorised)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "grant signing failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"grant":      token,
		"tool_count": len(authorised),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func orStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func isUniqueViolation(err error) bool {
	// pgx surfaces SQLSTATE 23505 in the error string; avoid a pgconn
	// dependency in the handler by matching the code substring.
	return strings.Contains(err.Error(), "23505")
}
