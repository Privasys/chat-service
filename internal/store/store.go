// Package store is chat-service's persistence layer: a pgx pool over the
// Postgres instance running on the app's sealed /data volume. It owns the
// per-user tool list (user_tools) — the source of truth for a user's MCP
// tools across sessions and devices.
package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned when a tool row does not exist (or is not owned
// by the requesting user).
var ErrNotFound = errors.New("tool not found")

// UserTool is one user-owned MCP tool.
type UserTool struct {
	ID                       uuid.UUID  `json:"id"`
	UserSub                  string     `json:"-"`
	Scope                    string     `json:"scope"`
	Kind                     string     `json:"kind"` // enclave | external
	Ref                      string     `json:"ref"`  // app id/alias | base_url
	Name                     string     `json:"name"`
	Label                    string     `json:"label"`
	Description              string     `json:"description,omitempty"`
	Icon                     string     `json:"icon,omitempty"`
	Transport                string     `json:"transport"`
	AuthMode                 string     `json:"auth_mode"`
	AuthAudience             string     `json:"auth_audience,omitempty"`
	AuthScopes               []string   `json:"auth_scopes,omitempty"`
	ExpectedDigest           string     `json:"expected_digest,omitempty"`
	RequiresUserConfirmation bool       `json:"requires_user_confirmation"`
	Enabled                  bool       `json:"enabled"`
	AcknowledgedAt           *time.Time `json:"acknowledged_at,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

type Store struct {
	pool *pgxpool.Pool
}

// New opens a pgx pool and applies the schema. It waits for Postgres to
// accept connections (it is started in the same container moments earlier),
// so a slow first-boot warmup doesn't crash the service.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	s := &Store{pool: pool}

	var lastErr error
	for i := 0; i < 30; i++ {
		if err := pool.Ping(ctx); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if lastErr != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres not reachable: %w", lastErr)
	}

	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

const cols = `id, user_sub, scope, kind, ref, name, label, description, icon,
	transport, auth_mode, auth_audience, auth_scopes, expected_digest,
	requires_user_confirmation, enabled, acknowledged_at, created_at, updated_at`

func scanTool(row pgx.Row) (*UserTool, error) {
	var t UserTool
	err := row.Scan(&t.ID, &t.UserSub, &t.Scope, &t.Kind, &t.Ref, &t.Name,
		&t.Label, &t.Description, &t.Icon, &t.Transport, &t.AuthMode,
		&t.AuthAudience, &t.AuthScopes, &t.ExpectedDigest,
		&t.RequiresUserConfirmation, &t.Enabled, &t.AcknowledgedAt,
		&t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// List returns all tools owned by userSub, oldest first.
func (s *Store) List(ctx context.Context, userSub string) ([]UserTool, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+cols+` FROM user_tools WHERE user_sub=$1 ORDER BY created_at`, userSub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserTool
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// Insert creates a tool. ID is assigned here (no DB extension required).
func (s *Store) Insert(ctx context.Context, t *UserTool) (*UserTool, error) {
	t.ID = uuid.New()
	if t.Scope == "" {
		t.Scope = "user"
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO user_tools (`+cols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17, now(), now())
		RETURNING `+cols,
		t.ID, t.UserSub, t.Scope, t.Kind, t.Ref, t.Name, t.Label, t.Description,
		t.Icon, t.Transport, t.AuthMode, t.AuthAudience, t.AuthScopes,
		t.ExpectedDigest, t.RequiresUserConfirmation, t.Enabled, t.AcknowledgedAt)
	return scanTool(row)
}

// SetEnabled flips the persisted on/off for a user's tool.
func (s *Store) SetEnabled(ctx context.Context, userSub string, id uuid.UUID, enabled bool) (*UserTool, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE user_tools SET enabled=$3, updated_at=now()
		WHERE id=$1 AND user_sub=$2 RETURNING `+cols, id, userSub, enabled)
	return scanTool(row)
}

// Delete removes a user's tool.
func (s *Store) Delete(ctx context.Context, userSub string, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM user_tools WHERE id=$1 AND user_sub=$2`, id, userSub)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Ping checks DB connectivity (used by /healthz).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
