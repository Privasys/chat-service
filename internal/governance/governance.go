// Package governance turns a user's saved tools into the authorised grant
// tool set for a given instance, enforcing the fleet's tool_policy.
//
// The grant carries only the user's *added* tools. The fleet's admin
// whitelist is already delivered to the enclave through its existing tool
// configuration, and the enclave unions the two; this keeps the whitelist's
// base_url/auth on the control-plane side and out of a browser-presented
// token.
package governance

import (
	"context"
	"strings"

	"github.com/Privasys/chat-service/internal/grant"
	"github.com/Privasys/chat-service/internal/mgmt"
	"github.com/Privasys/chat-service/internal/store"
)

// Policy modes (fleet tool_policy). Unknown/empty is treated as Locked.
const (
	PolicyLocked      = "locked"
	PolicyEnclaveOnly = "enclave_only"
	PolicyOpen        = "open"
)

type appResolver interface {
	ResolveEnclaveApp(ctx context.Context, idOrAlias string) (*mgmt.App, error)
}

// Resolve computes the authorised grant tools for userSub on inst.
//
//   - locked        → no user tools (admin whitelist only).
//   - enclave_only  → only kind=enclave that resolve to an attestable app.
//   - open          → enclave tools plus acknowledged external tools.
//
// Only enabled tools are included. Tools that cannot be admitted under the
// policy are skipped (not an error) so one bad entry never breaks the turn.
func Resolve(ctx context.Context, res appResolver, inst *mgmt.Instance, tools []store.UserTool) []grant.Tool {
	policy := normalize(inst.ToolPolicy)
	if policy == PolicyLocked {
		return nil
	}
	var out []grant.Tool
	for i := range tools {
		t := &tools[i]
		if !t.Enabled {
			continue
		}
		switch t.Kind {
		case "enclave":
			app, err := res.ResolveEnclaveApp(ctx, t.Ref)
			if err != nil || app == nil || !app.IsEnclave {
				continue // cannot prove enclave-ness → reject
			}
			base := app.Endpoint
			if base == "" && app.GatewayHost != "" {
				base = "https://" + app.GatewayHost
			}
			if base == "" {
				continue
			}
			digest := t.ExpectedDigest
			if digest == "" {
				digest = app.ExpectedDigest
			}
			out = append(out, grant.Tool{
				Name:                     t.Name,
				Transport:                orDefault(t.Transport, "mcp_sse"),
				BaseURL:                  strings.TrimRight(base, "/"),
				AuthMode:                 orDefault(t.AuthMode, "exchange"),
				AuthAudience:             t.AuthAudience,
				AuthScopes:               t.AuthScopes,
				ExpectedDigest:           digest,
				Verified:                 true,
				RequiresUserConfirmation: t.RequiresUserConfirmation,
			})
		case "external":
			if policy != PolicyOpen || t.AcknowledgedAt == nil {
				continue // off-platform only under 'open', only once acknowledged
			}
			out = append(out, grant.Tool{
				Name:                     t.Name,
				Transport:                orDefault(t.Transport, "mcp_sse"),
				BaseURL:                  strings.TrimRight(t.Ref, "/"),
				AuthMode:                 orDefault(t.AuthMode, "none"),
				AuthAudience:             t.AuthAudience,
				AuthScopes:               t.AuthScopes,
				Verified:                 false,
				RequiresUserConfirmation: t.RequiresUserConfirmation,
			})
		}
	}
	return out
}

// Admits reports whether a tool of the given kind may be ADDED under policy.
// (Resolution above is permissive-skip; add-time we reject loudly.)
func Admits(policy, kind string) bool {
	switch normalize(policy) {
	case PolicyLocked:
		return false
	case PolicyEnclaveOnly:
		return kind == "enclave"
	case PolicyOpen:
		return kind == "enclave" || kind == "external"
	default:
		return false
	}
}

func normalize(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case PolicyEnclaveOnly:
		return PolicyEnclaveOnly
	case PolicyOpen:
		return PolicyOpen
	default:
		return PolicyLocked
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
