// Command chat-service is the consumer back-end for chat.privasys.org. It
// runs as a Privasys container app (Postgres on the sealed /data volume)
// and owns per-user MCP tool state, fleet-governed tool resolution, and the
// signed tool-grant the front-end forwards to the confidential-ai enclave.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Privasys/chat-service/internal/auth"
	"github.com/Privasys/chat-service/internal/config"
	"github.com/Privasys/chat-service/internal/grant"
	"github.com/Privasys/chat-service/internal/handler"
	"github.com/Privasys/chat-service/internal/mgmt"
	"github.com/Privasys/chat-service/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()

	// The grant signer has no external dependency; a failure here is a real
	// misconfiguration, so it stays fatal.
	signer, ephemeral, err := grant.NewSigner(cfg.GrantKeyPEM, cfg.GrantKeyFile, cfg.GrantKID, cfg.GrantIssuer, cfg.GrantTTL)
	if err != nil {
		log.Fatalf("grant signer: %v", err)
	}
	if ephemeral {
		log.Printf("WARNING: no GRANT_KEY_PEM/FILE set — using an ephemeral grant key; JWKS rotates on restart")
	}

	// Store + auth depend on the local Postgres and the IdP. If either is not
	// ready we still start (serving /health so the platform routes us, and
	// /healthz reporting the degraded subsystem) instead of crash-looping.
	var startupErrs []string

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Printf("WARNING: store init failed (degraded): %v", err)
		startupErrs = append(startupErrs, "store: "+err.Error())
		st = nil
	} else {
		defer st.Close()
	}

	authn, err := auth.New(cfg.OIDCIssuer, cfg.OIDCAudience)
	if err != nil {
		log.Printf("WARNING: auth init failed (degraded): %v", err)
		startupErrs = append(startupErrs, "auth: "+err.Error())
		authn = nil
	} else {
		defer authn.Close()
	}

	// Apply any config previously delivered via POST /configure (sealed to
	// /data) over the env defaults — notably the management-service base URL,
	// which container apps can't receive from env.
	mgmtBase := cfg.MgmtBaseURL
	if pc, err := handler.LoadPersistedConfig(cfg.ConfigFile); err != nil {
		log.Printf("WARNING: could not read persisted config: %v", err)
	} else if pc.MgmtBaseURL != "" {
		mgmtBase = pc.MgmtBaseURL
		log.Printf("applied persisted mgmt_base_url=%s", mgmtBase)
	}

	h := handler.Router(handler.Deps{
		Store:      st,
		Mgmt:       mgmt.New(mgmtBase),
		Signer:     signer,
		Auth:       authn,
		CORS:       cfg.CORSOrigins,
		StartupErr: strings.Join(startupErrs, "; "),
		ConfigFile: cfg.ConfigFile,
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("chat-service listening on %s (mgmt=%s)", cfg.Addr, cfg.MgmtBaseURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Printf("chat-service stopped")
}
