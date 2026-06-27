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

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	signer, ephemeral, err := grant.NewSigner(cfg.GrantKeyPEM, cfg.GrantKeyFile, cfg.GrantKID, cfg.GrantIssuer, cfg.GrantTTL)
	if err != nil {
		log.Fatalf("grant signer: %v", err)
	}
	if ephemeral {
		log.Printf("WARNING: no GRANT_KEY_PEM/FILE set — using an ephemeral grant key; JWKS rotates on restart")
	}

	authn, err := auth.New(cfg.OIDCIssuer, cfg.OIDCAudience)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	defer authn.Close()

	h := handler.Router(handler.Deps{
		Store:  st,
		Mgmt:   mgmt.New(cfg.MgmtBaseURL),
		Signer: signer,
		Auth:   authn,
		CORS:   cfg.CORSOrigins,
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
