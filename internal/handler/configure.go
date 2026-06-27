package handler

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// PersistedConfig is the runtime configuration delivered via POST /configure
// and the shape persisted to the sealed /data volume. Container apps receive
// no env beyond $PORT, so environment-specific values (notably the
// management-service base URL — api-test on dev, api on prod) arrive here.
type PersistedConfig struct {
	MgmtBaseURL string `json:"mgmt_base_url,omitempty"`
}

// configure handles POST /configure: persist the delivered config to the
// sealed volume and apply the live-swappable parts. Auth-gated (the owner's
// bearer flows through the management-service RPC relay). Idempotent.
func (d Deps) configure(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	var p PersistedConfig
	if err := json.Unmarshal(body, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if p.MgmtBaseURL != "" {
		d.Mgmt.SetBase(p.MgmtBaseURL)
	}
	if err := savePersistedConfig(d.ConfigFile, p); err != nil {
		log.Printf("[configure] persist failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist configuration"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"mgmt_base_url": d.Mgmt.Base(),
	})
}

// LoadPersistedConfig reads the persisted config; a missing file yields a
// zero value and no error.
func LoadPersistedConfig(path string) (PersistedConfig, error) {
	var p PersistedConfig
	if path == "" {
		return p, nil
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, err
	}
	if err := json.Unmarshal(buf, &p); err != nil {
		return p, err
	}
	return p, nil
}

// savePersistedConfig atomically writes the config with 0600 perms.
func savePersistedConfig(path string, p PersistedConfig) error {
	if path == "" {
		return nil
	}
	buf, err := json.Marshal(p)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".chat-config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
