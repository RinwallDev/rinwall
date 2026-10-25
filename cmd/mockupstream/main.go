// Command mockupstream plays "the real enterprise service": it never
// trusts the proxy blindly, it verifies each capability token itself - a
// biscuit token's full signature chain plus its appended checks
// (internal/capability.Verify). Rather than a single public key hardcoded
// via env var, it fetches the proxy's key-rotation discovery endpoint
// (GET /biscuit-keys) at startup and refreshes it periodically, so a
// signing-key rotation on the proxy side reaches this verifier without a
// synchronized manual update or a restart - see
// internal/capability/keyring.go.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RinwallDev/rinwall/internal/capability"
)

// simulatedLatency lets the load-test harness (cmd/loadtest) decompose
// "what the proxy itself adds" from "how long the upstream API took to
// answer" - everything measured on localhost so far has ~0ms upstream
// latency, which is not what a real enterprise API looks like. Set via
// MOCK_UPSTREAM_LATENCY_MS, applied uniformly to every route so the number
// isn't tool-specific.
var simulatedLatency = func() time.Duration {
	ms, _ := strconv.Atoi(os.Getenv("MOCK_UPSTREAM_LATENCY_MS"))
	return time.Duration(ms) * time.Millisecond
}()

func withSimulatedLatency(h http.Handler) http.Handler {
	if simulatedLatency <= 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(simulatedLatency)
		h.ServeHTTP(w, r)
	})
}

var proxyURL = envOrDefault("JIT_PROXY_URL", "http://127.0.0.1:8080")

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	keysMu sync.RWMutex
	keys   []string
)

func refreshKeys() error {
	resp, err := http.Get(proxyURL + "/biscuit-keys")
	if err != nil {
		return fmt.Errorf("fetch %s/biscuit-keys: %w", proxyURL, err)
	}
	defer resp.Body.Close()
	var body struct {
		Keys []struct {
			PublicKeyHex string `json:"public_key_hex"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode biscuit-keys response: %w", err)
	}
	hexes := make([]string, 0, len(body.Keys))
	for _, k := range body.Keys {
		hexes = append(hexes, k.PublicKeyHex)
	}
	if len(hexes) == 0 {
		return fmt.Errorf("proxy returned zero servable biscuit keys")
	}
	keysMu.Lock()
	keys = hexes
	keysMu.Unlock()
	return nil
}

func currentKeys() []string {
	keysMu.RLock()
	defer keysMu.RUnlock()
	return keys
}

type user struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Tier   string `json:"tier"`
	Status string `json:"status"`
}

var (
	mu    sync.Mutex
	users = map[string]*user{
		"42": {ID: "42", Name: "Priya Shah", Email: "priya@example.com", Tier: "silver", Status: "active"},
		"7":  {ID: "7", Name: "Marco Diaz", Email: "marco@example.com", Tier: "silver", Status: "active"},
	}
)

func verifyToken(authHeader, expectedTool, expectedResource string) error {
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return capability.Verify(token, currentKeys(), expectedTool, expectedResource)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	// Listen first, fetch keys in the background. The proxy and this server
	// each need the other at startup - a zero-config proxy scans this
	// server's tools/list before it will serve anything, and this server
	// needs the proxy's /biscuit-keys before it can verify a capability -
	// so whichever starts second must not block the first. Until the first
	// fetch succeeds every call that carries a capability is rejected (an
	// empty key set verifies nothing), and each failed attempt is logged
	// with the reason, so "the proxy never came up" stays visible rather
	// than silent.
	go func() {
		backoff := 500 * time.Millisecond
		for {
			if err := refreshKeys(); err == nil {
				log.Printf("mockupstream: loaded %d biscuit key(s) from %s", len(currentKeys()), proxyURL)
				break
			} else {
				log.Printf("mockupstream: proxy not ready yet (%v), retrying in %v - set JIT_PROXY_URL if it's not on 127.0.0.1:8080", err, backoff)
			}
			time.Sleep(backoff)
			if backoff < 5*time.Second {
				backoff *= 2
			}
		}
		for {
			time.Sleep(30 * time.Second)
			if err := refreshKeys(); err != nil {
				log.Printf("mockupstream: biscuit key refresh failed, keeping previous key set: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		u, ok := users[r.PathValue("id")]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"detail": "no such user"})
			return
		}
		writeJSON(w, http.StatusOK, u)
	})

	mux.HandleFunc("PATCH /users/{id}/tier", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := verifyToken(r.Header.Get("Authorization"), "update_customer_tier", id); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": err.Error()})
			return
		}
		var body struct {
			Tier string `json:"tier"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		defer mu.Unlock()
		u, ok := users[id]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"detail": "no such user"})
			return
		}
		previousTier := u.Tier
		u.Tier = body.Tier
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "user": u, "previous_tier": previousTier})
	})

	mux.HandleFunc("PATCH /users/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := verifyToken(r.Header.Get("Authorization"), "update_customer_status", id); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": err.Error()})
			return
		}
		var body struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		defer mu.Unlock()
		u, ok := users[id]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"detail": "no such user"})
			return
		}
		previousStatus := u.Status
		u.Status = body.Status
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "user": u, "previous_status": previousStatus})
	})

	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		log.Printf("[mockupstream] event logged: %v", body)
		writeJSON(w, http.StatusOK, map[string]any{"status": "logged"})
	})

	// The "computer use" tool - no natural resource (a screenshot action
	// isn't scoped to one record the way a user update is), so the
	// capability token's resource claim is the empty string on both the
	// minting and verifying side. Still real biscuit verification, same as
	// every other mutating tool - proving capability minting/attenuation
	// happens correctly for this tool shape too, not a bypassed side path.
	mux.HandleFunc("POST /computer-action", func(w http.ResponseWriter, r *http.Request) {
		if err := verifyToken(r.Header.Get("Authorization"), "computer", ""); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": err.Error()})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		log.Printf("[mockupstream] computer action performed: %v", body)
		writeJSON(w, http.StatusOK, map[string]any{"status": "performed", "action": body["action"]})
	})

	mux.HandleFunc("POST /refund-emails", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			UserID      string `json:"user_id"`
			AmountCents any    `json:"amount_cents"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := verifyToken(r.Header.Get("Authorization"), "send_refund_email", body.UserID); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": err.Error()})
			return
		}
		log.Printf("[mockupstream] refund email SENT to user %s for %v cents (irreversible)", body.UserID, body.AmountCents)
		writeJSON(w, http.StatusOK, map[string]any{"status": "sent", "user_id": body.UserID, "amount_cents": body.AmountCents})
	})

	mux.HandleFunc("POST /users/{id}/close", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := verifyToken(r.Header.Get("Authorization"), "close_account", id); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": err.Error()})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		u, ok := users[id]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"detail": "no such user"})
			return
		}
		u.Status = "closed"
		log.Printf("[mockupstream] account CLOSED for user %s (irreversible)", id)
		writeJSON(w, http.StatusOK, map[string]any{"status": "closed", "user": u})
	})

	// The MCP face of this same upstream - see mcpserver.go. Registered on
	// the same mux and over the same user state, so a tier change made
	// through MCP passthrough and one made through the HTTP route are
	// visibly the same mutation to the same record.
	mux.HandleFunc("POST /mcp", handleMCP)

	if simulatedLatency > 0 {
		log.Printf("mockupstream simulating %v of latency on every request (MOCK_UPSTREAM_LATENCY_MS)", simulatedLatency)
	}
	log.Println("mockupstream listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", withSimulatedLatency(mux)))
}
