// sessionCapabilityCache is the boundary where the Fast Capability Plane's
// latency split actually happens: MintRoot (real Vault call, paid once)
// only runs on a cache miss; every other call in the same session reuses
// the cached Root and pays only the cost of local attenuation.
package handler

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/metrics"
)

type sessionCapabilityCache struct {
	mu    sync.Mutex
	roots map[string]capability.Root
}

func newSessionCapabilityCache() *sessionCapabilityCache {
	return &sessionCapabilityCache{roots: make(map[string]capability.Root)}
}

// getOrMint returns the cached root for sessionKey if it exists and hasn't
// expired (recorded under the "capability_cache_hit" metric - a mutex lock,
// no network call); otherwise it mints a fresh one via a real Vault round
// trip (recorded under "capability_root_mint") and caches it.
func (c *sessionCapabilityCache) getOrMint(ctx context.Context, m *metrics.Recorder, issuer capability.RootIssuer, sessionKey, delegatedUser, delegatedRole string) (capability.Root, error) {
	hitDone := m.Timer("capability_cache_hit")
	c.mu.Lock()
	if root, ok := c.roots[sessionKey]; ok && !root.Expired() {
		c.mu.Unlock()
		hitDone()
		return root, nil
	}
	c.mu.Unlock()

	done := m.Timer("capability_root_mint")
	root, err := issuer.MintRoot(ctx, sessionKey, delegatedUser, delegatedRole)
	done()
	if err != nil {
		// Distinguishable from any other mint failure so an operator (or an
		// alert on GET /metrics) can tell "Vault specifically is down" apart
		// from, say, a malformed session key.
		if errors.Is(err, capability.ErrVaultUnavailable) {
			m.IncrementCounter("vault_unavailable")
		}
		return nil, fmt.Errorf("session capability cache: mint root: %w", err)
	}

	c.mu.Lock()
	c.roots[sessionKey] = root
	c.mu.Unlock()
	return root, nil
}
