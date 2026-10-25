// sessionDBCache is the DB-credential analog of sessionCapabilityCache:
// the real Vault database secrets engine cost (a genuine CREATE ROLE
// round trip against the actual database) only gets paid once per
// session, per DB role - every other call in the same session reuses the
// already-open connection. Unlike the biscuit root (one keypair-derived
// object reused for any number of local attenuations), a real per-session
// dynamic DB credential means a real, separate connection pool per
// session - that's the actual, honest cost of genuine per-session dynamic
// secrets, not an oversight to optimize away.
package handler

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/metrics"
)

// dbLeaseSafetyMargin retires a cached connection a little before its
// real Vault lease expires, so a call never gets handed a connection
// that's about to be rejected mid-query - the same clamping spirit as
// biscuit attenuation never outliving its root's real expiry.
const dbLeaseSafetyMargin = 5 * time.Second

type sessionDBEntry struct {
	db        *sql.DB
	expiresAt time.Time
}

type sessionDBCache struct {
	mu      sync.Mutex
	entries map[string]*sessionDBEntry // key: sessionKey + "|" + dbRole - a session may use more than one db_role
}

func newSessionDBCache() *sessionDBCache {
	return &sessionDBCache{entries: make(map[string]*sessionDBEntry)}
}

func (c *sessionDBCache) getOrMint(ctx context.Context, m *metrics.Recorder, minter capability.DBCredentialMinter, dsnTemplate, sessionKey, dbRole string) (*sql.DB, error) {
	key := sessionKey + "|" + dbRole

	hitDone := m.Timer("db_cache_hit")
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.Unlock()
		hitDone()
		return entry.db, nil
	}
	c.mu.Unlock()

	done := m.Timer("db_credential_mint")
	cred, err := minter.MintDBCredential(ctx, dbRole)
	done()
	if err != nil {
		return nil, fmt.Errorf("session db cache: mint credential: %w", err)
	}

	dsn := fmt.Sprintf(dsnTemplate, cred.Username, cred.Password)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("session db cache: open connection: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("session db cache: ping with newly-minted credential: %w", err)
	}

	leaseDuration := time.Duration(cred.LeaseDuration) * time.Second
	expiresAt := time.Now().Add(leaseDuration - dbLeaseSafetyMargin)

	c.mu.Lock()
	if old, ok := c.entries[key]; ok {
		old.db.Close()
	}
	c.entries[key] = &sessionDBEntry{db: db, expiresAt: expiresAt}
	c.mu.Unlock()

	return db, nil
}
