package capability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// Vault-free backends for zero-config mode (see cmd/rinwall's --mcp flag).
// The point of these is that getting started shouldn't require running a
// secrets manager first - but what's given up has to be named exactly, not
// glossed as "dev mode."
//
// What is NOT given up: the seed. LocalSeedMinter reads crypto/rand, which
// is the same OS entropy Vault's own Transit engine ultimately draws on.
// A session seed is randomness, not a secret Vault is guarding, so
// sourcing it locally costs nothing in strength. What Vault actually buys
// for the seed is centralized auditing of who minted what and when - real,
// but an operational property, not a cryptographic one.
//
// What IS given up: durable custody of the signing key. See
// EphemeralKeyRingStore.

// LocalSeedMinter generates a session seed from crypto/rand with no Vault
// call at all. Tests use it so `go test` never depends on a live Vault
// server; zero-config mode uses it for real.
type LocalSeedMinter struct{}

func (LocalSeedMinter) MintSessionSeed(ctx context.Context, sessionKey string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// EphemeralKeyRingStore holds the biscuit signing keyring in memory only -
// nothing is ever written to disk, and a restart means a brand-new signing
// key.
//
// That restart behavior is the deliberate choice, not a limitation worked
// around: the alternative (a keyring file next to the config) would put
// private key material back in plaintext on disk, which is precisely what
// moving the keyring into Vault KV existed to stop. Losing it on restart
// costs almost nothing here, because verifiers already fetch the current
// key set from the proxy's own GET /biscuit-keys and refresh periodically
// rather than hardcoding one, and an attenuated token's TTL is seconds -
// so there is no meaningful population of in-flight tokens to invalidate.
//
// The real cost is custody: an operator cannot rotate deliberately and
// keep a grace window across a restart, and there is no record outside
// this process of which key signed what. That's the trade zero-config
// makes, and it's why production wants Vault KV.
type EphemeralKeyRingStore struct {
	mu sync.Mutex
	kr *KeyRing
}

func (s *EphemeralKeyRingStore) Load(ctx context.Context) (*KeyRing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kr, nil
}

func (s *EphemeralKeyRingStore) Save(ctx context.Context, kr *KeyRing) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kr = kr
	return nil
}
