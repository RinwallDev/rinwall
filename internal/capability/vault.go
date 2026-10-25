// Vault integration for the Fast Capability Plane's "paid once per session"
// half. This is deliberately scoped: it demonstrates the real latency
// architecture (one genuine network round trip to Vault per session, zero
// on the per-call hot path) using Vault's Transit engine to source a
// cryptographically random, audited session seed - it does NOT mint real
// AWS/DB credentials - dbsecrets.go and awssecrets.go do that, each with
// its own cost model (a DB credential once per session because CREATE
// ROLE is expensive; an AWS credential per call because sts:AssumeRole is
// cheap and AWS-TTL-enforced). The biscuit signing key
// itself (biscuit.go) is a separate, stable keypair - Vault is not asked to
// re-mint that per session, since a verifier can only trust one fixed
// public key.
package capability

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// vaultCallTimeout bounds every real network call this package makes to
// Vault. Without this, a hung Vault connection (a network partition
// specifically to Vault, a quorum-losing storage backend, anything short
// of Vault cleanly returning an error) would leave the calling request
// blocked indefinitely instead of failing fast with a clear signal. HA
// Vault is a deployment decision (PRODUCTION.md); failing fast is this
// codebase's job.
const vaultCallTimeout = 8 * time.Second

// ErrVaultUnavailable marks an error as caused by Vault being unreachable,
// timing out, or otherwise failing to answer - as opposed to, say, a
// malformed response it did answer with. Callers (internal/handler) use
// errors.Is against this to raise a distinguishable operational signal
// ("Vault specifically is down") rather than treating every capability
// mint failure identically.
var ErrVaultUnavailable = errors.New("capability: vault unavailable")

// SeedMinter sources the per-session random seed embedded in the root
// biscuit's authority facts. Interface so tests never need a live Vault
// server - only cmd/rinwall's real wiring uses VaultSeedMinter.
type SeedMinter interface {
	MintSessionSeed(ctx context.Context, sessionKey string) (seedHex string, err error)
}

// NewVaultClient builds the one Vault client a proxy process shares
// between the seed minter (Transit) and the key-ring store (KV v2) - one
// connection object, not two independently configured ones for what is
// ultimately the same Vault deployment.
func NewVaultClient(addr, token string) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("capability: vault client: %w", err)
	}
	client.SetToken(token)
	return client, nil
}

// VaultSeedMinter calls Vault's Transit engine once per session
// (transit/datakey/plaintext/<key>) - a real network round trip that
// costs real latency (hundreds of milliseconds), paid once per session,
// and leaves a real entry in Vault's own audit log.
type VaultSeedMinter struct {
	client     *vaultapi.Client
	transitKey string
}

func NewVaultSeedMinter(client *vaultapi.Client, transitKey string) *VaultSeedMinter {
	return &VaultSeedMinter{client: client, transitKey: transitKey}
}

func (m *VaultSeedMinter) MintSessionSeed(ctx context.Context, sessionKey string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, vaultCallTimeout)
	defer cancel()
	secret, err := m.client.Logical().WriteWithContext(ctx,
		"transit/datakey/plaintext/"+m.transitKey,
		map[string]any{"context": base64.StdEncoding.EncodeToString([]byte(sessionKey))},
	)
	if err != nil {
		return "", fmt.Errorf("%w: transit datakey: %v", ErrVaultUnavailable, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("capability: vault transit datakey: empty response")
	}
	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return "", fmt.Errorf("capability: vault transit datakey: missing plaintext field")
	}
	raw, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return "", fmt.Errorf("capability: vault transit datakey: decode plaintext: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// FakeSeedMinter is the name tests have always used for local seed
// generation. It is an alias, not a copy: the implementation is
// LocalSeedMinter in local.go, which zero-config mode uses for real - and
// there is nothing fake about it, since a session seed is randomness
// rather than a secret Vault was guarding.
type FakeSeedMinter = LocalSeedMinter
