// Key rotation for the biscuit signing keypair. Before this, biscuit.go
// held one seed forever, sourced from a plaintext config.yaml field - fine
// for a PoC, not something to ship. This file adds the two things that
// were actually missing: a way to change the signing key without breaking
// tokens already in flight, and a way for verifiers to learn about a new
// key without a synchronized manual update.
//
// Deliberately NOT built here: Vault Transit-based signing (having Vault
// hold the private key and sign on our behalf, so it never exists in the
// proxy's own memory at all). That's a real, further hardening step, but
// it needs validating biscuit-go's
// signer interface against a real Transit sign call first, and isn't worth
// the added per-session network hop until a customer's security review
// specifically asks for HSM-backed signing. What's here is the
// intermediate, still-real step: get the key out of a config file into
// Vault, and make rotation an explicit, non-automatic action.
package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// keyGracePeriod is how long a superseded key stays servable for
// verification after being replaced as current. It has to comfortably
// outlive any root capability signed under it - sessionRootTTL is 15m, so
// 2h is a wide safety margin, not a tight calculation, since the cost of
// keeping an old key around a bit longer is negligible.
const keyGracePeriod = 2 * time.Hour

// KeyEntry is one signing key's full material plus its rotation
// lifecycle. SeedHex is the private half - it exists in this struct only
// because the struct itself is meant to live in Vault, never in a config
// file or a discovery response.
type KeyEntry struct {
	ID           string     `json:"id"`
	SeedHex      string     `json:"seed_hex"`
	CreatedAt    time.Time  `json:"created_at"`
	SupersededAt *time.Time `json:"superseded_at,omitempty"`
}

func (e KeyEntry) privateKey() (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(e.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("capability: key %s: seed must be %d hex-decoded bytes", e.ID, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func generateKeyEntry() (KeyEntry, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyEntry{}, fmt.Errorf("capability: generate signing key: %w", err)
	}
	idBytes := make([]byte, 4)
	if _, err := rand.Read(idBytes); err != nil {
		return KeyEntry{}, fmt.Errorf("capability: generate key id: %w", err)
	}
	seed := priv.Seed()
	return KeyEntry{
		ID:        hex.EncodeToString(idBytes),
		SeedHex:   hex.EncodeToString(seed),
		CreatedAt: time.Now(),
	}, nil
}

// PublicKeyEntry is the public, servable half of a KeyEntry - what
// GET /biscuit-keys hands out. Never carries SeedHex.
type PublicKeyEntry struct {
	ID           string `json:"id"`
	PublicKeyHex string `json:"public_key_hex"`
	Current      bool   `json:"current"`
}

// KeyRing is the full rotation state, persisted as a single document
// rather than key-by-key - it's small, and rotation is a rare, deliberate
// action, not something that needs fine-grained concurrent writes.
type KeyRing struct {
	Keys      []KeyEntry `json:"keys"`
	CurrentID string     `json:"current_id"`
}

// NewKeyRing bootstraps a fresh keyring with one key, current. Called
// exactly once per deployment, the first time a proxy starts up and finds
// nothing in Vault yet.
func NewKeyRing() (*KeyRing, error) {
	entry, err := generateKeyEntry()
	if err != nil {
		return nil, err
	}
	return &KeyRing{Keys: []KeyEntry{entry}, CurrentID: entry.ID}, nil
}

// Current returns the entry (and derived private key) new roots should be
// signed with.
func (kr *KeyRing) Current() (KeyEntry, ed25519.PrivateKey, error) {
	for _, e := range kr.Keys {
		if e.ID == kr.CurrentID {
			priv, err := e.privateKey()
			return e, priv, err
		}
	}
	return KeyEntry{}, nil, fmt.Errorf("capability: keyring has no entry for current id %q", kr.CurrentID)
}

// Rotate generates a fresh signing key and makes it current. The
// previously-current key is marked superseded (starting its grace-period
// clock), not removed - tokens it already signed keep verifying at any
// verifier that still has it cached until Prune eventually drops it.
func (kr *KeyRing) Rotate() (newKeyID string, err error) {
	entry, err := generateKeyEntry()
	if err != nil {
		return "", err
	}
	now := time.Now()
	for i, e := range kr.Keys {
		if e.ID == kr.CurrentID && e.SupersededAt == nil {
			kr.Keys[i].SupersededAt = &now
		}
	}
	kr.Keys = append(kr.Keys, entry)
	kr.CurrentID = entry.ID
	return entry.ID, nil
}

// Prune drops any superseded key whose grace period has fully elapsed -
// no session signed under it can possibly still be alive. Safe to call on
// every load; a no-op most of the time.
func (kr *KeyRing) Prune(now time.Time) {
	kept := kr.Keys[:0]
	for _, e := range kr.Keys {
		if e.SupersededAt != nil && now.Sub(*e.SupersededAt) > keyGracePeriod {
			continue
		}
		kept = append(kept, e)
	}
	kr.Keys = kept
}

// ServablePublicKeys is what GET /biscuit-keys hands a verifier: every key
// still inside its grace period (or current), public half only.
func (kr *KeyRing) ServablePublicKeys() ([]PublicKeyEntry, error) {
	out := make([]PublicKeyEntry, 0, len(kr.Keys))
	for _, e := range kr.Keys {
		priv, err := e.privateKey()
		if err != nil {
			return nil, err
		}
		pub := priv.Public().(ed25519.PublicKey)
		out = append(out, PublicKeyEntry{
			ID:           e.ID,
			PublicKeyHex: hex.EncodeToString(pub),
			Current:      e.ID == kr.CurrentID,
		})
	}
	return out, nil
}

// KeyRingStore persists the whole keyring as one document. Vault's KV v2
// engine is the real store (below) - not Transit, since here Vault is
// just holding a document for us rather than performing a signing
// operation itself. Tests use an in-memory fake so go test never depends
// on a live Vault server, the same pattern as FakeSeedMinter standing in
// for Vault elsewhere in this package.
type KeyRingStore interface {
	// Load returns (nil, nil) if no keyring has been created yet - the
	// caller bootstraps one and Saves it, rather than Load doing that
	// implicitly, so "no keyring yet" and "storage error" stay distinguishable.
	Load(ctx context.Context) (*KeyRing, error)
	Save(ctx context.Context, kr *KeyRing) error
}

// VaultKeyRingStore stores the keyring under one path in Vault's KV v2
// secrets engine (the default `secret/` mount in a dev server already
// running for this project). This is the step up from "signing key in a
// config.yaml field": the private key material now lives only in Vault,
// fetched into proxy memory at startup/rotation, never written to disk
// alongside the rest of the deployment's config.
type VaultKeyRingStore struct {
	kv   *vaultapi.KVv2
	path string
}

func NewVaultKeyRingStore(client *vaultapi.Client, mountPath, secretPath string) *VaultKeyRingStore {
	return &VaultKeyRingStore{kv: client.KVv2(mountPath), path: secretPath}
}

func (s *VaultKeyRingStore) Load(ctx context.Context) (*KeyRing, error) {
	ctx, cancel := context.WithTimeout(ctx, vaultCallTimeout)
	defer cancel()
	secret, err := s.kv.Get(ctx, s.path)
	if err != nil {
		if errors.Is(err, vaultapi.ErrSecretNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: kv get keyring: %v", ErrVaultUnavailable, err)
	}
	raw, ok := secret.Data["keyring_json"].(string)
	if !ok {
		return nil, fmt.Errorf("capability: vault kv keyring at %s: missing keyring_json field", s.path)
	}
	var kr KeyRing
	if err := json.Unmarshal([]byte(raw), &kr); err != nil {
		return nil, fmt.Errorf("capability: decode keyring: %w", err)
	}
	return &kr, nil
}

func (s *VaultKeyRingStore) Save(ctx context.Context, kr *KeyRing) error {
	raw, err := json.Marshal(kr)
	if err != nil {
		return fmt.Errorf("capability: encode keyring: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, vaultCallTimeout)
	defer cancel()
	if _, err := s.kv.Put(ctx, s.path, map[string]any{"keyring_json": string(raw)}); err != nil {
		return fmt.Errorf("%w: kv put keyring: %v", ErrVaultUnavailable, err)
	}
	return nil
}

// FakeKeyRingStore is the name tests have always used for an in-memory
// keyring. It is an alias for EphemeralKeyRingStore (local.go), which
// zero-config mode uses for real - see that type for what holding the
// signing key only in memory actually costs.
type FakeKeyRingStore = EphemeralKeyRingStore
