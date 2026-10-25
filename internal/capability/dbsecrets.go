// Real Vault dynamic database credentials, validated against a real
// PostgreSQL instance.
//
// Unlike the biscuit session seed (a cheap Transit call, safe to
// reissue), a real DB credential costs Vault a genuine `CREATE ROLE`
// round trip against the database - not something to pay per tool call.
// So this mints ONE credential per session (same lifecycle as the biscuit
// root capability), reused for that session's DB-backed calls, with
// per-call restriction enforced by this proxy's own policy/reversibility
// layer - not by asking Vault for a new DB principal on every call.
package capability

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// DBCredential is a real, uniquely-generated Postgres role + password,
// minted by Vault's database secrets engine executing a real
// CREATE ROLE ... statement against the actual database - not a token
// this proxy verifies itself (unlike biscuit tokens), since the database
// itself is the verifier here, the same way a real AWS/DB principal
// always has to be.
type DBCredential struct {
	Username      string
	Password      string
	LeaseID       string
	LeaseDuration int // seconds, as Vault reports it
}

// DBCredentialMinter sources real, per-session Postgres credentials.
// Interface so tests never need a live Vault+Postgres pair - only
// cmd/rinwall's real wiring uses VaultDBCredentialMinter.
type DBCredentialMinter interface {
	MintDBCredential(ctx context.Context, dbRole string) (DBCredential, error)
	RevokeDBCredential(ctx context.Context, leaseID string) error
}

// VaultDBCredentialMinter calls Vault's database secrets engine
// (database/creds/<role>) - a real network round trip that executes a
// real CREATE ROLE statement against the configured database backend,
// exactly once per session (see sessioncache-style caching in the
// handler layer for the per-call reuse pattern this is meant to support).
type VaultDBCredentialMinter struct {
	client *vaultapi.Client
}

func NewVaultDBCredentialMinter(client *vaultapi.Client) *VaultDBCredentialMinter {
	return &VaultDBCredentialMinter{client: client}
}

func (m *VaultDBCredentialMinter) MintDBCredential(ctx context.Context, dbRole string) (DBCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, vaultCallTimeout)
	defer cancel()

	secret, err := m.client.Logical().ReadWithContext(ctx, "database/creds/"+dbRole)
	if err != nil {
		return DBCredential{}, fmt.Errorf("%w: database creds: %v", ErrVaultUnavailable, err)
	}
	if secret == nil || secret.Data == nil {
		return DBCredential{}, fmt.Errorf("capability: vault database creds: empty response for role %q", dbRole)
	}
	username, ok := secret.Data["username"].(string)
	if !ok {
		return DBCredential{}, fmt.Errorf("capability: vault database creds: missing username field")
	}
	password, ok := secret.Data["password"].(string)
	if !ok {
		return DBCredential{}, fmt.Errorf("capability: vault database creds: missing password field")
	}

	return DBCredential{
		Username:      username,
		Password:      password,
		LeaseID:       secret.LeaseID,
		LeaseDuration: secret.LeaseDuration,
	}, nil
}

// RevokeDBCredential ends a credential's lease early - Vault responds by
// running the database plugin's real revocation statements (a DROP ROLE,
// for the postgresql-database-plugin), not just forgetting about it on
// Vault's side. Used when a session ends deliberately, rather than only
// ever waiting out the lease TTL.
func (m *VaultDBCredentialMinter) RevokeDBCredential(ctx context.Context, leaseID string) error {
	ctx, cancel := context.WithTimeout(ctx, vaultCallTimeout)
	defer cancel()
	if err := m.client.Sys().RevokeWithContext(ctx, leaseID); err != nil {
		return fmt.Errorf("%w: revoke database lease: %v", ErrVaultUnavailable, err)
	}
	return nil
}

// FakeDBCredentialMinter is an in-memory stand-in for tests - no Vault or
// database dependency, mirrors FakeSeedMinter's role for the Transit path.
type FakeDBCredentialMinter struct {
	NextUsername string
	NextPassword string
	MintErr      error
	RevokeErr    error
	Revoked      []string // leaseIDs passed to RevokeDBCredential, for assertions
}

func (f *FakeDBCredentialMinter) MintDBCredential(ctx context.Context, dbRole string) (DBCredential, error) {
	if f.MintErr != nil {
		return DBCredential{}, f.MintErr
	}
	return DBCredential{
		Username:      f.NextUsername,
		Password:      f.NextPassword,
		LeaseID:       "fake-lease-" + dbRole,
		LeaseDuration: 60,
	}, nil
}

func (f *FakeDBCredentialMinter) RevokeDBCredential(ctx context.Context, leaseID string) error {
	if f.RevokeErr != nil {
		return f.RevokeErr
	}
	f.Revoked = append(f.Revoked, leaseID)
	return nil
}
