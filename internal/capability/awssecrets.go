// Real Vault dynamic AWS credentials, alongside dbsecrets.go. AWS access
// is attenuated per call via a real
// sts:AssumeRole (a cheap, fast, AWS-enforced-TTL operation - unlike a
// database CREATE ROLE, there's no expensive backend round trip to avoid
// repeating), so unlike the DB credential (minted once per session),
// nothing here needs session-level caching to be honest about cost.
//
// One real, important difference from the DB side, found while validating
// this against a live AWS account, not assumed: an AWS STS temporary
// credential CANNOT be actively invalidated once issued. Vault's lease
// revocation for these leases only removes Vault's own bookkeeping - the
// credential itself keeps working with AWS until its TTL naturally
// expires, confirmed live (revoked the lease, the same credential still
// successfully read S3 afterward). This is an AWS platform limitation,
// not a gap in this implementation - the real security boundary for AWS
// dynamic secrets is the TTL itself, which is why keeping it short matters
// more here than it does for the DB path (where a real DROP ROLE gives an
// actual hard stop).
package capability

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// AWSCredential is a real, temporary AWS credential minted by Vault via a
// genuine sts:AssumeRole call - not a token this proxy verifies itself,
// since AWS's own STS/IAM is the verifier here, the same way the database
// itself is the verifier for DBCredential.
type AWSCredential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	LeaseID         string
	LeaseDuration   int // seconds, as Vault reports it
}

// AWSCredentialMinter sources real, per-call AWS credentials. Interface so
// tests never need a live Vault+AWS pair - only cmd/rinwall's real wiring
// uses VaultAWSCredentialMinter.
type AWSCredentialMinter interface {
	MintAWSCredential(ctx context.Context, awsRole string) (AWSCredential, error)
	// RevokeAWSCredential ends the lease in Vault's own bookkeeping. It
	// does NOT invalidate the credential with AWS - see the package
	// comment above. Still worth calling when a caller is done with a
	// credential early, so Vault's lease count/audit trail reflects
	// reality, but callers must not treat this as a security control the
	// way DBCredentialMinter's revoke is.
	RevokeAWSCredential(ctx context.Context, leaseID string) error
}

// VaultAWSCredentialMinter calls Vault's AWS secrets engine
// (aws/sts/<role>) - a real network round trip that executes a real
// sts:AssumeRole against AWS, using Vault's own configured root credential
// (itself scoped to nothing more than sts:AssumeRole on the specific
// role(s) a Vault AWS role names - docs/REFERENCE.md's dynamic-secrets section
// shows how that credential is itself provisioned narrowly).
type VaultAWSCredentialMinter struct {
	client *vaultapi.Client
}

func NewVaultAWSCredentialMinter(client *vaultapi.Client) *VaultAWSCredentialMinter {
	return &VaultAWSCredentialMinter{client: client}
}

func (m *VaultAWSCredentialMinter) MintAWSCredential(ctx context.Context, awsRole string) (AWSCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, vaultCallTimeout)
	defer cancel()

	secret, err := m.client.Logical().ReadWithContext(ctx, "aws/sts/"+awsRole)
	if err != nil {
		return AWSCredential{}, fmt.Errorf("%w: aws sts creds: %v", ErrVaultUnavailable, err)
	}
	if secret == nil || secret.Data == nil {
		return AWSCredential{}, fmt.Errorf("capability: vault aws sts creds: empty response for role %q", awsRole)
	}
	accessKey, ok := secret.Data["access_key"].(string)
	if !ok {
		return AWSCredential{}, fmt.Errorf("capability: vault aws sts creds: missing access_key field")
	}
	secretKey, ok := secret.Data["secret_key"].(string)
	if !ok {
		return AWSCredential{}, fmt.Errorf("capability: vault aws sts creds: missing secret_key field")
	}
	sessionToken, ok := secret.Data["security_token"].(string)
	if !ok {
		return AWSCredential{}, fmt.Errorf("capability: vault aws sts creds: missing security_token field")
	}

	return AWSCredential{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
		LeaseID:         secret.LeaseID,
		LeaseDuration:   secret.LeaseDuration,
	}, nil
}

func (m *VaultAWSCredentialMinter) RevokeAWSCredential(ctx context.Context, leaseID string) error {
	ctx, cancel := context.WithTimeout(ctx, vaultCallTimeout)
	defer cancel()
	if err := m.client.Sys().RevokeWithContext(ctx, leaseID); err != nil {
		return fmt.Errorf("%w: revoke aws lease: %v", ErrVaultUnavailable, err)
	}
	return nil
}

// FakeAWSCredentialMinter is an in-memory stand-in for tests - no Vault or
// AWS dependency, mirrors FakeDBCredentialMinter's role.
type FakeAWSCredentialMinter struct {
	NextAccessKeyID     string
	NextSecretAccessKey string
	NextSessionToken    string
	MintErr             error
	RevokeErr           error
	Revoked             []string
}

func (f *FakeAWSCredentialMinter) MintAWSCredential(ctx context.Context, awsRole string) (AWSCredential, error) {
	if f.MintErr != nil {
		return AWSCredential{}, f.MintErr
	}
	return AWSCredential{
		AccessKeyID:     f.NextAccessKeyID,
		SecretAccessKey: f.NextSecretAccessKey,
		SessionToken:    f.NextSessionToken,
		LeaseID:         "fake-lease-" + awsRole,
		LeaseDuration:   900,
	}, nil
}

func (f *FakeAWSCredentialMinter) RevokeAWSCredential(ctx context.Context, leaseID string) error {
	if f.RevokeErr != nil {
		return f.RevokeErr
	}
	f.Revoked = append(f.Revoked, leaseID)
	return nil
}
