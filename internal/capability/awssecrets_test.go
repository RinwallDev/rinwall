package capability

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestFakeAWSCredentialMinter_MintReturnsConfiguredCredential(t *testing.T) {
	f := &FakeAWSCredentialMinter{NextAccessKeyID: "AKIA-fake", NextSecretAccessKey: "secret", NextSessionToken: "token"}
	cred, err := f.MintAWSCredential(context.Background(), "s3-orders-reader")
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessKeyID != "AKIA-fake" || cred.SecretAccessKey != "secret" || cred.SessionToken != "token" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}

func TestFakeAWSCredentialMinter_MintErrorPropagates(t *testing.T) {
	wantErr := context.DeadlineExceeded
	f := &FakeAWSCredentialMinter{MintErr: wantErr}
	_, err := f.MintAWSCredential(context.Background(), "s3-orders-reader")
	if err != wantErr {
		t.Fatalf("expected the configured error to propagate, got %v", err)
	}
}

func TestFakeAWSCredentialMinter_RevokeRecordsLeaseID(t *testing.T) {
	f := &FakeAWSCredentialMinter{}
	if err := f.RevokeAWSCredential(context.Background(), "lease-123"); err != nil {
		t.Fatal(err)
	}
	if len(f.Revoked) != 1 || f.Revoked[0] != "lease-123" {
		t.Fatalf("expected lease-123 recorded as revoked, got %v", f.Revoked)
	}
}

// TestVaultAWSCredentialMinter_RealS3Integration is the real thing: mints
// an actual Vault-issued AWS STS credential (a genuine sts:AssumeRole
// against real AWS), uses it to call the real S3 API, confirms the
// granted object is readable and a non-granted one is genuinely denied by
// AWS IAM itself, and confirms - the one honest difference from the DB
// side - that Vault's revoke does NOT invalidate the credential with AWS
// (a real platform limitation, not a bug here). Skipped unless
// JIT_INTEGRATION_AWS=1, since it needs the real local Vault dev server
// (AWS secrets engine mounted, role "s3-orders-reader" configured against
// a real S3 bucket - see the plan's AWS/DB dynamic secrets section for
// the exact setup) rather than anything this test can provision itself.
func TestVaultAWSCredentialMinter_RealS3Integration(t *testing.T) {
	if os.Getenv("JIT_INTEGRATION_AWS") != "1" {
		t.Skip("set JIT_INTEGRATION_AWS=1 to run against a real Vault + AWS (see the plan's AWS/DB dynamic secrets section for setup)")
	}

	vaultAddr := envOrDefault("JIT_TEST_VAULT_ADDR", "http://127.0.0.1:8200")
	vaultToken := envOrDefault("JIT_TEST_VAULT_TOKEN", "dev-root-token")
	bucket := os.Getenv("JIT_TEST_S3_BUCKET")
	if bucket == "" {
		t.Skip("set JIT_TEST_S3_BUCKET to the demo bucket name to run this test")
	}
	region := envOrDefault("JIT_TEST_AWS_REGION", "us-west-2")

	client, err := NewVaultClient(vaultAddr, vaultToken)
	if err != nil {
		t.Fatal(err)
	}
	minter := NewVaultAWSCredentialMinter(client)

	ctx := context.Background()
	cred, err := minter.MintAWSCredential(ctx, "s3-orders-reader")
	if err != nil {
		t.Fatalf("mint: %v - is the aws secrets engine configured? see the plan's setup notes", err)
	}
	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" || cred.SessionToken == "" {
		t.Fatalf("expected a real access key/secret/session token, got %+v", cred)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)),
	)
	if err != nil {
		t.Fatal(err)
	}
	s3Client := s3.NewFromConfig(awsCfg)

	// The granted object must be readable.
	out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("orders/order-priya.json"),
	})
	if err != nil {
		t.Fatalf("expected the minted credential to read the granted object, got: %v", err)
	}
	body, _ := io.ReadAll(out.Body)
	out.Body.Close()
	if len(body) == 0 {
		t.Fatal("expected non-empty content for the granted object")
	}

	// A non-granted object must be genuinely denied by AWS IAM itself -
	// this is what proves least-privilege, not just "some credential works."
	_, err = s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("internal/internal-secret.json"),
	})
	if err == nil {
		t.Fatal("expected an access-denied error reading a non-granted object, got none")
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() != 403 {
		t.Fatalf("expected a 403 for the non-granted object, got HTTP %d: %v", respErr.HTTPStatusCode(), err)
	}

	// Revoke, then confirm - the real, honest finding - that the
	// credential STILL works, because AWS STS tokens can't be actively
	// invalidated once issued. This is not what you'd want from a
	// database credential, and the package doc explains why it's
	// nonetheless correct behavior here.
	if err := minter.RevokeAWSCredential(ctx, cred.LeaseID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("orders/order-priya.json"),
	})
	if err != nil {
		t.Fatalf("expected the credential to still work after Vault's revoke (AWS STS tokens aren't actively revocable), got: %v", err)
	}
}
