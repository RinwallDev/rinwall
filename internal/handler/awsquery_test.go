package handler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

const awsTestToolsYAMLTemplate = `
tools:
  - name: get_order_document
    reversibility_class: B
    aws_role: s3-orders-reader
    aws_s3_bucket: %s
    aws_s3_key_arg: key
    args_schema:
      key:
        type: string
        required: true
`

// TestHandle_AWSBackedTool_RealS3Integration drives a full request through
// the real pipeline (Handle -> handleInner -> execute -> executeAWSS3Get)
// against the real Vault + AWS account set up for the AWS/DB dynamic
// secrets work. Skipped unless JIT_INTEGRATION_AWS=1 and
// JIT_TEST_S3_BUCKET is set - see the plan's AWS/DB dynamic secrets
// section for the exact setup this expects.
func TestHandle_AWSBackedTool_RealS3Integration(t *testing.T) {
	if os.Getenv("JIT_INTEGRATION_AWS") != "1" {
		t.Skip("set JIT_INTEGRATION_AWS=1 to run against a real Vault + AWS (see the plan's AWS/DB dynamic secrets section for setup)")
	}
	bucket := os.Getenv("JIT_TEST_S3_BUCKET")
	if bucket == "" {
		t.Skip("set JIT_TEST_S3_BUCKET to the demo bucket name to run this test")
	}

	dir := t.TempDir()
	toolsPath := filepath.Join(dir, "tools.yaml")
	toolsYAML := fmt.Sprintf(awsTestToolsYAMLTemplate, bucket)
	if err := os.WriteFile(toolsPath, []byte(toolsYAML), 0644); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.LoadFromYAML(toolsPath)
	if err != nil {
		t.Fatal(err)
	}

	pol, err := policy.New(context.Background(), testPolicyPath)
	if err != nil {
		t.Fatal(err)
	}

	aud, err := audit.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })

	capIssuer, err := capability.NewBiscuitRootIssuer(context.Background(), &capability.FakeKeyRingStore{}, capability.FakeSeedMinter{})
	if err != nil {
		t.Fatal(err)
	}

	vaultAddr := testEnvOrDefault("JIT_TEST_VAULT_ADDR", "http://127.0.0.1:8200")
	vaultToken := testEnvOrDefault("JIT_TEST_VAULT_TOKEN", "dev-root-token")
	region := testEnvOrDefault("JIT_TEST_AWS_REGION", "us-west-2")

	vaultClient, err := capability.NewVaultClient(vaultAddr, vaultToken)
	if err != nil {
		t.Fatal(err)
	}

	h := New(reg, pol, capIssuer, approval.NewStore(), aud, saga.NewStore(), "http://unused.invalid")
	h.AWSSecrets = capability.NewVaultAWSCredentialMinter(vaultClient)
	h.AWSRegion = region

	result, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "test", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "get_order_document", Args: map[string]any{"key": "orders/order-priya.json"},
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if result.Status != "executed" {
		t.Fatalf("expected status executed, got %q (reason: %s)", result.Status, result.Reason)
	}
	body, ok := result.UpstreamBody.(map[string]any)
	if !ok {
		t.Fatalf("expected UpstreamBody to be a parsed JSON object, got %T: %v", result.UpstreamBody, result.UpstreamBody)
	}
	if body["customer_email"] != "priya@example.com" {
		t.Fatalf("expected the real order document content, got: %v", body)
	}

	// The non-granted object must still be denied when reached through
	// the full proxy pipeline, not just the raw minter - proves the
	// policy/registry wiring doesn't accidentally widen access beyond
	// what the IAM role itself grants. The test tool's own args_schema
	// has no path restriction on "key" (unlike the real example tool),
	// deliberately, so this exercises AWS IAM's own denial, not our
	// schema validation rejecting the call before it ever reaches AWS.
	deniedResult, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "test", AgentID: "a1", DelegatedUser: "alex@example.com", DelegatedRole: "support",
		Tool: "get_order_document", Args: map[string]any{"key": "internal/internal-secret.json"},
	})
	if err != nil {
		t.Fatalf("Handle (denied case): %v", err)
	}
	if deniedResult.Status != "error" {
		t.Fatalf("expected the non-granted object to come back as an error (AWS AccessDenied), got status %q", deniedResult.Status)
	}
}
