// AWS-backed tool execution - the real Vault dynamic-secrets path
// (aws/sts/<role>, a genuine sts:AssumeRole against the actual AWS
// account) alongside the existing biscuit/HTTP and DB paths. Unlike the
// DB path, a fresh credential is minted on EVERY call rather than cached
// per session: a real AssumeRole is cheap and AWS-TTL-enforced, so there's
// no cost reason to reuse one, and a real reason not to - AWS STS
// credentials can't be actively revoked once issued (see
// internal/capability/awssecrets.go), so minting fresh per call and
// keeping the TTL short is the only real way to bound one call's exposure
// window rather than a whole session's.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

func (h *Handler) executeAWSS3Get(ctx context.Context, tool registry.Tool, args map[string]any, resource string, req proxytypes.CallRequest, path string) (proxytypes.CallResult, error) {
	if h.AWSSecrets == nil {
		return proxytypes.CallResult{Status: "error",
			Reason: "tool " + tool.Name + " is aws-backed but no AWSSecrets minter is configured on this proxy"}, nil
	}

	mintDone := h.Metrics.Timer("aws_credential_mint")
	cred, err := h.AWSSecrets.MintAWSCredential(ctx, tool.AWSRole)
	mintDone()
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: mint aws credential: %w", err)
	}

	key, _ := args[tool.S3KeyArg].(string)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(h.AWSRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)),
	)
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: build aws config: %w", err)
	}
	s3Client := s3.NewFromConfig(awsCfg)

	queryDone := h.Metrics.Timer("aws_s3_get")
	out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tool.S3Bucket),
		Key:    aws.String(key),
	})
	queryDone()
	if err != nil {
		h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "aws s3 get failed: " + err.Error(), "path": path, "aws_role": tool.AWSRole})
		return proxytypes.CallResult{Status: "error", Reason: err.Error()}, nil
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "aws s3 body read failed: " + err.Error(), "path": path, "aws_role": tool.AWSRole})
		return proxytypes.CallResult{Status: "error", Reason: err.Error()}, nil
	}

	// The demo objects are JSON, but this path shouldn't assume every
	// object a future aws-backed tool reads is - fall back to the raw
	// text rather than failing the call over an unmarshal error.
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		parsed = string(body)
	}
	if len(tool.SanitizeFields) > 0 {
		parsed = stripFields(parsed, tool.SanitizeFields)
	}

	h.Audit.Write(map[string]any{"decision": "EXECUTED", "tool": tool.Name, "delegated_role": req.DelegatedRole,
		"reason": path, "resource": resource, "transport": req.Transport, "agent_id": req.AgentID, "aws_role": tool.AWSRole})

	if req.RunID != "" {
		h.Sagas.RecordStep(&saga.Step{
			RunID: req.RunID, Tool: tool.Name, ReversibilityClass: string(tool.ReversibilityClass),
			Resource: resource, Args: args, DelegatedUser: req.DelegatedUser, DelegatedRole: req.DelegatedRole,
			AgentID: req.AgentID, ExecutedAt: time.Now(),
		})
	}

	return proxytypes.CallResult{Status: "executed", UpstreamBody: parsed}, nil
}
