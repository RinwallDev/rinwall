package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

// MCP-to-MCP passthrough: the proxy is an MCP server to the agent and an
// MCP client to the real server, so it can be dropped in front of an MCP
// server someone already runs without that server changing at all. This is
// the fourth upstream kind alongside HTTP, DB, and AWS.
//
// Three things about this path differ from the HTTP one, and all three are
// worth stating plainly rather than leaving implied:
//
// 1. The upstream's own credential lives here, in the client the proxy
// holds - never in the agent's context. That's the actual security gain of
// sitting in the middle rather than handing the agent a token: an injected
// instruction can make the agent ASK for a bad call, which policy then
// judges, but it can never exfiltrate the credential itself, because the
// agent never had it.
//
// 2. The capability token is still minted and forwarded (in the spec's own
// `params._meta`), but a stock upstream MCP server will ignore it. There is
// no pretending otherwise: for an unmodified upstream, the enforcement that
// actually binds is entirely proxy-side - policy, taint, class gating,
// approvals, saga compensation. The token is there so an upstream that
// wants a second, independent check can have one (cmd/mockupstream shows
// what that verification looks like), not because it is doing work today.
//
// 3. Unlike DB- and AWS-backed tools, this is not restricted to Class B.
// An upstream catalog is the general case and contains real Class A and
// Class C tools; refusing to load those would push exactly the calls that
// most need gating back outside the firewall.

// executeMCPCall forwards a validated call onward to the upstream MCP
// server. It mirrors the HTTP branch of execute() step for step -
// pre-image, capability, upstream call, sanitize, audit, saga record - so
// an MCP-backed tool composes with every other part of the system rather
// than being a side path that quietly skips half of them.
func (h *Handler) executeMCPCall(ctx context.Context, tool registry.Tool, args map[string]any, resource string, req proxytypes.CallRequest, path string) (proxytypes.CallResult, error) {
	if h.MCPUpstream == nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: tool %q is mcp-backed but no upstream MCP server is configured (set mcp_upstream_url)", tool.Name)
	}
	isCompensation := req.Transport == compensationTransport

	// Fails closed on a missing snapshot, same as the HTTP path in execute():
	// a class A mutation with nothing to restore from is not executed.
	var preImage json.RawMessage
	if tool.ReversibilityClass == registry.ClassA && !isCompensation {
		preImage = h.captureMCPPreImage(ctx, tool, resource)
		if preImage == nil {
			h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
				"reason":   "pre-image capture failed - refusing to execute a compensable mutation without a snapshot to restore from",
				"resource": resource, "path": path, "transport": req.Transport, "agent_id": req.AgentID})
			return proxytypes.CallResult{Status: "error", Reason: "pre-image capture failed - a compensable (class A) mutation is not executed without a snapshot to restore from"}, nil
		}
	}

	root, err := h.caps.getOrMint(ctx, h.Metrics, h.Capability, sessionKeyFor(req), req.DelegatedUser, req.DelegatedRole)
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: get/mint root capability: %w", err)
	}
	attenuateDone := h.Metrics.Timer("capability_attenuate")
	token, err := root.Attenuate(tool.Name, resource, tokenTTL)
	attenuateDone()
	if err != nil {
		return proxytypes.CallResult{}, fmt.Errorf("handler: attenuate capability: %w", err)
	}

	upstreamDone := h.Metrics.Timer("mcp_upstream_call")
	res, err := h.MCPUpstream.CallToolWithMeta(ctx, tool.UpstreamMCPTool(), args, map[string]any{
		"jit_capability": token.Value,
		"jit_resource":   resource,
	})
	upstreamDone()
	if err != nil {
		h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "upstream MCP call failed: " + err.Error(), "path": path})
		return proxytypes.CallResult{Status: "error", Reason: err.Error()}, nil
	}

	// An MCP tool reports its own failures via isError on an otherwise
	// perfectly valid response, so this is a real upstream failure, not a
	// transport one. It matters here beyond reporting: recording a failed
	// call as an executed saga step would later have compensation try to
	// undo something that never happened.
	if res.IsError {
		h.Audit.Write(map[string]any{"decision": "ERROR", "tool": tool.Name, "delegated_role": req.DelegatedRole,
			"reason": "upstream MCP tool reported an error: " + res.Text(), "path": path, "resource": resource})
		return proxytypes.CallResult{Status: "error", Reason: res.Text()}, nil
	}

	body := decodeMCPContent(res)
	if len(tool.SanitizeFields) > 0 {
		body = stripFields(body, tool.SanitizeFields)
	}

	h.Audit.Write(map[string]any{"decision": "EXECUTED", "tool": tool.Name, "delegated_role": req.DelegatedRole,
		"reason": path, "resource": resource, "upstream": "mcp:" + tool.UpstreamMCPTool(),
		"transport": req.Transport, "agent_id": req.AgentID})

	if req.RunID != "" && !isCompensation {
		h.Sagas.RecordStep(&saga.Step{
			RunID: req.RunID, Tool: tool.Name, ReversibilityClass: string(tool.ReversibilityClass),
			Resource: resource, Args: args, PreImage: preImage,
			DelegatedUser: req.DelegatedUser, DelegatedRole: req.DelegatedRole, AgentID: req.AgentID,
			ExecutedAt: time.Now(),
		})
	}

	return proxytypes.CallResult{Status: "executed", UpstreamCode: 200, UpstreamBody: body}, nil
}

// captureMCPPreImage is the MCP analog of capturePreImage: it reads the
// resource's prior state by calling another tool on the same upstream
// server (pre_image.mcp_tool), passing the resource under the mutating
// tool's own ResourceArg name.
func (h *Handler) captureMCPPreImage(ctx context.Context, tool registry.Tool, resource string) json.RawMessage {
	if tool.PreImage == nil || tool.PreImage.MCPTool == "" || h.MCPUpstream == nil {
		return nil
	}
	args := map[string]any{}
	if tool.ResourceArg != "" {
		args[tool.ResourceArg] = resource
	}
	res, err := h.MCPUpstream.CallTool(ctx, tool.PreImage.MCPTool, args)
	if err != nil || res.IsError {
		// nil here makes executeMCPCall refuse the mutation - see its
		// caller. The warning is for the operator; the refusal is for the
		// agent.
		reason := "upstream reported an error"
		if err != nil {
			reason = err.Error()
		}
		fmt.Fprintf(os.Stderr, "[saga] warning: could not capture MCP pre-image for %s/%s: %s\n", tool.Name, resource, reason)
		return nil
	}
	raw, err := json.Marshal(decodeMCPContent(res))
	if err != nil {
		return nil
	}

	h.sagaMu.Lock()
	h.preImages[tool.Name+"|"+resource] = json.RawMessage(raw)
	h.sagaMu.Unlock()

	h.Audit.Write(map[string]any{"decision": "SNAPSHOT", "tool": tool.Name, "resource": resource,
		"reason": "pre-image captured via MCP for possible compensation", "pre_image": json.RawMessage(raw)})
	return json.RawMessage(raw)
}

// decodeMCPContent turns an MCP result's content blocks into the same
// shape the HTTP path produces, so response sanitization, compensation's
// pre-image field lookups, and everything downstream see one representation
// regardless of which upstream kind answered.
//
// Nearly every MCP tool returns its payload as JSON inside a text block, so
// that is decoded to a real object where it parses. Where it doesn't - a
// tool that genuinely returns prose - the text is returned as-is rather
// than forced into a structure it doesn't have.
func decodeMCPContent(res interface {
	Text() string
}) any {
	text := res.Text()
	if text == "" {
		return map[string]any{}
	}
	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err == nil {
		return parsed
	}
	return text
}
