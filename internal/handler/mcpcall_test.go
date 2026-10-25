package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/mcpclient"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

// Catalog for MCP-to-MCP passthrough. Tool names match the real
// policies/tool_policy.rego rules, so these tests break if the shipped
// policy bundle and the handler ever drift apart - the same discipline
// newTestHandler already applies to the HTTP-backed tools.
const testMCPToolsYAML = `
tools:
  - name: mcp_get_user
    reversibility_class: B
    mcp_tool: "="
    resource_arg: user_id
    args_schema:
      user_id: {type: string, required: true}

  - name: mcp_update_customer_tier
    reversibility_class: A
    mcp_tool: "="
    resource_arg: user_id
    reviewer_role: admin-lead
    compensate_fields: ["tier"]
    pre_image:
      mcp_tool: mcp_get_user
    args_schema:
      user_id: {type: string, required: true}
      tier: {type: string, required: true, enum: ["bronze", "silver", "gold"]}

  - name: mcp_close_account
    reversibility_class: C
    mcp_tool: "="
    resource_arg: user_id
    reviewer_role: admin-lead
    args_schema:
      user_id: {type: string, required: true}
`

// fakeMCPUpstream is the MCP analog of fakeUpstream: real tier state, and
// real biscuit verification of the capability the proxy forwards in _meta,
// so these tests prove the token is genuinely bound to this tool and this
// resource rather than just present.
type fakeMCPUpstream struct {
	mu           sync.Mutex
	tiers        map[string]string
	closed       map[string]bool
	calls        []string
	failTool     string
	publicKeyHex string
}

func newFakeMCPUpstream(publicKeyHex string) *fakeMCPUpstream {
	return &fakeMCPUpstream{
		tiers: map[string]string{"42": "silver", "7": "bronze"}, closed: map[string]bool{},
		publicKeyHex: publicKeyHex,
	}
}

func (f *fakeMCPUpstream) callNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeMCPUpstream) tier(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tiers[id]
}

func (f *fakeMCPUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     any            `json:"id"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	respond := func(result any) {
		w.Header().Set("Content-Type", "application/json")
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		_, _ = w.Write(payload)
	}
	text := func(s string, isErr bool) map[string]any {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}, "isError": isErr}
	}
	jsonText := func(v any) map[string]any {
		raw, _ := json.Marshal(v)
		return text(string(raw), false)
	}

	switch req.Method {
	case "initialize":
		respond(map[string]any{"protocolVersion": "2025-06-18"})
	case "tools/list":
		respond(map[string]any{"tools": []map[string]any{}})
	case "tools/call":
		name, _ := req.Params["name"].(string)
		args, _ := req.Params["arguments"].(map[string]any)
		meta, _ := req.Params["_meta"].(map[string]any)
		capToken, _ := meta["jit_capability"].(string)
		id, _ := args["user_id"].(string)

		f.mu.Lock()
		f.calls = append(f.calls, name)
		shouldFail := f.failTool == name
		f.mu.Unlock()

		if shouldFail {
			respond(text("upstream refused", true))
			return
		}

		switch name {
		case "mcp_get_user":
			f.mu.Lock()
			defer f.mu.Unlock()
			respond(jsonText(map[string]any{"id": id, "tier": f.tiers[id], "closed": f.closed[id]}))
		case "mcp_update_customer_tier":
			if err := capability.Verify(capToken, []string{f.publicKeyHex}, name, id); err != nil {
				respond(text("capability verification failed: "+err.Error(), true))
				return
			}
			tier, _ := args["tier"].(string)
			f.mu.Lock()
			defer f.mu.Unlock()
			previous := f.tiers[id]
			f.tiers[id] = tier
			respond(jsonText(map[string]any{"status": "updated", "tier": tier, "previous_tier": previous}))
		case "mcp_close_account":
			if err := capability.Verify(capToken, []string{f.publicKeyHex}, name, id); err != nil {
				respond(text("capability verification failed: "+err.Error(), true))
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			f.closed[id] = true
			respond(jsonText(map[string]any{"status": "closed"}))
		default:
			respond(text("unknown tool: "+name, true))
		}
	}
}

func newMCPTestHandler(t *testing.T) (*Handler, *fakeMCPUpstream) {
	t.Helper()

	capIssuer, err := capability.NewBiscuitRootIssuer(context.Background(), &capability.FakeKeyRingStore{}, capability.FakeSeedMinter{})
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := capIssuer.CurrentPublicKeyHex()
	if err != nil {
		t.Fatal(err)
	}

	upstream := newFakeMCPUpstream(pubKeyHex)
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)

	dir := t.TempDir()
	toolsPath := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(toolsPath, []byte(testMCPToolsYAML), 0644); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.LoadFromYAML(toolsPath)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	pol, err := policy.New(context.Background(), testPolicyPath)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	aud, err := audit.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })

	// UpstreamBase is deliberately left pointing nowhere: nothing on the
	// MCP path may fall through to the HTTP forwarder, and a bogus base
	// makes that a test failure rather than a silent success.
	h := New(reg, pol, capIssuer, approval.NewStore(), aud, saga.NewStore(), "http://127.0.0.1:1")
	h.MCPUpstream = mcpclient.New(server.URL)
	return h, upstream
}

func TestMCP_ClassBReadForwardsAndDecodes(t *testing.T) {
	h, upstream := newMCPTestHandler(t)

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "dana", DelegatedRole: "support",
		Tool: "mcp_get_user", Args: map[string]any{"user_id": "42"},
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected executed, got %s: %s", res.Status, res.Reason)
	}
	body, ok := res.UpstreamBody.(map[string]any)
	if !ok {
		t.Fatalf("expected the MCP text content decoded to an object, got %T", res.UpstreamBody)
	}
	if body["tier"] != "silver" {
		t.Fatalf("unexpected body: %+v", body)
	}
	if got := upstream.callNames(); len(got) != 1 || got[0] != "mcp_get_user" {
		t.Fatalf("unexpected upstream calls: %v", got)
	}
}

// The capability really is bound to this tool and this resource, not just
// present: the fake upstream verifies it the same way cmd/mockupstream
// does, so a token that didn't match would fail this test.
func TestMCP_ForwardedCapabilityVerifiesAtUpstream(t *testing.T) {
	h, upstream := newMCPTestHandler(t)

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "jordan", DelegatedRole: "SalesManager",
		Tool: "mcp_update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Status != "executed" {
		t.Fatalf("expected executed, got %s: %s", res.Status, res.Reason)
	}
	if upstream.tier("42") != "gold" {
		t.Fatalf("upstream tier not updated: %s", upstream.tier("42"))
	}
}

// Class A over MCP: the pre-image is read through the upstream's own
// pre_image.mcp_tool, and a denial later in the same run walks the tier
// change back - the saga engine working over a forwarded MCP upstream, not
// only over HTTP.
func TestMCP_ClassACompensatesThroughUpstream(t *testing.T) {
	h, upstream := newMCPTestHandler(t)
	runID := "run-mcp-1"

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "jordan", DelegatedRole: "SalesManager",
		Tool: "mcp_update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"}, RunID: runID,
	})
	if err != nil || res.Status != "executed" {
		t.Fatalf("setup call failed: %v / %+v", err, res)
	}
	if upstream.tier("42") != "gold" {
		t.Fatalf("expected tier gold before compensation, got %s", upstream.tier("42"))
	}

	// A SalesManager is not authorized for mcp_close_account, so this is
	// denied - which is what triggers the run's compensation.
	denied, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "jordan", DelegatedRole: "SalesManager",
		Tool: "mcp_close_account", Args: map[string]any{"user_id": "42"}, RunID: runID,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if denied.Status != "denied" {
		t.Fatalf("expected denied, got %s", denied.Status)
	}

	if got := upstream.tier("42"); got != "silver" {
		t.Fatalf("compensation should have restored tier to silver via the MCP upstream, got %q", got)
	}
	// The pre-image read has to have actually happened through MCP, or the
	// restore above would have had nothing to restore from.
	var sawPreImageRead bool
	for _, name := range upstream.callNames() {
		if name == "mcp_get_user" {
			sawPreImageRead = true
		}
	}
	if !sawPreImageRead {
		t.Fatalf("expected a pre_image.mcp_tool read on the upstream, saw %v", upstream.callNames())
	}
}

// Class C over MCP is still gated: MCP-backed tools are not restricted to
// Class B the way DB- and AWS-backed ones are, precisely so irreversible
// upstream tools stay inside the firewall - and being inside it has to
// mean the Class C gate applies.
func TestMCP_ClassCStillRoutesToApproval(t *testing.T) {
	h, upstream := newMCPTestHandler(t)

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "dana", DelegatedRole: "support",
		Tool: "mcp_close_account", Args: map[string]any{"user_id": "42"},
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("expected pending_approval for a class C MCP tool, got %s: %s", res.Status, res.Reason)
	}
	if len(upstream.callNames()) != 0 {
		t.Fatalf("nothing should have reached the upstream before approval, saw %v", upstream.callNames())
	}
}

// A tool reporting its own failure is a valid MCP response, not a transport
// error - but it must not be recorded as an executed saga step, or a later
// compensation would try to undo something that never happened.
func TestMCP_UpstreamToolErrorIsNotRecordedAsExecuted(t *testing.T) {
	h, upstream := newMCPTestHandler(t)
	runID := "run-mcp-fail"

	upstream.mu.Lock()
	upstream.failTool = "mcp_update_customer_tier"
	upstream.mu.Unlock()

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "jordan", DelegatedRole: "SalesManager",
		Tool: "mcp_update_customer_tier", Args: map[string]any{"user_id": "7", "tier": "gold"}, RunID: runID,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Status != "error" {
		t.Fatalf("expected error status from an isError result, got %s", res.Status)
	}
	for _, step := range h.Sagas.StepsFor(runID) {
		if step.Tool == "mcp_update_customer_tier" {
			t.Fatal("a failed upstream call must not be recorded as an executed saga step")
		}
	}
}

// Misconfiguration has to say so plainly rather than fail somewhere
// downstream: a catalog can declare mcp-backed tools while the proxy has no
// upstream configured, and the operator needs to know which knob is missing.
func TestMCP_NoUpstreamConfiguredIsAClearError(t *testing.T) {
	h, _ := newMCPTestHandler(t)
	h.MCPUpstream = nil

	_, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "dana", DelegatedRole: "support",
		Tool: "mcp_get_user", Args: map[string]any{"user_id": "42"},
	})
	if err == nil {
		t.Fatal("expected an error when no upstream MCP server is configured")
	}
	if !strings.Contains(err.Error(), "mcp_upstream_url") {
		t.Fatalf("the error should name the missing config knob, got: %v", err)
	}
}

// Same fail-closed rule on the MCP path: no pre-image, no mutation.
func TestMCP_ClassARefusedWhenPreImageCaptureFails(t *testing.T) {
	h, upstream := newMCPTestHandler(t)
	upstream.mu.Lock()
	upstream.failTool = "mcp_get_user"
	upstream.mu.Unlock()

	res, err := h.Handle(context.Background(), proxytypes.CallRequest{
		Transport: "rest", AgentID: "agent-1", DelegatedUser: "jordan@example.com", DelegatedRole: "SalesManager",
		Tool: "mcp_update_customer_tier", Args: map[string]any{"user_id": "42", "tier": "gold"},
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Status != "error" || !strings.Contains(res.Reason, "pre-image") {
		t.Fatalf("expected refusal for lack of a pre-image, got %+v", res)
	}
	if got := upstream.tier("42"); got != "silver" {
		t.Fatalf("mutation must not have reached the upstream, tier is %q", got)
	}
	for _, name := range upstream.callNames() {
		if name == "mcp_update_customer_tier" {
			t.Fatal("the mutating tool must never have been called")
		}
	}
}
