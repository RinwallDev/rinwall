package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/audit"
	"github.com/RinwallDev/rinwall/internal/authn"
	"github.com/RinwallDev/rinwall/internal/capability"
	"github.com/RinwallDev/rinwall/internal/handler"
	"github.com/RinwallDev/rinwall/internal/policy"
	"github.com/RinwallDev/rinwall/internal/registry"
	"github.com/RinwallDev/rinwall/internal/saga"
)

const testToolsYAML = `
tools:
  - name: get_user
    description: "Look up a customer record by id"
    reversibility_class: B
    method: GET
    path: /users/{user_id}
    resource_arg: user_id
    args_schema:
      user_id: {type: string, required: true}

  # No arguments at all - the shape that produced "required": null and
  # made Claude Code reject the whole catalog.
  - name: ping
    description: "Health check, takes no arguments"
    reversibility_class: B
    method: GET
    path: /healthz
    args_schema: {}
`

const jwtSecret = "test-jwt-secret"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	h, verifier := newTestComponents(t)
	mux := http.NewServeMux()
	Register(mux, h, verifier)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// newTestComponents builds the handler and verifier both transports are
// served from, against a permissive fake upstream.
func newTestComponents(t *testing.T) (*handler.Handler, *authn.Verifier) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	toolsPath := filepath.Join(dir, "tools.yaml")
	os.WriteFile(toolsPath, []byte(testToolsYAML), 0644)
	reg, err := registry.LoadFromYAML(toolsPath)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(context.Background(), "../../../policies/tool_policy.rego")
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
	h := handler.New(reg, pol, capIssuer, approval.NewStore(), aud, saga.NewStore(), upstream.URL)
	return h, authn.NewVerifier(jwtSecret)
}

func mint(t *testing.T, user, role string) string {
	t.Helper()
	tok, err := authn.Mint(jwtSecret, user, role, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// rpcCall posts a raw JSON-RPC request body and returns the raw response -
// deliberately not using a real MCP client SDK here (that's what
// scripts/mcp_client_check.py is for) so these tests can assert on exact
// wire-level behavior (status codes, headers, body shape) fast and without
// a Python dependency.
func rpcCall(t *testing.T, server *httptest.Server, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", server.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestGet_MethodNotAllowed(t *testing.T) {
	server := newTestServer(t)
	resp, err := http.Get(server.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /mcp (no SSE push offered), got %d", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "POST" {
		t.Fatalf("expected Allow: POST header, got %q", allow)
	}
}

func TestNotification_GetsBareAccepted(t *testing.T) {
	server := newTestServer(t)
	// No "id" field - a JSON-RPC notification, not a request. Must get a
	// bare 202 with no JSON-RPC response body, per the transport spec -
	// not a "method not found" error, which an earlier version of this
	// adapter incorrectly returned.
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for a notification, got %d", resp.StatusCode)
	}
}

func TestInitialize_EchoesSupportedClientVersion(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`, nil)
	var body struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Result.ProtocolVersion != "2025-03-26" {
		t.Fatalf("expected the server to echo back a version it supports, got %q", body.Result.ProtocolVersion)
	}
}

func TestInitialize_FallsBackToLatestForUnknownClientVersion(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`, nil)
	var body struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Result.ProtocolVersion != latestProtocolVersion {
		t.Fatalf("expected fallback to %q for an unsupported client version, got %q", latestProtocolVersion, body.Result.ProtocolVersion)
	}
}

func TestUnsupportedProtocolVersionHeader_Rejected(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		map[string]string{"MCP-Protocol-Version": "1999-01-01"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unsupported MCP-Protocol-Version header, got %d", resp.StatusCode)
	}
}

func TestSupportedProtocolVersionHeader_Allowed(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		map[string]string{"MCP-Protocol-Version": latestProtocolVersion})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a supported MCP-Protocol-Version header, got %d", resp.StatusCode)
	}
}

func TestOrigin_DisallowedHostRejected(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		map[string]string{"Origin": "https://evil.example.com"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-local Origin (DNS-rebinding guard), got %d", resp.StatusCode)
	}
}

func TestOrigin_AbsentAllowed(t *testing.T) {
	server := newTestServer(t)
	// Real non-browser MCP client SDKs don't send an Origin header at all.
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with no Origin header, got %d", resp.StatusCode)
	}
}

func TestToolsCall_NoAuthRejected(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_user","arguments":{"user_id":"42"}}}`, nil)
	var body struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Error == nil {
		t.Fatal("expected a JSON-RPC error for an unauthenticated tools/call")
	}
}

func TestToolsCall_ValidJWTExecutes(t *testing.T) {
	server := newTestServer(t)
	tok := mint(t, "alex@example.com", "support")
	resp := rpcCall(t, server,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_user","arguments":{"user_id":"42"}}}`,
		map[string]string{"Authorization": "Bearer " + tok})
	var body struct {
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Result.IsError {
		t.Fatal("expected a valid tools/call to execute, not error")
	}
}

// An agent behind the proxy picks tools by reading descriptions. The proxy
// used to replace every one with a class label, which made every tool look
// the same to the model it was supposed to be protecting.
func TestToolsList_CarriesUpstreamDescription(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	var body struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range body.Result.Tools {
		if tool.Name == "get_user" && tool.Description == "Look up a customer record by id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the catalog's own description to reach the agent, got %+v", body.Result.Tools)
	}
}

// Found by registering with the real Claude Code client: a tool with no
// required arguments serialized "required": null, and the client's strict
// validator rejected the entire tools/list over it. The key must be an
// array or absent - never null.
func TestToolsList_EmptySchemaNeverEmitsNullRequired(t *testing.T) {
	server := newTestServer(t)
	resp := rpcCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	var body struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, tool := range body.Result.Tools {
		if req, present := tool.InputSchema["required"]; present && req == nil {
			t.Fatalf("tool %q emits \"required\": null - a strict client rejects the whole catalog over this", tool.Name)
		}
		if tool.Name == "ping" {
			if _, present := tool.InputSchema["required"]; present {
				t.Fatalf("a tool with no required arguments should omit the key, got %v", tool.InputSchema)
			}
			checked++
		}
	}
	if checked != 1 {
		t.Fatal("test fixture: the empty-schema tool was not in tools/list")
	}
}
