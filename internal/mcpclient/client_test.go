package mcpclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeMCPServer records what it was sent and answers with whatever the test
// wired up - enough to assert the wire-level behavior a real upstream would
// depend on, without needing a real one.
type fakeMCPServer struct {
	sseMode      bool
	sessionID    string
	gotSessionID []string
	gotAuth      []string
	lastParams   map[string]any
	notified     bool
}

func (f *fakeMCPServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)

		f.gotSessionID = append(f.gotSessionID, r.Header.Get("Mcp-Session-Id"))
		f.gotAuth = append(f.gotAuth, r.Header.Get("Authorization"))

		if req.ID == nil {
			f.notified = true
			w.WriteHeader(http.StatusAccepted)
			return
		}

		var result any
		switch req.Method {
		case "initialize":
			if f.sessionID != "" {
				w.Header().Set("Mcp-Session-Id", f.sessionID)
			}
			result = map[string]any{"protocolVersion": "2025-06-18"}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{
				{"name": "get_user", "description": "Read a user.",
					"inputSchema": map[string]any{"type": "object"}},
			}}
		case "tools/call":
			f.lastParams = req.Params
			result = map[string]any{
				"content": []map[string]any{{"type": "text", "text": `{"tier":"gold"}`}},
				"isError": false,
			}
		}

		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if f.sseMode {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: message\ndata: " + string(payload) + "\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	})
}

func TestClient_HandshakeListAndCall(t *testing.T) {
	fake := &fakeMCPServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	c := New(srv.URL)
	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "get_user" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
	if !fake.notified {
		// A real server may treat a missing notifications/initialized as an
		// incomplete handshake, so this is protocol conformance, not detail.
		t.Fatal("client never sent notifications/initialized")
	}

	res, err := c.CallTool(context.Background(), "get_user", map[string]any{"user_id": "42"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatal("expected a successful result")
	}
	if res.Text() != `{"tier":"gold"}` {
		t.Fatalf("unexpected content text: %q", res.Text())
	}
}

// The transport spec lets a server answer a POST with an SSE stream instead
// of a JSON object and requires clients to handle both - a real upstream is
// free to pick either, so this can't be left to chance.
func TestClient_SSEFramedResponse(t *testing.T) {
	fake := &fakeMCPServer{sseMode: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	tools, err := New(srv.URL).ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools over SSE: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool over SSE, got %d", len(tools))
	}
}

// The spec says a client MUST echo an Mcp-Session-Id the server assigned at
// initialize on every subsequent request. Dropping it makes a stateful
// upstream reject everything after the handshake.
func TestClient_EchoesAssignedSessionID(t *testing.T) {
	fake := &fakeMCPServer{sessionID: "sess-abc"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	c := New(srv.URL)
	if _, err := c.ListTools(context.Background()); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if fake.gotSessionID[0] != "" {
		t.Fatal("the initialize request should not carry a session id - the server assigns it")
	}
	for i, got := range fake.gotSessionID[1:] {
		if got != "sess-abc" {
			t.Fatalf("request %d after initialize sent session id %q, want %q", i+1, got, "sess-abc")
		}
	}
}

// The upstream's credential is held here and sent to the upstream - the
// whole reason the agent never has to hold it.
func TestClient_SendsUpstreamCredential(t *testing.T) {
	fake := &fakeMCPServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	c := New(srv.URL, WithAuthorization("Bearer upstream-secret"))
	if _, err := c.ListTools(context.Background()); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for i, got := range fake.gotAuth {
		if got != "Bearer upstream-secret" {
			t.Fatalf("request %d sent Authorization %q", i, got)
		}
	}
}

func TestClient_CallToolWithMetaCarriesCapability(t *testing.T) {
	fake := &fakeMCPServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	_, err := New(srv.URL).CallToolWithMeta(context.Background(), "update_customer_tier",
		map[string]any{"user_id": "42"}, map[string]any{"jit_capability": "biscuit-token"})
	if err != nil {
		t.Fatalf("CallToolWithMeta: %v", err)
	}
	meta, ok := fake.lastParams["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("params carried no _meta: %+v", fake.lastParams)
	}
	if meta["jit_capability"] != "biscuit-token" {
		t.Fatalf("capability not forwarded: %+v", meta)
	}
	// _meta must be a sibling of name/arguments, not folded into the tool's
	// own arguments, or the upstream would see a phantom argument its
	// schema never declared.
	args, _ := fake.lastParams["arguments"].(map[string]any)
	if _, leaked := args["jit_capability"]; leaked {
		t.Fatal("capability leaked into the tool's arguments")
	}
}

// A JSON-RPC error is a protocol failure and must surface as a Go error,
// which is a different thing from a tool reporting its own failure via
// isError - see TestClient_ToolReportedErrorIsNotATransportError.
func TestClient_JSONRPCErrorSurfacesAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL).ListTools(context.Background())
	if err == nil {
		t.Fatal("expected a JSON-RPC error to surface as an error")
	}
}

func TestClient_ToolReportedErrorIsNotATransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID any `json:"id"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
			"content": []map[string]any{{"type": "text", "text": "permission denied"}},
			"isError": true,
		}})
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	res, err := New(srv.URL).CallTool(context.Background(), "close_account", nil)
	if err != nil {
		t.Fatalf("a tool-reported failure is a valid response, not a transport error: %v", err)
	}
	if !res.IsError || res.Text() != "permission denied" {
		t.Fatalf("expected the tool's own error to come through intact, got %+v", res)
	}
}
