// Package mcp exposes the handler as an MCP server over two transports:
// Streamable HTTP (POST /mcp, spec 2025-06-18, back-compatible with
// 2024-11-05/2025-03-26 clients) and stdio (stdio.go), for clients that
// launch a local server process rather than connect to a URL. Both
// transports share one JSON-RPC dispatch; they differ only in message
// framing and in where the caller's identity comes from.
//
// Wire-level conformance was checked against the spec text and the official
// Python SDK: version negotiation echoes back whatever version the client
// requests (if it's one we claim), JSON-RPC notifications get no response
// body, GET returns 405 (no server-initiated SSE push), and the Origin
// header is checked per the spec's DNS-rebinding warning. Deliberately not
// built: SSE streaming responses and Mcp-Session-Id session state - both
// spec-optional, and this proxy needs neither.
//
// MCP has no standardized notion of "the real delegated human's role."
// Until the spec grows one, the HTTP transport carries delegated identity
// as a verified JWT on the Authorization header (the same
// internal/authn.Verifier the REST adapter uses); the stdio transport runs
// as one identity fixed at startup, since a locally launched process serves
// exactly one local user. AgentID is a plain label - telemetry, never a
// trust boundary.
package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/RinwallDev/rinwall/internal/authn"
	"github.com/RinwallDev/rinwall/internal/handler"
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
)

// supportedProtocolVersions is every MCP protocol version this adapter
// claims to speak - per the spec's negotiation rule, a requested version we
// support is echoed back; anything else gets our latest.
var supportedProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const latestProtocolVersion = "2025-06-18"

func isSupportedProtocolVersion(v string) bool {
	for _, sv := range supportedProtocolVersions {
		if sv == v {
			return true
		}
	}
	return false
}

// originAllowed implements the transport spec's own security requirement
// ("servers MUST validate the Origin header... to prevent DNS rebinding
// attacks"). A real MCP client SDK (Python/TS, non-browser) typically sends
// no Origin header at all - only a browser-driven request would, which is
// exactly the DNS-rebinding scenario this guards against - so an absent
// Origin is allowed and a present one must be a local origin.
func originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type toolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	// Meta rides in MCP's own reserved extension field (_meta on any
	// request) rather than an invented top-level key - the spec-aligned
	// way to carry implementation-specific data like taint provenance.
	Meta *struct {
		ArgProvenance map[string]proxytypes.Provenance `json:"arg_provenance,omitempty"`
		RunID         string                           `json:"run_id,omitempty"`
		ContextWindow []proxytypes.ContextMessage      `json:"context_window,omitempty"`
		// Screenshot/StatedIntent feed the visual provenance judge
		// (registry.Tool.VisualProvenanceJudge). Screenshot is base64.
		Screenshot   string `json:"screenshot,omitempty"`
		StatedIntent string `json:"stated_intent,omitempty"`
	} `json:"_meta,omitempty"`
}

// Server is the transport-agnostic MCP server: one dispatch, served over
// HTTP (Register) and/or stdio (ServeStdio).
type Server struct {
	h        *handler.Handler
	verifier *authn.Verifier
}

func NewServer(h *handler.Handler, verifier *authn.Verifier) *Server {
	return &Server{h: h, verifier: verifier}
}

// Register mounts the Streamable HTTP transport on mux.
func Register(mux *http.ServeMux, h *handler.Handler, verifier *authn.Verifier) {
	NewServer(h, verifier).Register(mux)
}

func (s *Server) Register(mux *http.ServeMux) {
	// The transport spec requires the endpoint to support both POST and
	// GET. We don't offer server-initiated SSE push, and the spec
	// explicitly allows answering GET with 405 to say so.
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		if !originAllowed(r.Header.Get("Origin")) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}

		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, rpcError(nil, -32700, "parse error"))
			return
		}

		// A JSON-RPC notification (no id, e.g. notifications/initialized)
		// gets a bare 202 Accepted with no body, never a JSON-RPC response.
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		if req.Method != "initialize" {
			if pv := r.Header.Get("MCP-Protocol-Version"); pv != "" && !isSupportedProtocolVersion(pv) {
				http.Error(w, "unsupported MCP-Protocol-Version: "+pv, http.StatusBadRequest)
				return
			}
		}

		writeJSON(w, s.dispatch(r.Context(), req, func() (authn.Claims, error) {
			return s.verifier.FromRequest(r)
		}, r.Header.Get("X-Agent-Id")))
	})
}

// dispatch answers one JSON-RPC request (never a notification - callers
// filter those first, since the two transports acknowledge them
// differently). identity is a callback because the transports resolve it
// differently: HTTP verifies a bearer token per request, stdio was fixed
// at startup. It is only consulted for tools/call - initialize and
// tools/list are unauthenticated discovery on both transports.
func (s *Server) dispatch(ctx context.Context, req rpcRequest, identity func() (authn.Claims, error), agentID string) map[string]any {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)
		negotiated := latestProtocolVersion
		if isSupportedProtocolVersion(params.ProtocolVersion) {
			negotiated = params.ProtocolVersion
		}
		return rpcResult(req.ID, map[string]any{
			"protocolVersion": negotiated,
			"serverInfo":      map[string]any{"name": "rinwall", "version": "0.1.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		})

	case "tools/list":
		tools := make([]map[string]any, 0, len(s.h.Registry.All()))
		for name, t := range s.h.Registry.All() {
			// The upstream's real description when there is one - an
			// agent picks tools by reading these.
			desc := t.Description
			if desc == "" {
				desc = fmt.Sprintf("reversibility_class=%s", t.ReversibilityClass)
			}
			tools = append(tools, map[string]any{
				"name":        name,
				"description": desc,
				"inputSchema": schemaToJSON(t.ArgsSchema),
			})
		}
		return rpcResult(req.ID, map[string]any{"tools": tools})

	case "tools/call":
		claims, err := identity()
		if err != nil {
			return rpcError(req.ID, -32001, "unauthorized: "+err.Error())
		}
		var params toolsCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return rpcError(req.ID, -32602, "invalid params")
		}
		callReq := proxytypes.CallRequest{
			Transport:     "mcp",
			AgentID:       agentID,
			DelegatedUser: claims.DelegatedUser,
			DelegatedRole: claims.DelegatedRole,
			Tool:          params.Name,
			Args:          params.Arguments,
		}
		if params.Meta != nil {
			callReq.ArgProvenance = params.Meta.ArgProvenance
			callReq.RunID = params.Meta.RunID
			callReq.ContextWindow = params.Meta.ContextWindow
			if params.Meta.Screenshot != "" {
				decoded, err := base64.StdEncoding.DecodeString(params.Meta.Screenshot)
				if err != nil {
					return rpcError(req.ID, -32602, "invalid params: screenshot: not valid base64: "+err.Error())
				}
				callReq.Screenshot = decoded
			}
			callReq.StatedIntent = params.Meta.StatedIntent
		}
		result, err := s.h.Handle(ctx, callReq)
		if err != nil {
			return rpcError(req.ID, -32000, err.Error())
		}
		resultJSON, _ := json.Marshal(result)
		return rpcResult(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(resultJSON)}},
			"isError": result.Status == "denied" || result.Status == "error",
		})

	default:
		return rpcError(req.ID, -32601, "method not found: "+req.Method)
	}
}

func schemaToJSON(schema map[string]registry.FieldSpec) map[string]any {
	props := map[string]any{}
	var required []string
	for name, spec := range schema {
		p := map[string]any{"type": jsonSchemaType(spec.Type)}
		if len(spec.Enum) > 0 {
			p["enum"] = spec.Enum
		}
		props[name] = p
		if spec.Required {
			required = append(required, name)
		}
	}
	out := map[string]any{"type": "object", "properties": props}
	// Omitted when empty, never emitted as null: a nil slice marshals to
	// JSON null, and real clients validate tools/list strictly - Claude
	// Code rejected the entire catalog over one tool with no required
	// arguments. The official Python SDK was lenient, which is why tests
	// against it never caught this.
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func jsonSchemaType(t string) string {
	switch t {
	case "number":
		return "number"
	case "bool":
		return "boolean"
	default:
		return "string"
	}
}

func rpcResult(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "result": result}
}

func rpcError(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id),
		"error": map[string]any{"code": code, "message": message}}
}

func rawOrNull(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	return id
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
