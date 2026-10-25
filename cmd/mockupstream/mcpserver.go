package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/RinwallDev/rinwall/internal/capability"
)

// The MCP face of the mock upstream, added to verify MCP-to-MCP
// passthrough end to end: the proxy is an MCP server to the agent AND an
// MCP client to this, over exactly the same user state the HTTP routes
// mutate. Two things about it are deliberate.
//
// First, it exposes its tools under mcp_-prefixed names so they can live in
// the SAME catalog as the HTTP-backed tools rather than in a parallel
// deployment - which makes the real claim testable, that one proxy fronts
// HTTP, DB, AWS, and MCP upstreams at once and every one of them goes
// through the same policy, taint, class gating, and saga machinery.
//
// Second, and more interesting: it verifies the capability token the proxy
// forwards in params._meta, the same way the HTTP routes verify the one in
// their Authorization header. That turns "an upstream that wants to check
// independently can" from a claim into something demonstrated - the
// upstream is checking that this exact call was authorized for this exact
// tool and resource, and rejects a token that wasn't. A stock upstream MCP
// server would simply ignore the field; this one shows what adopting it
// buys.

type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func stringSchema(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required}
}

var mcpTools = []mcpToolDef{
	{
		Name:        "mcp_get_user",
		Description: "Read a customer record.",
		InputSchema: stringSchema([]string{"user_id"}, map[string]any{
			"user_id": map[string]any{"type": "string"},
		}),
	},
	{
		Name:        "mcp_update_customer_tier",
		Description: "Change a customer's loyalty tier.",
		InputSchema: stringSchema([]string{"user_id", "tier"}, map[string]any{
			"user_id": map[string]any{"type": "string"},
			"tier":    map[string]any{"type": "string", "enum": []any{"bronze", "silver", "gold"}},
		}),
	},
	{
		Name:        "mcp_close_account",
		Description: "Permanently close a customer account. This cannot be undone.",
		InputSchema: stringSchema([]string{"user_id"}, map[string]any{
			"user_id": map[string]any{"type": "string"},
		}),
	},
}

func mcpResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func mcpJSONResult(v any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return mcpResult("internal error encoding result", true)
	}
	return mcpResult(string(raw), false)
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     any            `json:"id"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON-RPC body", http.StatusBadRequest)
		return
	}
	// A notification carries no id and gets no response body - the same
	// rule this project's own MCP adapter follows.
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	reply := func(result any) {
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}

	switch req.Method {
	case "initialize":
		reply(map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "mockupstream", "version": "0.1"},
		})
	case "tools/list":
		reply(map[string]any{"tools": mcpTools})
	case "tools/call":
		reply(callMCPTool(req.Params))
	default:
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]any{"code": -32601, "message": "method not found: " + req.Method}})
	}
}

func callMCPTool(params map[string]any) map[string]any {
	name, _ := params["name"].(string)
	args, _ := params["arguments"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	meta, _ := params["_meta"].(map[string]any)
	capToken, _ := meta["jit_capability"].(string)

	userID, _ := args["user_id"].(string)

	// Independent verification, exactly as the HTTP routes do it: this
	// upstream does not take the proxy's word that the call was
	// authorized. mcp_get_user is left unverified on purpose, mirroring
	// GET /users/{id} - a read this mock never gated - so the difference
	// between a gated and an ungated tool stays visible.
	if name != "mcp_get_user" {
		if err := capability.Verify(capToken, currentKeys(), name, userID); err != nil {
			log.Printf("[mockupstream/mcp] REJECTED %s for user %s: %v", name, userID, err)
			return mcpResult("capability verification failed: "+err.Error(), true)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	u, ok := users[userID]
	if !ok {
		return mcpResult("no such user: "+userID, true)
	}

	switch name {
	case "mcp_get_user":
		return mcpJSONResult(u)

	case "mcp_update_customer_tier":
		tier, _ := args["tier"].(string)
		previous := u.Tier
		u.Tier = tier
		log.Printf("[mockupstream/mcp] tier %s -> %s for user %s", previous, tier, userID)
		return mcpJSONResult(map[string]any{"status": "updated", "user": u, "previous_tier": previous})

	case "mcp_close_account":
		u.Status = "closed"
		log.Printf("[mockupstream/mcp] account CLOSED for user %s (irreversible)", userID)
		return mcpJSONResult(map[string]any{"status": "closed", "user": u})

	default:
		return mcpResult("unknown tool: "+name, true)
	}
}
