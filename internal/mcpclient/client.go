// Package mcpclient is the client half of MCP - what this proxy needs to
// forward a call ONWARD to an upstream MCP server, as opposed to
// internal/adapter/mcp which is the server half that agents connect to.
//
// Having both is what makes "put the firewall in front of the MCP server
// you already run" possible at all: the agent talks MCP to us, we talk MCP
// to the real server, and the agent never holds that server's credential -
// we do, configured once, and it never enters the agent's context.
//
// Written against the same Streamable HTTP transport spec the server side
// was validated against, so it handles the parts a real upstream may use
// even though this project's own server doesn't: an Mcp-Session-Id
// assigned at initialize (which the spec says clients MUST echo on every
// later request), the MCP-Protocol-Version header, and an SSE-framed
// response, since the spec lets a server answer a POST with either a
// single JSON object or an event stream and requires clients to handle
// both.
package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const protocolVersion = "2025-06-18"

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// CallResult mirrors MCP's tools/call result: content blocks plus an
// isError flag that is NOT a transport error - a tool can fail on its own
// terms and still return a perfectly valid JSON-RPC response.
type CallResult struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError"`
}

// Text flattens the content blocks into a single string, which is what
// nearly every MCP tool actually returns.
func (r CallResult) Text() string {
	var b strings.Builder
	for _, block := range r.Content {
		if s, ok := block["text"].(string); ok {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(s)
		}
	}
	return b.String()
}

type Client struct {
	url  string
	auth string
	http *http.Client

	mu          sync.Mutex
	sessionID   string
	initialized bool
	nextID      int
}

type Option func(*Client)

// WithAuthorization sets a header sent on every request to the upstream -
// this is the credential the AGENT never gets to see.
func WithAuthorization(value string) Option {
	return func(c *Client) { c.auth = value }
}

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

func New(url string, opts ...Option) *Client {
	c := &Client{
		url:  url,
		http: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Initialize performs the MCP handshake. Safe to call more than once - a
// second call is a no-op, so callers don't have to coordinate who
// initializes first.
func (c *Client) Initialize(ctx context.Context) error {
	c.mu.Lock()
	if c.initialized {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	raw, sessionID, err := c.post(ctx, map[string]any{
		"jsonrpc": "2.0", "id": c.id(), "method": "initialize",
		"params": map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "rinwall", "version": "0.1"},
		},
	})
	if err != nil {
		return err
	}
	var resp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	_ = json.Unmarshal(raw, &resp)

	c.mu.Lock()
	c.sessionID = sessionID
	c.initialized = true
	c.mu.Unlock()

	// The spec's initialized notification. A notification gets no
	// response body, and a server that dislikes it isn't a reason to fail
	// the handshake we already completed.
	_, _, _ = c.post(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return nil
}

func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	if err := c.Initialize(ctx); err != nil {
		return nil, err
	}
	raw, _, err := c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": c.id(), "method": "tools/list"})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("mcpclient: parsing tools/list from %s: %w", c.url, err)
	}
	return resp.Result.Tools, nil
}

func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (CallResult, error) {
	return c.CallToolWithMeta(ctx, name, args, nil)
}

// CallToolWithMeta is CallTool plus the spec's own `params._meta` extension
// field - the same channel this project's MCP server side already accepts
// run ids and taint through. The proxy uses it to hand an upstream the
// capability token minted for this exact call, so an upstream that wants to
// verify independently can, without that being required of one that doesn't.
func (c *Client) CallToolWithMeta(ctx context.Context, name string, args, meta map[string]any) (CallResult, error) {
	if err := c.Initialize(ctx); err != nil {
		return CallResult{}, err
	}
	if args == nil {
		args = map[string]any{}
	}
	params := map[string]any{"name": name, "arguments": args}
	if len(meta) > 0 {
		params["_meta"] = meta
	}
	raw, _, err := c.post(ctx, map[string]any{
		"jsonrpc": "2.0", "id": c.id(), "method": "tools/call",
		"params": params,
	})
	if err != nil {
		return CallResult{}, err
	}
	var resp struct {
		Result CallResult `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return CallResult{}, fmt.Errorf("mcpclient: parsing tools/call result from %s: %w", c.url, err)
	}
	return resp.Result, nil
}

func (c *Client) id() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	return c.nextID
}

// post sends one JSON-RPC message and returns the raw response body plus
// any session id the server assigned. A JSON-RPC error in the body is
// returned as a Go error - callers shouldn't have to unpack that shape
// themselves.
func (c *Client) post(ctx context.Context, payload map[string]any) (body []byte, sessionID string, err error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(buf))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", protocolVersion)
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	}
	c.mu.Lock()
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	c.mu.Unlock()

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("mcpclient: reaching %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	sessionID = resp.Header.Get("Mcp-Session-Id")

	// A notification is answered with 202 and no body - nothing to parse,
	// and not an error.
	if resp.StatusCode == http.StatusAccepted {
		return nil, sessionID, nil
	}
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, sessionID, fmt.Errorf("mcpclient: %s returned HTTP %d: %s", c.url, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	raw, err := readBody(resp)
	if err != nil {
		return nil, sessionID, err
	}
	if len(raw) == 0 {
		return nil, sessionID, nil
	}

	var probe struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, sessionID, fmt.Errorf("mcpclient: %s returned a non-JSON-RPC body: %w", c.url, err)
	}
	if probe.Error != nil {
		return nil, sessionID, fmt.Errorf("mcpclient: %s returned JSON-RPC error %d: %s", c.url, probe.Error.Code, probe.Error.Message)
	}
	return raw, sessionID, nil
}

// readBody handles both shapes the transport allows for a response to a
// POSTed request: a plain JSON object, or an SSE stream whose events carry
// the JSON-RPC response. The spec requires clients to support both, and a
// real upstream is free to pick either.
func readBody(resp *http.Response) ([]byte, error) {
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return io.ReadAll(resp.Body)
	}

	// Take the first event carrying a JSON-RPC response and stop; the
	// server may keep the stream open after answering, and waiting for it
	// to close would hang the call.
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		case line == "":
			if data.Len() > 0 {
				return []byte(data.String()), nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("mcpclient: reading SSE stream: %w", err)
	}
	if data.Len() > 0 {
		return []byte(data.String()), nil
	}
	return nil, fmt.Errorf("mcpclient: SSE stream ended without a response")
}
