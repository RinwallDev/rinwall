// Package rest is one of the two adapters (see internal/adapter/mcp for
// the other): the conventional reverse-proxy path for agents calling
// REST/function-calling APIs directly rather than through an MCP server.
// Equal in standing to the MCP adapter, not a fallback.
package rest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/RinwallDev/rinwall/internal/approval"
	"github.com/RinwallDev/rinwall/internal/authn"
	"github.com/RinwallDev/rinwall/internal/handler"
	"github.com/RinwallDev/rinwall/internal/proxytypes"
	"github.com/RinwallDev/rinwall/internal/registry"
)

type toolCallBody struct {
	AgentID string         `json:"agent_id"`
	Tool    string         `json:"tool"`
	Args    map[string]any `json:"args"`
	// ArgProvenance: per-argument "trusted" | "tainted", supplied by the
	// orchestrator - we have no way to infer this ourselves. Absent
	// entirely, or an argument simply not mentioned, is treated as
	// trusted - see proxytypes.CallRequest's doc comment for why that's
	// the deliberate default rather than fail-closed.
	ArgProvenance map[string]proxytypes.Provenance `json:"arg_provenance,omitempty"`
	// RunID groups this call with others into one logical multi-step
	// operation for internal/saga - see proxytypes.CallRequest's doc
	// comment. Empty means untracked, same compatibility default as
	// ArgProvenance being absent.
	RunID string `json:"run_id,omitempty"`
	// ContextWindow: a bounded slice of the actual recent conversation,
	// for tools with the model-based provenance judge add-on enabled
	// (registry.Tool.ProvenanceJudge) - see internal/provenance. Absent
	// means the judge is never consulted, same compatibility default as
	// the other optional fields above.
	ContextWindow []proxytypes.ContextMessage `json:"context_window,omitempty"`
	// Screenshot/StatedIntent: for tools with the visual provenance judge
	// add-on enabled (registry.Tool.VisualProvenanceJudge) - see
	// internal/visualprovenance. Screenshot is base64-encoded image bytes
	// (PNG/JPEG); StatedIntent is the agent's own stated reasoning for the
	// action it's about to take. Both absent means the judge is never
	// consulted, same compatibility default as the other optional fields.
	Screenshot   string `json:"screenshot,omitempty"`
	StatedIntent string `json:"stated_intent,omitempty"`
}

type approveBody struct {
	Hash string `json:"hash"`
}

type envelopeBody struct {
	Tool           string                         `json:"tool"`
	ArgConstraints map[string]approval.Constraint `json:"arg_constraints"`
	MaxUses        int                            `json:"max_uses"`
	TTLSeconds     int                            `json:"ttl_seconds"`
}

func Register(mux *http.ServeMux, h *handler.Handler, appr *approval.Store, verifier *authn.Verifier) {
	mux.HandleFunc("POST /tool-call", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		var body toolCallBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "reason": "bad request body"})
			return
		}
		var screenshot []byte
		if body.Screenshot != "" {
			decoded, err := base64.StdEncoding.DecodeString(body.Screenshot)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "reason": "screenshot: not valid base64: " + err.Error()})
				return
			}
			screenshot = decoded
		}
		result, err := h.Handle(r.Context(), proxytypes.CallRequest{
			Transport: "rest", AgentID: body.AgentID, DelegatedUser: claims.DelegatedUser,
			DelegatedRole: claims.DelegatedRole, Tool: body.Tool, Args: body.Args,
			ArgProvenance: body.ArgProvenance, RunID: body.RunID, ContextWindow: body.ContextWindow,
			Screenshot: screenshot, StatedIntent: body.StatedIntent,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("POST /approvals/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		id := r.PathValue("id")
		var body approveBody
		_ = json.NewDecoder(r.Body).Decode(&body)

		pending, ok := appr.Get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "reason": "no such approval"})
			return
		}
		updated, err := appr.Approve(id, body.Hash, claims.DelegatedUser, claims.DelegatedRole)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		if updated.Status != approval.StatusApproved {
			// Four-eyes: this approval landed but at least one more distinct
			// approver is still required before the call actually executes.
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "recorded",
				"reason": fmt.Sprintf("%d of %d required approvals recorded - awaiting %d more",
					len(updated.Approvers), updated.RequiredApprovals, updated.RequiredApprovals-len(updated.Approvers)),
			})
			return
		}
		result, err := h.CompleteApproval(r.Context(), pending, proxytypes.CallRequest{
			Transport: "rest", DelegatedUser: claims.DelegatedUser, DelegatedRole: claims.DelegatedRole, Tool: pending.Tool,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("POST /approvals/{id}/deny", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		id := r.PathValue("id")
		// Fetched before Deny so we still have RunID even though Deny only
		// returns an error, not the updated record.
		pending, ok := appr.Get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "reason": "no such approval"})
			return
		}
		if err := appr.Deny(id, claims.DelegatedUser, claims.DelegatedRole); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		// A denied approval that belongs to a tracked run is the same
		// "workflow broke here" signal a synchronous deny inside Handle
		// already triggers compensation for - see Handler.Handle's wrapper.
		if pending.RunID != "" {
			h.CompensateRun(r.Context(), pending.RunID, fmt.Sprintf("approval %s for %s denied by %s", id, pending.Tool, claims.DelegatedUser))
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "denied"})
	})

	// Requires the same reviewer_role as the tool itself, exactly like
	// /approve and /deny - cancelling a queued Class C action is at least
	// as sensitive as approving one.
	//
	// compensate_run is deliberately opt-in, not a default either
	// direction: a cancelled hold is a genuinely different signal than a
	// denial (see internal/handler.CompensateRun's callers) - the reviewer
	// might be blocking only this one risky step while being fine with
	// earlier, unrelated steps in the same run standing. Auto-compensating
	// by default would risk undoing something the reviewer never objected
	// to; never compensating would leave no way to unwind the run when
	// they DO want that. So the reviewer decides explicitly, at the exact
	// moment they have the context to make that call correctly.
	mux.HandleFunc("POST /holds/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		id := r.PathValue("id")
		var body struct {
			CompensateRun bool `json:"compensate_run"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body) // an empty/absent body is fine - compensate_run just defaults false

		hold, err := appr.CancelHold(id, claims.DelegatedRole)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		if body.CompensateRun && hold.RunID != "" {
			h.CompensateRun(r.Context(), hold.RunID, fmt.Sprintf("hold %s for %s cancelled by %s (compensate_run requested)", id, hold.Tool, claims.DelegatedUser))
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "cancelled"})
	})

	// Lets a human pre-authorize a bounded envelope ahead of time - Tier 1.
	// e.g. {"tool":"send_refund_email","arg_constraints":{"amount_cents":{"Op":"lte","Value":"5000"}},"max_uses":3,"ttl_seconds":86400}
	//
	// Gated the same way approve/deny are: creating an envelope is arguably
	// MORE sensitive than approving one request, since it standing-
	// pre-authorizes every future call that matches - so it requires the
	// exact same reviewer_role as manually approving that tool would, not
	// just any verified identity. Only makes sense for Class C tools in the
	// first place (CheckPreAuth is only ever consulted from the Class C
	// tier-1 path), so an envelope for an unknown or non-Class-C tool is
	// rejected outright rather than silently created and never matched.
	mux.HandleFunc("POST /envelopes", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.FromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		var body envelopeBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "reason": "bad request body"})
			return
		}
		tool, ok := h.Registry.Get(body.Tool)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "reason": fmt.Sprintf("unknown tool %q", body.Tool)})
			return
		}
		if tool.ReversibilityClass != registry.ClassC {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error",
				"reason": fmt.Sprintf("tool %q is class %s, not C - pre-authorized envelopes only apply to Class C tools", body.Tool, tool.ReversibilityClass)})
			return
		}
		if claims.DelegatedRole != tool.ReviewerRole {
			writeJSON(w, http.StatusForbidden, map[string]any{"status": "error",
				"reason": fmt.Sprintf("creating an envelope for %q requires reviewer_role=%q, caller has role %q", body.Tool, tool.ReviewerRole, claims.DelegatedRole)})
			return
		}

		ttl := body.TTLSeconds
		if ttl <= 0 {
			ttl = 86400
		}
		env, err := appr.CreateEnvelope(body.Tool, body.ArgConstraints, body.MaxUses, time.Duration(ttl)*time.Second)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		h.Audit.Write(map[string]any{"decision": "ENVELOPE_CREATED", "tool": body.Tool, "delegated_role": claims.DelegatedRole,
			"reason":         fmt.Sprintf("envelope %s created by %s, max_uses=%d, ttl=%ds", env.ID, claims.DelegatedUser, body.MaxUses, ttl),
			"delegated_user": claims.DelegatedUser})
		writeJSON(w, http.StatusOK, map[string]any{"status": "created", "envelope_id": env.ID})
	})

	// Listing endpoints back the reviewer UI (GET /admin). Any verified
	// identity may view what's pending - the specific ReviewerRole check
	// still gates the actual approve/deny action, this just lets a human
	// see the queue before acting on it.
	mux.HandleFunc("GET /approvals", func(w http.ResponseWriter, r *http.Request) {
		if _, err := verifier.FromRequest(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, appr.ListPendingApprovals())
	})

	mux.HandleFunc("GET /holds", func(w http.ResponseWriter, r *http.Request) {
		if _, err := verifier.FromRequest(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, appr.ListHolds())
	})

	mux.HandleFunc("GET /envelopes", func(w http.ResponseWriter, r *http.Request) {
		if _, err := verifier.FromRequest(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "reason": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, appr.ListEnvelopes())
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
