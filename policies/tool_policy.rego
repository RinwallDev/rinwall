# Coarse, role-based authorization: is the REAL delegated human's role even
# permitted to attempt this tool at all. This is deliberately separate from
# the Class C tiering mechanism (approval/pre-auth/hold), which decides HOW
# an already-permitted Class C call actually gets to run - see
# internal/approval. A tool can be policy-ALLOWED for a role and still be
# blocked by Class C tiering until a human (or a matching envelope) signs
# off on the specific call.
package rinwall

default allow = false
default deny_reason = "no matching policy rule"

allow {
	input.tool == "get_user"
}

allow {
	input.tool == "log_event"
}

# Any role may attempt "computer" - the reversibility/visual-provenance
# machinery, not role authorization, is what has to gate a screenshot-
# reasoning tool's actual danger, since a name-based role rule can't
# distinguish scrolling a page from confirming a payment any better than
# internal/classify can. See registry.Tool.VisualProvenanceJudge.
allow {
	input.tool == "computer"
}

allow {
	input.tool == "update_customer_tier"
	input.delegated_role == "SalesManager"
	input.args.tier == "silver"
}

allow {
	input.tool == "update_customer_tier"
	input.delegated_role == "SalesManager"
	input.args.tier == "gold"
}

allow {
	input.tool == "update_customer_tier"
	input.delegated_role == "admin"
}

allow {
	input.tool == "update_customer_status"
	input.delegated_role == "admin-lead"
}

allow {
	input.tool == "update_customer_status"
	input.delegated_role == "admin"
}

allow {
	input.tool == "send_refund_email"
	input.delegated_role == "support"
}

allow {
	input.tool == "send_refund_email"
	input.delegated_role == "admin"
}

allow {
	input.tool == "close_account"
	input.delegated_role == "support"
}

allow {
	input.tool == "close_account"
	input.delegated_role == "admin"
}

allow {
	input.tool == "list_customer_orders"
	input.delegated_role == "support"
}

allow {
	input.tool == "list_customer_orders"
	input.delegated_role == "admin"
}

allow {
	input.tool == "get_order_document"
	input.delegated_role == "support"
}

allow {
	input.tool == "get_order_document"
	input.delegated_role == "admin"
}

# MCP-backed tools (mcp_tool set in the catalog) go through this exact same
# policy engine as every HTTP-, DB-, and AWS-backed tool - which is the
# point: forwarding onward to an MCP server does not create a side path that
# skips authorization.

allow {
	input.tool == "mcp_get_user"
}

allow {
	input.tool == "mcp_update_customer_tier"
	input.delegated_role == "SalesManager"
}

allow {
	input.tool == "mcp_update_customer_tier"
	input.delegated_role == "admin"
}

allow {
	input.tool == "mcp_close_account"
	input.delegated_role == "support"
}

allow {
	input.tool == "mcp_close_account"
	input.delegated_role == "admin"
}

# "computer" (screenshot-reasoning agents): any role may attempt it - the
# visual-provenance/reversibility machinery gates the actual danger per
# call, since a role rule cannot distinguish scrolling from confirming a
# payment any better than a name-based classifier can.

allow {
	input.tool == "computer"
}

deny_reason = reason {
	not allow
	reason := sprintf("delegated_role=%q is not authorized for tool=%q (args=%v)", [input.delegated_role, input.tool, input.args])
}
