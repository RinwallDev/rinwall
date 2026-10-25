// Package adminui embeds the minimal reviewer console served at GET /admin.
// This is about the demo not depending on a reviewer typing curl commands
// for Class C approvals - not a real admin product. Auth is handled by the
// page itself pasting a bearer token into every fetch(), same JWTs
// cmd/devtoken mints; the page never gets special server-side privilege.
package adminui

import _ "embed"

//go:embed admin.html
var HTML []byte
