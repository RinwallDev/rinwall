package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testSecret = "test-secret"

func requestWith(auth string) *http.Request {
	r := httptest.NewRequest("POST", "/tool-call", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

func TestVerifier_RejectsMissingAndForged(t *testing.T) {
	v := NewVerifier(testSecret)

	if _, err := v.FromRequest(requestWith("")); err == nil {
		t.Fatal("a normal verifier must reject a missing credential")
	}
	if _, err := v.FromRequest(requestWith("Bearer not.a.token")); err == nil {
		t.Fatal("a normal verifier must reject a malformed credential")
	}
	// Signed with a different secret.
	other, err := Mint("some-other-secret", "evil", "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.FromRequest(requestWith("Bearer " + other)); err == nil {
		t.Fatal("a token signed with the wrong secret must be rejected")
	}
}

func TestVerifier_AcceptsGenuineToken(t *testing.T) {
	v := NewVerifier(testSecret)
	tok, err := Mint(testSecret, "dana", "support", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.FromRequest(requestWith("Bearer " + tok))
	if err != nil {
		t.Fatalf("a genuine token must verify: %v", err)
	}
	if claims.DelegatedUser != "dana" || claims.DelegatedRole != "support" {
		t.Fatalf("claims not carried through: %+v", claims)
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	v := NewVerifier(testSecret)
	tok, err := Mint(testSecret, "dana", "support", -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.FromRequest(requestWith("Bearer " + tok)); err == nil {
		t.Fatal("an expired token must be rejected")
	}
}

// Zero-config mode's whole convenience: no token needed to get started.
func TestOpenVerifier_AcceptsMissingCredential(t *testing.T) {
	v := NewOpenVerifier(testSecret, Claims{DelegatedUser: "local", DelegatedRole: "local"})
	if !v.IsOpen() {
		t.Fatal("IsOpen must report the relaxed posture so a banner can say so")
	}
	claims, err := v.FromRequest(requestWith(""))
	if err != nil {
		t.Fatalf("open mode must accept a missing credential: %v", err)
	}
	if claims.DelegatedUser != "local" || claims.DelegatedRole != "local" {
		t.Fatalf("expected the fallback identity, got %+v", claims)
	}
}

// The line that keeps this a convenience rather than an authentication
// bypass: a MISSING credential falls back, a BAD one does not. If a forged
// token silently became the local identity, anyone could authenticate as
// the fallback simply by sending garbage.
func TestOpenVerifier_StillRejectsBadCredentials(t *testing.T) {
	v := NewOpenVerifier(testSecret, Claims{DelegatedUser: "local", DelegatedRole: "local"})

	forged, err := Mint("some-other-secret", "evil", "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, header := range map[string]string{
		"forged signature": "Bearer " + forged,
		"malformed":        "Bearer not.a.token",
		"empty bearer":     "Bearer ",
	} {
		t.Run(name, func(t *testing.T) {
			claims, err := v.FromRequest(requestWith(header))
			if err == nil && name != "empty bearer" {
				t.Fatalf("open mode must still reject a bad credential, got %+v", claims)
			}
			if err == nil && claims.DelegatedUser == "evil" {
				t.Fatal("a forged token's claims must never be trusted")
			}
		})
	}
}

// A real token presented in open mode is honored normally, so an operator
// can exercise role policy without restarting out of the mode.
func TestOpenVerifier_HonorsARealToken(t *testing.T) {
	v := NewOpenVerifier(testSecret, Claims{DelegatedUser: "local", DelegatedRole: "local"})
	tok, err := Mint(testSecret, "reviewer@localhost", "approver", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.FromRequest(requestWith("Bearer " + tok))
	if err != nil {
		t.Fatal(err)
	}
	if claims.DelegatedRole != "approver" {
		t.Fatalf("a real token must win over the fallback, got %+v", claims)
	}
}
