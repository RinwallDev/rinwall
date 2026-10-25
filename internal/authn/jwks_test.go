package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testIdP stands in for a real IdP (Okta/Auth0/etc) from this code's point
// of view: a real, self-signed RSA keypair plus a real httptest.Server
// serving a real JWKS document built from its public half - the same
// "prove it against the real shape of the thing" standard the rest of
// this project holds itself to, without needing an actual third-party IdP
// account.
type testIdP struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	kid    string
}

func newTestIdP(t *testing.T, kid string) *testIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{priv: priv, kid: kid}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reads idp.kid/idp.priv live (not a captured local) so a test can
		// simulate the IdP rotating its signing key mid-test by mutating
		// those fields directly - see
		// TestJWKSVerifier_UnknownKidTriggersExactlyOneRefetch.
		doc := jwksDocument{Keys: []jwkKey{{
			Kty: "RSA",
			Kid: idp.kid,
			N:   base64.RawURLEncoding.EncodeToString(idp.priv.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigIntBytesFromInt(idp.priv.PublicKey.E)),
		}}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(idp.server.Close)
	return idp
}

func bigIntBytesFromInt(e int) []byte {
	return big.NewInt(int64(e)).Bytes()
}

// mint signs a real RS256 token with this IdP's private key - claims are
// passed as a plain map so tests can exercise arbitrary/non-default claim
// names for userClaim/roleClaim.
func (idp *testIdP) mint(t *testing.T, claims map[string]any, ttl time.Duration) string {
	t.Helper()
	mc := jwt.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	mc["exp"] = time.Now().Add(ttl).Unix()
	mc["iat"] = time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mc)
	token.Header["kid"] = idp.kid
	signed, err := token.SignedString(idp.priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestNewJWKSVerifier_RequiresIssuer(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	if _, err := NewJWKSVerifier(idp.server.URL, "", "", "", ""); err == nil {
		t.Fatal("expected NewJWKSVerifier to refuse construction without an issuer")
	}
}

func TestJWKSVerifier_AcceptsGenuineToken(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tok := idp.mint(t, map[string]any{
		"iss": "https://idp.example.com/", "delegated_user": "dana@example.com", "delegated_role": "support",
	}, time.Hour)

	claims, err := v.FromRequest(requestWith("Bearer " + tok))
	if err != nil {
		t.Fatalf("a genuine RS256 token must verify: %v", err)
	}
	if claims.DelegatedUser != "dana@example.com" || claims.DelegatedRole != "support" {
		t.Fatalf("claims not carried through: %+v", claims)
	}
}

func TestJWKSVerifier_RejectsWrongKey(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	otherIdP := newTestIdP(t, "key-1") // same kid, DIFFERENT private key - simulates a forged/substituted signature
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	forged := otherIdP.mint(t, map[string]any{
		"iss": "https://idp.example.com/", "delegated_user": "evil", "delegated_role": "admin",
	}, time.Hour)
	if _, err := v.FromRequest(requestWith("Bearer " + forged)); err == nil {
		t.Fatal("expected a token signed by a different key (even with a matching kid) to be rejected")
	}
}

func TestJWKSVerifier_RejectsExpired(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tok := idp.mint(t, map[string]any{
		"iss": "https://idp.example.com/", "delegated_user": "dana", "delegated_role": "support",
	}, -time.Minute)
	if _, err := v.FromRequest(requestWith("Bearer " + tok)); err == nil {
		t.Fatal("expected an expired token to be rejected")
	}
}

func TestJWKSVerifier_RejectsWrongIssuer(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tok := idp.mint(t, map[string]any{
		"iss": "https://a-completely-different-app.example.com/", "delegated_user": "dana", "delegated_role": "support",
	}, time.Hour)
	if _, err := v.FromRequest(requestWith("Bearer " + tok)); err == nil {
		t.Fatal("expected a token issued for a different application (wrong iss) to be rejected - this is the cross-app replay this check exists to catch")
	}
}

func TestJWKSVerifier_RejectsWrongAudienceWhenConfigured(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "jitfirewall-prod", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tok := idp.mint(t, map[string]any{
		"iss": "https://idp.example.com/", "aud": "some-other-app", "delegated_user": "dana", "delegated_role": "support",
	}, time.Hour)
	if _, err := v.FromRequest(requestWith("Bearer " + tok)); err == nil {
		t.Fatal("expected a token with a non-matching audience to be rejected")
	}
}

func TestJWKSVerifier_ConfigurableClaimNames(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "", "email", "https://jitfirewall/role")
	if err != nil {
		t.Fatal(err)
	}
	tok := idp.mint(t, map[string]any{
		"iss": "https://idp.example.com/", "email": "jordan@example.com", "https://jitfirewall/role": "SalesManager",
		// The default claim names must NOT be consulted once overridden.
		"delegated_user": "wrong", "delegated_role": "wrong",
	}, time.Hour)

	claims, err := v.FromRequest(requestWith("Bearer " + tok))
	if err != nil {
		t.Fatal(err)
	}
	if claims.DelegatedUser != "jordan@example.com" || claims.DelegatedRole != "SalesManager" {
		t.Fatalf("expected the configured claim names to be used, got %+v", claims)
	}
}

func TestJWKSVerifier_RejectsHS256Token(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// A validly-signed HS256 token (e.g. one from cmd/devtoken) must never
	// be accepted by a Verifier in JWKS mode - only RS256 is trusted here.
	hs256Tok, err := Mint("any-secret", "dana", "support", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.FromRequest(requestWith("Bearer " + hs256Tok)); err == nil {
		t.Fatal("expected an HS256 token to be rejected by a JWKS-mode verifier")
	}
}

func TestJWKSVerifier_UnknownKidTriggersExactlyOneRefetch(t *testing.T) {
	idp := newTestIdP(t, "key-1")
	v, err := NewJWKSVerifier(idp.server.URL, "https://idp.example.com/", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the IdP having rotated to a new key AFTER this Verifier's
	// initial fetch, by minting with a kid that wasn't in the cache at
	// construction time but IS servable now (mint's own idp.kid is used
	// as the header, and idp's JWKS handler always reports the CURRENT
	// idp.kid/key - flipping it here simulates a real rotation).
	idp.kid = "key-2"
	idp.priv, _ = rsa.GenerateKey(rand.Reader, 2048)
	rotated := idp.mint(t, map[string]any{
		"iss": "https://idp.example.com/", "delegated_user": "dana", "delegated_role": "support",
	}, time.Hour)

	claims, err := v.FromRequest(requestWith("Bearer " + rotated))
	if err != nil {
		t.Fatalf("expected an unknown kid to trigger a refetch and then succeed, got: %v", err)
	}
	if claims.DelegatedUser != "dana" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// A genuinely unknown kid (the IdP never actually serving it) must
	// still be rejected, not accepted after refetching finds nothing.
	idp.kid = "key-that-will-never-be-served"
	stillBad := fmt.Sprintf("Bearer %s", idp.mint(t, map[string]any{
		"iss": "https://idp.example.com/", "delegated_user": "dana", "delegated_role": "support",
	}, time.Hour))
	idp.kid = "key-2" // restore what the JWKS endpoint actually serves before the request fires
	if _, err := v.FromRequest(requestWith(stillBad)); err == nil {
		t.Fatal("expected a kid the IdP never actually serves to be rejected even after a refetch")
	}
}
