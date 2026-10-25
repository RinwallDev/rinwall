// Package authn verifies the delegated human's identity. This is separate
// from - and a prerequisite for - the capability/reversibility machinery:
// every policy decision downstream trusts DelegatedUser/DelegatedRole, so
// those values must come from a signed token, never from a plain string the
// caller wrote into the request itself. Two modes behind one Verifier
// type: HS256 with a shared secret (local/dev, paired with cmd/devtoken),
// or RS256 against a real IdP's published JWKS (NewJWKSVerifier). Callers
// don't know which is active.
package authn

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	DelegatedUser string `json:"delegated_user"`
	DelegatedRole string `json:"delegated_role"`
	jwt.RegisteredClaims
}

type Verifier struct {
	secret   []byte
	fallback *Claims

	// JWKS mode (a real IdP - Okta/Auth0/Azure AD/etc - RS256-signed
	// tokens verified against keys published at a discovery endpoint,
	// instead of the shared HS256 secret above). jwksURL == "" means this
	// Verifier is in ordinary HS256 mode; see NewJWKSVerifier and
	// jwks.go. issuer is mandatory in this mode (enforced by
	// NewJWKSVerifier) - see its own doc comment for why. userClaim/
	// roleClaim name which of the token's own claims map to
	// DelegatedUser/DelegatedRole, since a real IdP's admin controls what
	// custom claims a token actually carries.
	jwksURL   string
	issuer    string
	audience  string
	userClaim string
	roleClaim string
	keysMu    sync.RWMutex
	keys      map[string]*rsa.PublicKey
}

func NewVerifier(secret string) *Verifier {
	return &Verifier{secret: []byte(secret)}
}

// NewJWKSVerifier is real-IdP mode: tokens are verified against RS256 keys
// fetched from jwksURL (RFC 7517), not a shared secret. issuer is
// mandatory, not optional - without issuer (and, when set, audience)
// validation, a token legitimately issued by the same IdP for a
// *different* application could be replayed against this proxy, a real
// cross-app token confusion risk, not a theoretical one. userClaim/
// roleClaim let a real IdP's own claim names (Auth0's namespaced custom
// claims, Okta's custom authorization-server claims, an Azure AD app's
// optional claims - very unlikely to be named exactly "delegated_user"/
// "delegated_role" out of the box) map onto this proxy's two required
// fields via config rather than code; empty defaults to those same two
// names, so an operator only sets these if their IdP actually differs.
//
// Fetches the JWKS once, synchronously, before returning - an operator
// misconfiguring the URL should find out at startup, not on the first
// real login - then refreshes it in the background every 10 minutes, and
// additionally on-demand whenever a token names a "kid" not in the
// current cache (the same reasoning GET /biscuit-keys's own discovery
// endpoint uses: the IdP rotating its signing key should never require a
// synchronized manual update on this side).
func NewJWKSVerifier(jwksURL, issuer, audience, userClaim, roleClaim string) (*Verifier, error) {
	if issuer == "" {
		return nil, fmt.Errorf("authn: jwt_issuer is required when jwt_jwks_url is set - without it a token issued by the same IdP for a different application could be replayed here")
	}
	if userClaim == "" {
		userClaim = "delegated_user"
	}
	if roleClaim == "" {
		roleClaim = "delegated_role"
	}
	keys, err := fetchJWKS(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("authn: fetch JWKS at %s: %w", jwksURL, err)
	}
	v := &Verifier{jwksURL: jwksURL, issuer: issuer, audience: audience, userClaim: userClaim, roleClaim: roleClaim, keys: keys}
	go v.backgroundRefreshJWKS()
	return v, nil
}

func (v *Verifier) backgroundRefreshJWKS() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if fresh, err := fetchJWKS(v.jwksURL); err == nil {
			v.keysMu.Lock()
			v.keys = fresh
			v.keysMu.Unlock()
		}
		// A failed refresh keeps the existing cached keys rather than
		// wiping them - a transient JWKS endpoint outage must not break
		// verification that was working a moment ago.
	}
}

// lookupJWKSKey returns the cached key for kid, refetching the JWKS
// exactly once first if it's not already cached - see NewJWKSVerifier's
// doc comment for why a cache miss isn't treated as an immediate reject.
func (v *Verifier) lookupJWKSKey(kid string) (*rsa.PublicKey, error) {
	v.keysMu.RLock()
	k, ok := v.keys[kid]
	v.keysMu.RUnlock()
	if ok {
		return k, nil
	}
	fresh, err := fetchJWKS(v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("key id %q not in cache and refetching JWKS failed: %w", kid, err)
	}
	v.keysMu.Lock()
	v.keys = fresh
	v.keysMu.Unlock()
	if k, ok := fresh[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("key id %q not found even after refetching JWKS", kid)
}

// NewOpenVerifier is zero-config mode's verifier (cmd/rinwall's --mcp flag):
// a request arriving with NO Authorization header is treated as the given
// local identity instead of being rejected, so getting started doesn't
// require minting a token first.
//
// The narrowness matters. This makes a MISSING credential succeed; it does
// not make a BAD one succeed. A request that does present a token is
// verified exactly as strictly as ever, and a forged or expired one is
// still rejected rather than quietly falling back to the local identity -
// which would turn this convenience into a trivial authentication bypass.
// Two useful consequences: an operator can hand out real tokens to
// exercise role policy without restarting out of this mode, and approvals
// still require a genuine, distinct identity, so the self-approval check
// stays real.
//
// cmd/rinwall only ever pairs this with a loopback-only listener - see its
// refusal to bind a non-local address in zero-config mode.
func NewOpenVerifier(secret string, fallback Claims) *Verifier {
	return &Verifier{secret: []byte(secret), fallback: &fallback}
}

// IsOpen reports whether a missing credential is accepted, so callers can
// say so in a startup banner rather than leaving it implicit.
func (v *Verifier) IsOpen() bool { return v.fallback != nil }

// Verify checks signature, expiry, and that the required delegated-identity
// claims are present. In ordinary (HS256) mode it deliberately does not
// accept "none" or any asymmetric algorithm switch - only the configured
// HMAC secret. In JWKS mode (see NewJWKSVerifier) it verifies against the
// discovered RS256 keys instead, and additionally enforces issuer (and
// audience, if configured).
func (v *Verifier) Verify(tokenString string) (Claims, error) {
	if v.jwksURL != "" {
		return v.verifyJWKS(tokenString)
	}

	var claims Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return v.secret, nil
	})
	if err != nil {
		return Claims{}, fmt.Errorf("authn: %w", err)
	}
	if !token.Valid {
		return Claims{}, fmt.Errorf("authn: invalid token")
	}
	if claims.DelegatedUser == "" || claims.DelegatedRole == "" {
		return Claims{}, fmt.Errorf("authn: token missing delegated_user/delegated_role claims")
	}
	return claims, nil
}

// verifyJWKS is Verify's real-IdP path: claims are parsed generically
// (jwt.MapClaims), since a real IdP's token carries whatever claim names
// its admin configured, not this project's own struct field names -
// userClaim/roleClaim (see NewJWKSVerifier) name which two of them map to
// DelegatedUser/DelegatedRole.
func (v *Verifier) verifyJWKS(tokenString string) (Claims, error) {
	opts := []jwt.ParserOption{jwt.WithIssuer(v.issuer)}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	var mapClaims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenString, &mapClaims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v - JWKS mode only accepts RS256/RS384/RS512", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token has no kid header - cannot select a verification key")
		}
		return v.lookupJWKSKey(kid)
	}, opts...)
	if err != nil {
		return Claims{}, fmt.Errorf("authn: %w", err)
	}
	if !token.Valid {
		return Claims{}, fmt.Errorf("authn: invalid token")
	}

	user, _ := mapClaims[v.userClaim].(string)
	role, _ := mapClaims[v.roleClaim].(string)
	if user == "" || role == "" {
		return Claims{}, fmt.Errorf("authn: token missing required claims %q/%q", v.userClaim, v.roleClaim)
	}
	return Claims{DelegatedUser: user, DelegatedRole: role}, nil
}

// FromRequest extracts and verifies the bearer token from the standard
// Authorization header - the one place both adapters pull delegated
// identity from.
func (v *Verifier) FromRequest(r *http.Request) (Claims, error) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		// Only an ABSENT credential falls back, and only in open mode. A
		// present-but-invalid one still goes through Verify below and is
		// still rejected - see NewOpenVerifier.
		if v.fallback != nil {
			return *v.fallback, nil
		}
		return Claims{}, fmt.Errorf("authn: missing Authorization: Bearer <token> header")
	}
	return v.Verify(tok)
}

// Mint is used by cmd/devtoken only - a real deployment never mints its own
// identity tokens, an IdP does. Exported so the dev CLI can call it without
// duplicating the claims shape.
func Mint(secret, user, role string, ttl time.Duration) (string, error) {
	claims := Claims{
		DelegatedUser: user,
		DelegatedRole: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
