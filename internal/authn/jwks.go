// JWKS (RFC 7517) fetch/parse for real-IdP mode (Verifier.jwksURL set via
// NewJWKSVerifier). Hand-rolled against the stdlib rather than a third-
// party JWKS library, deliberately - this project already has an
// established pattern for exactly this shape of problem (fetch a set of
// public signing keys from a discovery endpoint, cache by id, refresh on
// demand) hand-rolled against stdlib crypto in
// internal/capability/keyring.go for the biscuit signing key, and the
// actual parsing needed here (base64url-decode an RSA modulus/exponent
// into a crypto/rsa.PublicKey) is small enough that pulling in a
// dependency for it isn't worth it on a security-critical verification
// path. RSA only (RS256/384/512) for now - what every major enterprise
// IdP (Okta, Auth0, Azure AD, Google) issues by default; an EC key in the
// document is skipped, not silently mistaken for something it isn't.
package authn

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"` // base64url-encoded RSA modulus
	E   string `json:"e"` // base64url-encoded RSA public exponent
}

// fetchJWKS retrieves and parses the JWKS document at url, returning every
// usable RSA key keyed by its "kid". A key with an unrecognized "kty"
// (e.g. an EC key mixed into the same document) or a missing "kid" is
// skipped, not an error - a JWKS document legitimately mixes key types
// and purposes; only ending up with zero usable keys is treated as
// failure.
func fetchJWKS(url string) (map[string]*rsa.PublicKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: unexpected status %d", url, resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode JWKS from %s: %w", url, err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			continue // malformed entry - skip it rather than failing the whole fetch over one bad key
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable RSA keys found in JWKS at %s", url)
	}
	return keys, nil
}

func rsaPublicKeyFromJWK(nb64, eb64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nb64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eb64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, fmt.Errorf("empty modulus or exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
