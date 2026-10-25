// Circuit breakers:
// semantic loop detection (the same call repeated past a threshold in a
// short window - a hallucinating or looping agent retrying the same
// mutation) and per-session rate limiting (a blunt cap on how fast one
// session can drive tool calls at all). Both are cheap, in-memory, and
// session-scoped - not a replacement for the policy engine, an additional
// backstop against runaway agent behavior policy alone wouldn't catch.
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

const (
	loopWindow    = 30 * time.Second
	loopThreshold = 3 // same (tool, args) more than this many times inside the window trips the breaker

	rateLimitTokens  = 20.0
	rateRefillPerSec = rateLimitTokens / 60.0 // 20 calls/minute steady-state
)

type loopGuard struct {
	mu      sync.Mutex
	history map[string][]time.Time
}

func newLoopGuard() *loopGuard {
	return &loopGuard{history: make(map[string][]time.Time)}
}

// tooManyRepeats records this call and reports whether the same
// (sessionKey, tool, args) combination has now recurred past loopThreshold
// within loopWindow.
func (g *loopGuard) tooManyRepeats(sessionKey, tool string, args map[string]any) bool {
	key := sessionKey + "|" + callHash(tool, args)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	var recent []time.Time
	for _, t := range g.history[key] {
		if now.Sub(t) < loopWindow {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	g.history[key] = recent

	return len(recent) > loopThreshold
}

func callHash(tool string, args map[string]any) string {
	b, _ := json.Marshal(args) // sorted keys, deterministic
	sum := sha256.Sum256([]byte(tool + "|" + string(b)))
	return hex.EncodeToString(sum[:])
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket)}
}

// Allow reports whether sessionKey has budget left, spending one token if so.
func (r *rateLimiter) Allow(sessionKey string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	b, ok := r.buckets[sessionKey]
	if !ok {
		r.buckets[sessionKey] = &bucket{tokens: rateLimitTokens - 1, lastRefill: now}
		return true
	}

	b.tokens += now.Sub(b.lastRefill).Seconds() * rateRefillPerSec
	if b.tokens > rateLimitTokens {
		b.tokens = rateLimitTokens
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
