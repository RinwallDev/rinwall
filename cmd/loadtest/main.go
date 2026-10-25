// Command loadtest is the concurrent-load + latency benchmark harness. A
// p50/p95 measured one request at a time against a localhost upstream
// says nothing about contention; this drives N concurrent sessions
// (distinct delegated users, each minting its own root capability), each
// firing a burst of real HTTP tool calls at the actual running proxy, with
// real client-observed latency recorded - not simulated, not mocked.
//
// It also exists to answer a second, more honest question than "is the
// proxy fast": how much does the proxy ITSELF add on top of whatever the
// real upstream enterprise API already takes to respond? cmd/mockupstream
// can simulate realistic upstream latency via MOCK_UPSTREAM_LATENCY_MS -
// run this harness once with that unset (0ms, isolates proxy overhead) and
// once with it set to something like 30-50ms (a realistic same-region API
// call), and compare GET /metrics' per-stage breakdown between runs. Proxy
// overhead (validate+policy+capability, excluding upstream_call) should
// stay essentially flat across both - if it doesn't, the proxy is adding
// hidden cost that scales with something it shouldn't.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RinwallDev/rinwall/internal/authn"
)

func main() {
	baseURL := flag.String("base-url", "http://127.0.0.1:8080", "proxy base URL")
	jwtSecret := flag.String("jwt-secret", "dev-jwt-secret-change-me", "must match the running proxy's config.yaml jwt_secret")
	sessions := flag.Int("sessions", 50, "number of concurrent simulated agent sessions (distinct delegated users - each pays its own real Vault root-mint cost once)")
	callsPerSession := flag.Int("calls-per-session", 20, "tool calls per session, sequential within a session (an agent's own calls are sequential; sessions run concurrently with each other)")
	tool := flag.String("tool", "log_event", "tool to call repeatedly - log_event by default, see the vary comment below")
	role := flag.String("role", "support", "delegated role for the minted JWTs")
	userID := flag.String("user-id", "42", "resource argument value passed as user_id, when tool needs one")
	flag.Parse()

	// log_event is the default specifically because its args vary per call
	// (a unique message each time, via the call index) - calling the SAME
	// (tool, args) repeatedly, as a naive loadtest would with get_user,
	// correctly trips internal/handler's semantic loop breaker
	// (loopThreshold=3 within 30s) past the 3rd identical call. That's the
	// breaker doing its job against exactly the shape it's meant to catch,
	// not a bug - but it means it's the wrong tool for measuring realistic
	// steady-state proxy overhead under load. Pass -tool get_user
	// explicitly to deliberately exercise the loop breaker instead.

	// A default http.Client's Transport caps idle connections per host at
	// 2 - under real concurrency that forces most of these sessions to pay
	// a fresh TCP handshake per call instead of reusing a pooled
	// connection, which would inflate measured latency with a client-side
	// artifact that has nothing to do with the proxy. Size the pool to the
	// actual concurrency this run uses.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: *sessions + 1,
			MaxIdleConns:        *sessions + 1,
		},
	}

	// runTag makes each invocation's delegated users unique. Without it,
	// two successive runs against the same long-running proxy reuse the
	// same usernames - and the session capability cache, the per-session
	// rate limiter, and the loop guard are all real in-memory state on
	// that process that persists across invocations, keyed by delegated
	// user. A second run would then see stale rate-limit budgets and
	// cache hits left over from the first, contaminating the very numbers
	// this harness exists to measure. This was caught empirically: a
	// second run with 8 overlapping usernames from a prior run showed
	// unexplained denials traced to exactly this.
	runTag := time.Now().UnixNano()

	var (
		mu        sync.Mutex
		latencies []time.Duration
		httpErrs  int64
		denied    int64
	)

	var wg sync.WaitGroup
	start := time.Now()
	for s := 0; s < *sessions; s++ {
		wg.Add(1)
		user := fmt.Sprintf("loadtest-%d-user-%d@example.com", runTag, s)
		go func(user string) {
			defer wg.Done()
			tok, err := authn.Mint(*jwtSecret, user, *role, time.Hour)
			if err != nil {
				log.Printf("mint error for %s: %v", user, err)
				atomic.AddInt64(&httpErrs, 1)
				return
			}
			for c := 0; c < *callsPerSession; c++ {
				callStart := time.Now()
				status, err := doCall(client, *baseURL, tok, *tool, *userID, user, c)
				elapsed := time.Since(callStart)

				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()

				if err != nil {
					atomic.AddInt64(&httpErrs, 1)
					continue
				}
				if status == "denied" {
					atomic.AddInt64(&denied, 1)
				}
			}
		}(user)
	}
	wg.Wait()
	wallClock := time.Since(start)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	n := len(latencies)
	pct := func(p float64) time.Duration {
		if n == 0 {
			return 0
		}
		idx := int(float64(n) * p)
		if idx >= n {
			idx = n - 1
		}
		return latencies[idx]
	}
	var sum time.Duration
	for _, d := range latencies {
		sum += d
	}

	fmt.Printf("\n=== loadtest result ===\n")
	fmt.Printf("sessions=%d calls_per_session=%d total_calls=%d wall_clock=%v\n", *sessions, *callsPerSession, n, wallClock)
	if n > 0 {
		fmt.Printf("throughput=%.1f calls/sec\n", float64(n)/wallClock.Seconds())
		fmt.Printf("client-observed round-trip latency: p50=%v p95=%v p99=%v avg=%v max=%v\n",
			pct(0.50), pct(0.95), pct(0.99), sum/time.Duration(n), latencies[n-1])
	}
	fmt.Printf("http_errors=%d denied=%d\n", httpErrs, denied)
	fmt.Printf("cross-reference against GET %s/metrics for the per-stage server-side breakdown\n", *baseURL)
}

func doCall(client *http.Client, baseURL, jwt, tool, userID, sessionUser string, callIndex int) (status string, err error) {
	var body string
	switch tool {
	case "log_event":
		body = fmt.Sprintf(`{"tool":"log_event","args":{"message":"loadtest call %d from %s"}}`, callIndex, sessionUser)
	default:
		body = fmt.Sprintf(`{"tool":%q,"args":{"user_id":%q}}`, tool, userID)
	}
	req, err := http.NewRequest("POST", baseURL+"/tool-call", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Status, nil
}
