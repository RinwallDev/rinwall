// Package metrics records per-stage durations from internal/handler and
// exposes p50/p95 via cmd/rinwall's /metrics endpoint, so the latency claims
// in docs/REFERENCE.md are numbers rather than assertions. Deliberately not
// Prometheus/OTel yet - an export is on the roadmap; this is the minimum
// needed to measure.
package metrics

import (
	"sort"
	"sync"
	"time"
)

const maxSamplesPerStage = 2000

type Recorder struct {
	mu       sync.Mutex
	samples  map[string][]time.Duration
	counters map[string]int64
}

func New() *Recorder {
	return &Recorder{samples: make(map[string][]time.Duration), counters: make(map[string]int64)}
}

// IncrementCounter tracks a discrete event rather than a duration - e.g.
// "vault_unavailable", so an operator can tell "Vault specifically is
// failing" apart from a generic slow stage in /metrics without having to
// grep logs for it.
func (r *Recorder) IncrementCounter(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[name]++
}

func (r *Recorder) Record(stage string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.samples[stage]
	s = append(s, d)
	if len(s) > maxSamplesPerStage {
		s = s[len(s)-maxSamplesPerStage:] // drop oldest, keep it a rolling window
	}
	r.samples[stage] = s
}

// Timer returns a func to call at the end of a stage: `defer r.Timer("policy")()`.
func (r *Recorder) Timer(stage string) func() {
	start := time.Now()
	return func() { r.Record(stage, time.Since(start)) }
}

type StageStats struct {
	Count int     `json:"count"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	AvgMs float64 `json:"avg_ms"`
	MaxMs float64 `json:"max_ms"`
}

// Snapshot is stages (latency distributions) plus counters (discrete event
// totals) - separate shapes because they answer different questions:
// "how slow" vs. "how often did this specific bad thing happen."
type Snapshot struct {
	Stages   map[string]StageStats `json:"stages"`
	Counters map[string]int64      `json:"counters"`
}

func (r *Recorder) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	stages := make(map[string]StageStats, len(r.samples))
	for stage, durs := range r.samples {
		if len(durs) == 0 {
			continue
		}
		sorted := make([]time.Duration, len(durs))
		copy(sorted, durs)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

		var sum time.Duration
		for _, d := range sorted {
			sum += d
		}
		stages[stage] = StageStats{
			Count: len(sorted),
			P50Ms: toMs(sorted[len(sorted)*50/100]),
			P95Ms: toMs(sorted[min(len(sorted)*95/100, len(sorted)-1)]),
			AvgMs: toMs(sum / time.Duration(len(sorted))),
			MaxMs: toMs(sorted[len(sorted)-1]),
		}
	}

	counters := make(map[string]int64, len(r.counters))
	for name, count := range r.counters {
		counters[name] = count
	}

	return Snapshot{Stages: stages, Counters: counters}
}

func toMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
