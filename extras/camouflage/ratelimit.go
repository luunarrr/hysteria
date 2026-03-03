package camouflage

import (
	"sync"
	"time"
)

// RateLimiter tracks per-source-IP failure counts and auto-relays
// sources that exceed the threshold. It never blocks -- it only
// transitions a source from "checked" to "auto-relayed".
type RateLimiter struct {
	mu        sync.Mutex
	counters  map[string]*sourceCounter
	threshold int
	window    time.Duration
}

type sourceCounter struct {
	failures  int
	firstSeen time.Time
}

// NewRateLimiter creates a rate limiter with the given failure threshold
// and sliding window duration.
func NewRateLimiter(threshold int, window time.Duration) *RateLimiter {
	if threshold <= 0 {
		threshold = 100
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &RateLimiter{
		counters:  make(map[string]*sourceCounter),
		threshold: threshold,
		window:    window,
	}
}

// RecordFailure increments the failure counter for the given source.
func (r *RateLimiter) RecordFailure(src string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	c, ok := r.counters[src]
	if !ok {
		r.counters[src] = &sourceCounter{failures: 1, firstSeen: now}
		return
	}
	if now.Sub(c.firstSeen) > r.window {
		c.failures = 1
		c.firstSeen = now
		return
	}
	c.failures++
}

// IsRateLimited returns true if the source has exceeded the failure threshold
// within the current window.
func (r *RateLimiter) IsRateLimited(src string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	c, ok := r.counters[src]
	if !ok {
		return false
	}
	if time.Since(c.firstSeen) > r.window {
		delete(r.counters, src)
		return false
	}
	return c.failures >= r.threshold
}

// Cleanup removes expired entries. Call periodically from a background goroutine.
func (r *RateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for src, c := range r.counters {
		if now.Sub(c.firstSeen) > r.window {
			delete(r.counters, src)
		}
	}
}
