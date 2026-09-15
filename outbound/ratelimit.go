package outbound

import (
	"math"
	"sync"
	"time"
)

// RateLimit configures a token-bucket rate limit. Rate is the number of
// permitted requests per second and Burst is the maximum bucket size. A Rate
// of zero disables limiting.
type RateLimit struct {
	Rate  float64
	Burst float64
}

// tokenBucket implements a simple refilling token bucket. It is not safe for
// concurrent use; callers must hold the owning keyedLimiter lock.
type tokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func (b *tokenBucket) allow(now time.Time) bool {
	if b.rate <= 0 {
		return true
	}
	if b.last.IsZero() {
		b.last = now
		b.tokens = b.burst
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = math.Min(b.burst, b.tokens+elapsed*b.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// keyedLimiter maintains one token bucket per key (e.g. a source or target IP
// address). Buckets that have been idle for longer than idleTTL and have
// refilled to capacity are removed by sweep, preventing unbounded memory
// growth for clients that never return.
type keyedLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*tokenBucket
}

func newKeyedLimiter(rl RateLimit) *keyedLimiter {
	return &keyedLimiter{
		rate:    rl.Rate,
		burst:   rl.Burst,
		buckets: make(map[string]*tokenBucket),
	}
}

// allow reports whether a request for key is permitted at time now.
func (l *keyedLimiter) allow(key string, now time.Time) bool {
	if l.rate <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{rate: l.rate, burst: l.burst}
		l.buckets[key] = b
	}
	return b.allow(now)
}

// sweep removes buckets that have been idle for at least idleTTL and would
// have refilled to capacity, i.e. future traffic from the key would not be
// affected by the bucket being recreated.
func (l *keyedLimiter) sweep(now time.Time, idleTTL time.Duration) {
	if l.rate <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		elapsed := now.Sub(b.last)
		if elapsed < idleTTL {
			continue
		}
		if b.tokens+elapsed.Seconds()*b.rate >= b.burst {
			delete(l.buckets, key)
		}
	}
}
