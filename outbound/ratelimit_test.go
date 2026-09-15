package outbound

import (
	"testing"
	"time"
)

func TestKeyedLimiter(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newKeyedLimiter(RateLimit{Rate: 10, Burst: 1})

	if !l.allow("a", now) {
		t.Fatal("first request within burst should be allowed")
	}
	if l.allow("a", now) {
		t.Fatal("second immediate request should be denied")
	}
	// Different keys have independent buckets.
	if !l.allow("b", now) {
		t.Fatal("first request for another key should be allowed")
	}
	// At 10 req/s a full token takes 100ms to accrue.
	if l.allow("a", now.Add(90*time.Millisecond)) {
		t.Fatal("90ms worth of tokens should not permit a request")
	}
	if !l.allow("a", now.Add(110*time.Millisecond)) {
		t.Fatal("refilled bucket should permit a request")
	}
}

func TestKeyedLimiterDisabled(t *testing.T) {
	now := time.Now()
	l := newKeyedLimiter(RateLimit{})
	for i := 0; i < 1000; i++ {
		if !l.allow("a", now) {
			t.Fatal("zero-rate limiter should allow every request")
		}
	}
	l.sweep(now, time.Minute)
	if len(l.buckets) != 0 {
		t.Fatalf("disabled limiter should not retain buckets, got %d", len(l.buckets))
	}
}

func TestKeyedLimiterSweep(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newKeyedLimiter(RateLimit{Rate: 10, Burst: 1})

	// A key that was allowed once has a full-but-draining bucket.
	if !l.allow("fresh", now) {
		t.Fatal("unexpected denial")
	}
	// A key whose bucket was exhausted.
	if !l.allow("stale", now) {
		t.Fatal("unexpected denial")
	}
	if l.allow("stale", now) {
		t.Fatal("bucket should be exhausted")
	}

	// Nothing is removed before the idle TTL expires.
	l.sweep(now.Add(30*time.Second), time.Minute)
	if len(l.buckets) != 2 {
		t.Fatalf("expected 2 buckets before TTL expiry, got %d", len(l.buckets))
	}
	// After the TTL both buckets would have refilled to capacity and are
	// reaped, including the one that was left empty.
	later := now.Add(idleTTL + time.Second)
	l.sweep(later, idleTTL)
	if len(l.buckets) != 0 {
		t.Fatalf("expected idle buckets to be reaped, got %d", len(l.buckets))
	}
}
