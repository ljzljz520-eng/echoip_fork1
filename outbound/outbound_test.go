package outbound

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeDial records invocations and can block or fail on demand.
type fakeDial struct {
	mu       sync.Mutex
	calls    int
	gotIP    net.IP
	gotPort  uint64
	gotDelay time.Duration
	err      error
	entered  chan struct{}
	release  chan struct{}
}

func newFakeDial() *fakeDial {
	return &fakeDial{entered: make(chan struct{}, 16)}
}

func (f *fakeDial) dial(ip net.IP, port uint64, timeout time.Duration) error {
	f.mu.Lock()
	f.calls++
	f.gotIP = ip
	f.gotPort = port
	f.gotDelay = timeout
	err := f.err
	f.mu.Unlock()
	f.entered <- struct{}{}
	if f.release != nil {
		<-f.release
	}
	return err
}

func newTestGuard(t *testing.T, cfg Config, dial DialFunc) *Guard {
	t.Helper()
	if dial == nil {
		dial = newFakeDial().dial
	}
	g, err := NewGuard(cfg, dial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g
}

func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP: %s", s)
	}
	return ip
}

func deniedError(err error) *GuardError {
	var ge *GuardError
	if errors.As(err, &ge) {
		return ge
	}
	return nil
}

func TestParsePortSpec(t *testing.T) {
	var tests = []struct {
		spec    string
		port    uint64
		allowed bool
	}{
		{"", 1, true},
		{"", 65535, true},
		{"80,443", 80, true},
		{"80,443", 443, true},
		{"80,443", 8080, false},
		{"8000-9000", 8000, true},
		{"8000-9000", 9000, true},
		{"8000-9000", 7999, false},
		{"8000-9000", 9001, false},
		{"80, 443 , 8000 - 9000", 443, true},
		{"80, 443 , 8000 - 9000", 8500, true},
	}
	for _, tt := range tests {
		policy, err := ParsePortSpec(tt.spec)
		if err != nil {
			t.Fatalf("ParsePortSpec(%q): %v", tt.spec, err)
		}
		if got := policy.Allows(tt.port); got != tt.allowed {
			t.Errorf("Allows(%d) with spec %q = %v, want %v", tt.port, tt.spec, got, tt.allowed)
		}
	}

	for _, spec := range []string{"0", "65536", "abc", "100-90", "1-", "-80"} {
		if _, err := ParsePortSpec(spec); err == nil {
			t.Errorf("expected error parsing %q", spec)
		}
	}
}

func TestDefaultAddressPolicy(t *testing.T) {
	cfg := DefaultConfig()
	var blocked = []string{
		"10.0.0.1",        // RFC1918
		"172.16.5.5",      // RFC1918
		"172.31.255.255",  // RFC1918 edge
		"192.168.1.1",     // RFC1918
		"127.0.0.1",       // loopback
		"127.255.255.255", // loopback range
		"169.254.0.1",     // link-local
		"169.254.169.254", // cloud metadata
		"100.100.100.200", // Alibaba metadata
		"::1",             // IPv6 loopback
		"fe80::1",         // IPv6 link-local
		"fd00:ec2::254",   // AWS IMDS over IPv6
	}
	var allowed = []string{
		"8.8.8.8",
		"172.32.0.1", // just outside RFC1918
		"203.0.113.7",
		"2606:4700:4700::1111",
		"fc00::1", // IPv6 ULA is not in the default block list
	}
	for _, s := range blocked {
		fd := newFakeDial()
		g := newTestGuard(t, cfg, fd.dial)
		ip := parseIP(t, s)
		err := g.Probe(ip, ip, 80)
		ge := deniedError(err)
		if ge == nil || ge.Kind != KindPolicy {
			t.Errorf("expected policy denial for %s, got %v", s, err)
		}
		if fd.calls != 0 {
			t.Errorf("dial should not be attempted for blocked %s", s)
		}
	}
	for _, s := range allowed {
		fd := newFakeDial()
		g := newTestGuard(t, cfg, fd.dial)
		ip := parseIP(t, s)
		if err := g.Probe(ip, ip, 80); err != nil {
			t.Errorf("expected %s to be allowed, got %v", s, err)
		}
		if fd.calls != 1 {
			t.Errorf("expected one dial for %s, got %d", s, fd.calls)
		}
	}
}

func TestAddressPolicyToggles(t *testing.T) {
	var tests = []struct {
		name     string
		mutate   func(*Config)
		probe    string
		wantKind Kind
	}{
		{"rfc1918 disabled", func(c *Config) { c.BlockRFC1918 = false }, "10.0.0.1", -1},
		{"loopback disabled", func(c *Config) { c.BlockLoopback = false }, "127.0.0.1", -1},
		{"link-local disabled, metadata still blocked",
			func(c *Config) { c.BlockLinkLocal = false }, "169.254.169.254", KindPolicy},
		{"link-local disabled, other link-local allowed",
			func(c *Config) { c.BlockLinkLocal = false }, "169.254.10.10", -1},
		{"metadata disabled, ipv6 metadata allowed",
			func(c *Config) { c.BlockMetadata = false }, "fd00:ec2::254", -1},
		{"ipv4 disabled", func(c *Config) { c.AllowIPv4 = false }, "8.8.8.8", KindPolicy},
		{"ipv6 disabled", func(c *Config) { c.AllowIPv6 = false }, "2606:4700:4700::1111", KindPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(&cfg)
			fd := newFakeDial()
			g := newTestGuard(t, cfg, fd.dial)
			ip := parseIP(t, tt.probe)
			err := g.Probe(ip, ip, 80)
			if tt.wantKind < 0 {
				if err != nil {
					t.Fatalf("expected probe allowed, got %v", err)
				}
				return
			}
			ge := deniedError(err)
			if ge == nil || ge.Kind != tt.wantKind {
				t.Fatalf("expected %v, got %v", tt.wantKind, err)
			}
		})
	}
}

func TestCustomBlockedNetwork(t *testing.T) {
	cfg := DefaultConfig()
	_, network, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cfg.BlockedNetworks = []*net.IPNet{network}
	g := newTestGuard(t, cfg, nil)
	if err := g.Probe(parseIP(t, "203.0.113.50"), parseIP(t, "203.0.113.50"), 80); err == nil {
		t.Error("expected address in custom network to be blocked")
	}
	if err := g.Probe(parseIP(t, "203.0.114.1"), parseIP(t, "203.0.114.1"), 80); err != nil {
		t.Errorf("expected address outside custom network to be allowed, got %v", err)
	}
}

func TestPortPolicyEnforced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ports, _ = ParsePortSpec("80,443,8000-8009")
	fd := newFakeDial()
	g := newTestGuard(t, cfg, fd.dial)
	target := parseIP(t, "203.0.113.7")

	var cases = []struct {
		port    uint64
		allowed bool
	}{
		{80, true}, {443, true}, {8000, true}, {8009, true},
		{444, false}, {7999, false}, {8010, false},
	}
	for _, tt := range cases {
		err := g.Probe(target, target, tt.port)
		ge := deniedError(err)
		switch {
		case tt.allowed && err != nil:
			t.Errorf("port %d: expected allowed, got %v", tt.port, err)
		case !tt.allowed && (ge == nil || ge.Scope != "port"):
			t.Errorf("port %d: expected port denial, got %v", tt.port, err)
		}
	}
	if fd.calls != 4 {
		t.Errorf("expected 4 dial attempts, got %d", fd.calls)
	}
}

func TestSourceRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SourceRateV4 = RateLimit{Rate: 10, Burst: 1}

	clock := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	oldNow := timeNow
	timeNow = func() time.Time { return clock }
	defer func() { timeNow = oldNow }()

	fd := newFakeDial()
	g := newTestGuard(t, cfg, fd.dial)
	source := parseIP(t, "198.51.100.1")
	target := parseIP(t, "203.0.113.10")

	if err := g.Probe(source, target, 80); err != nil {
		t.Fatal(err)
	}
	err := g.Probe(source, target, 80)
	ge := deniedError(err)
	if ge == nil || ge.Kind != KindRate || ge.Scope != "source" {
		t.Fatalf("expected source rate limit, got %v", err)
	}
	// After enough time passes for a refill, the probe is allowed again.
	clock = clock.Add(110 * time.Millisecond)
	if err := g.Probe(source, target, 80); err != nil {
		t.Fatalf("expected refilled probe allowed, got %v", err)
	}
}

func TestTargetRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetRateV4 = RateLimit{Rate: 10, Burst: 1}
	fd := newFakeDial()
	g := newTestGuard(t, cfg, fd.dial)
	target := parseIP(t, "203.0.113.10")

	if err := g.Probe(parseIP(t, "198.51.100.1"), target, 80); err != nil {
		t.Fatal(err)
	}
	err := g.Probe(parseIP(t, "198.51.100.2"), target, 80)
	ge := deniedError(err)
	if ge == nil || ge.Kind != KindRate || ge.Scope != "target" {
		t.Fatalf("expected target rate limit from distinct sources, got %v", err)
	}
}

func TestRateLimitsPerFamily(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SourceRateV4 = RateLimit{Rate: 1, Burst: 1}
	// IPv6 source rate limiting stays disabled.
	g := newTestGuard(t, cfg, nil)

	v4 := parseIP(t, "198.51.100.1")
	v6 := parseIP(t, "2001:db8::1")
	if err := g.Probe(v4, v4, 80); err != nil {
		t.Fatal(err)
	}
	if ge := deniedError(g.Probe(v4, v4, 80)); ge == nil || ge.Kind != KindRate {
		t.Fatal("expected IPv4 source rate limit")
	}
	for i := 0; i < 5; i++ {
		if err := g.Probe(v6, v6, 80); err != nil {
			t.Fatalf("IPv6 probes should be unlimited, attempt %d: %v", i, err)
		}
	}
}

func TestGlobalConcurrencyLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 1
	fd := newFakeDial()
	fd.release = make(chan struct{})
	defer close(fd.release)
	g := newTestGuard(t, cfg, fd.dial)

	go func() {
		_ = g.Probe(parseIP(t, "203.0.113.1"), parseIP(t, "203.0.113.1"), 80)
	}()
	<-fd.entered

	err := g.Probe(parseIP(t, "203.0.113.2"), parseIP(t, "203.0.113.2"), 80)
	ge := deniedError(err)
	if ge == nil || ge.Kind != KindConcurrency || ge.Scope != "global" {
		t.Fatalf("expected global concurrency limit, got %v", err)
	}
}

func TestFamilyConcurrencyLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentV4 = 1
	v4Entered := make(chan struct{}, 1)
	release := make(chan struct{})
	// Only the in-flight IPv4 probe blocks; IPv6 dials complete immediately
	// so their independent concurrency pool can be exercised.
	dial := func(ip net.IP, port uint64, timeout time.Duration) error {
		if ip.To4() != nil {
			v4Entered <- struct{}{}
			<-release
		}
		return nil
	}
	g := newTestGuard(t, cfg, dial)
	defer close(release)

	go func() {
		_ = g.Probe(parseIP(t, "203.0.113.1"), parseIP(t, "203.0.113.1"), 80)
	}()
	<-v4Entered

	// The IPv4 family is saturated.
	err := g.Probe(parseIP(t, "203.0.113.2"), parseIP(t, "203.0.113.2"), 80)
	ge := deniedError(err)
	if ge == nil || ge.Scope != "ipv4" {
		t.Fatalf("expected ipv4 concurrency limit, got %v", err)
	}
	// IPv6 has its own independent concurrency pool.
	if err := g.Probe(parseIP(t, "2001:db8::2"), parseIP(t, "2001:db8::2"), 80); err != nil {
		t.Fatalf("IPv6 probe should not share the IPv4 concurrency cap: %v", err)
	}
}

func TestProbeTimeoutConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 42 * time.Millisecond
	fd := newFakeDial()
	g := newTestGuard(t, cfg, fd.dial)
	target := parseIP(t, "203.0.113.7")
	if err := g.Probe(target, target, 22); err != nil {
		t.Fatal(err)
	}
	if fd.gotDelay != 42*time.Millisecond {
		t.Errorf("expected 42ms dial timeout, got %s", fd.gotDelay)
	}
	if fd.gotPort != 22 || !fd.gotIP.Equal(target) {
		t.Errorf("dial invoked with %s:%d, want %s:22", fd.gotIP, fd.gotPort, target)
	}
}

func TestDefaultTimeoutWhenUnset(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 0
	fd := newFakeDial()
	g := newTestGuard(t, cfg, fd.dial)
	if err := g.Probe(parseIP(t, "203.0.113.7"), parseIP(t, "203.0.113.7"), 80); err != nil {
		t.Fatal(err)
	}
	if fd.gotDelay != defaultProbeTimeout {
		t.Errorf("expected default timeout %s, got %s", defaultProbeTimeout, fd.gotDelay)
	}
}

func TestMetrics(t *testing.T) {
	cfg := DefaultConfig()
	var failTarget uint64 = 1
	dial := func(ip net.IP, port uint64, timeout time.Duration) error {
		if port == failTarget {
			return errors.New("connection refused")
		}
		return nil
	}
	g := newTestGuard(t, cfg, dial)

	v4 := parseIP(t, "203.0.113.7")
	v6 := parseIP(t, "2001:db8::7")
	_ = g.Probe(v4, v4, 80)
	_ = g.Probe(v4, v4, 1)
	_ = g.Probe(v6, v6, 80)
	// Policy denial is counted separately.
	_ = g.Probe(parseIP(t, "10.0.0.1"), parseIP(t, "10.0.0.1"), 80)

	stats := g.Stats()
	if stats.Attempts != 3 || stats.Succeeded != 2 || stats.Failed != 1 {
		t.Errorf("unexpected totals: %+v", stats)
	}
	if stats.Blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.Blocked)
	}
	if stats.InFlight != 0 {
		t.Errorf("expected no in-flight probes, got %d", stats.InFlight)
	}
	if stats.FailureRate != 1.0/3.0 {
		t.Errorf("expected failure rate %.3f, got %.3f", 1.0/3.0, stats.FailureRate)
	}
	if stats.IPv4.Attempts != 2 || stats.IPv4.Failed != 1 || stats.IPv6.Succeeded != 1 {
		t.Errorf("unexpected per-family stats: v4=%+v v6=%+v", stats.IPv4, stats.IPv6)
	}
	if stats.IPv4.Blocked != 1 {
		t.Errorf("expected IPv4 block counted in family stats, got %d", stats.IPv4.Blocked)
	}
}

func TestInvalidConfig(t *testing.T) {
	var bad = []Config{
		{Timeout: -1},
		{MaxConcurrent: -2},
		{SourceRateV4: RateLimit{Rate: -1}},
		{TargetRateV6: RateLimit{Rate: 1, Burst: -1}},
	}
	for i, cfg := range bad {
		if _, err := NewGuard(cfg, nil); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}
