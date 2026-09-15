// Package outbound enforces security policy for connections initiated by the
// port probing endpoint. Every outbound connection passes through a Guard,
// which applies address and port policy, per-source and per-target rate
// limits (separately for IPv4 and IPv6), global and per-family concurrency
// caps, a bounded dial timeout and connection metrics.
package outbound

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// defaultProbeTimeout is used when Config.Timeout is not set.
const defaultProbeTimeout = 2 * time.Second

// sweepInterval controls how often stale rate-limit buckets are reaped.
const sweepInterval = time.Minute

// idleTTL is how long a fully-refilled bucket must be idle before it is reaped.
const idleTTL = 5 * time.Minute

// Kind classifies why a Guard denied a probe.
type Kind int

const (
	// KindPolicy means that the target address or port is forbidden by
	// policy, or probing for the IP family is disabled.
	KindPolicy Kind = iota
	// KindRate means that a per-source or per-target rate limit was exceeded.
	KindRate
	// KindConcurrency means that the global or per-family concurrency cap
	// was reached.
	KindConcurrency
)

func (k Kind) String() string {
	switch k {
	case KindPolicy:
		return "policy_denied"
	case KindRate:
		return "rate_limited"
	case KindConcurrency:
		return "concurrency_limited"
	default:
		return "unknown"
	}
}

// GuardError describes a probe that was rejected before any connection was
// made. Scope identifies the dimension that rejected the request, e.g.
// "source", "target", "global" or "ipv4".
type GuardError struct {
	Kind   Kind
	Scope  string
	Reason string
}

func (e *GuardError) Error() string {
	return fmt.Sprintf("outbound probe denied (%s/%s): %s", e.Kind, e.Scope, e.Reason)
}

func policyError(scope, reason string, args ...any) *GuardError {
	return &GuardError{Kind: KindPolicy, Scope: scope, Reason: fmt.Sprintf(reason, args...)}
}

func rateError(scope, reason string, args ...any) *GuardError {
	return &GuardError{Kind: KindRate, Scope: scope, Reason: fmt.Sprintf(reason, args...)}
}

func concurrencyError(scope string) *GuardError {
	return &GuardError{Kind: KindConcurrency, Scope: scope, Reason: "concurrency limit reached"}
}

// PortRange is an inclusive range of TCP ports.
type PortRange struct {
	Start uint16
	End   uint16
}

// PortPolicy restricts which TCP ports may be probed. A zero-value policy
// permits every valid port.
type PortPolicy struct {
	Ports  map[uint16]bool
	Ranges []PortRange
}

// Allows reports whether port is permitted by the policy.
func (p PortPolicy) Allows(port uint64) bool {
	if len(p.Ports) == 0 && len(p.Ranges) == 0 {
		return true
	}
	if p.Ports[uint16(port)] {
		return true
	}
	for _, r := range p.Ranges {
		if port >= uint64(r.Start) && port <= uint64(r.End) {
			return true
		}
	}
	return false
}

// ParsePortSpec parses a comma-separated list of individual ports and
// inclusive port ranges, e.g. "80,443,8000-9000". An empty string produces a
// policy that permits all ports.
func ParsePortSpec(spec string) (PortPolicy, error) {
	policy := PortPolicy{Ports: map[uint16]bool{}}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		start, end, found := strings.Cut(item, "-")
		if !found {
			port, err := parsePort(start)
			if err != nil {
				return PortPolicy{}, err
			}
			policy.Ports[port] = true
			continue
		}
		lo, err := parsePort(start)
		if err != nil {
			return PortPolicy{}, err
		}
		hi, err := parsePort(end)
		if err != nil {
			return PortPolicy{}, err
		}
		if lo > hi {
			return PortPolicy{}, fmt.Errorf("invalid port range %s: start greater than end", item)
		}
		policy.Ranges = append(policy.Ranges, PortRange{Start: lo, End: hi})
	}
	if len(policy.Ports) == 0 && len(policy.Ranges) == 0 {
		return PortPolicy{}, nil
	}
	return policy, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port: %s", s)
	}
	return uint16(n), nil
}

// Config holds the outbound security policy for port probes. Zero-valued
// numeric limits mean "unlimited". Use DefaultConfig to get safe defaults.
type Config struct {
	// Timeout bounds the duration of a single outbound TCP connection.
	Timeout time.Duration

	// MaxConcurrent caps globally simultaneous outbound probes. The V4/V6
	// variants cap probes per address family; all three may be combined.
	MaxConcurrent   int
	MaxConcurrentV4 int
	MaxConcurrentV6 int

	// AllowIPv4 and AllowIPv6 toggle probing for each address family.
	AllowIPv4 bool
	AllowIPv6 bool

	// SourceRate* and TargetRate* limit probes per source and per target
	// address, independently for each address family.
	SourceRateV4 RateLimit
	SourceRateV6 RateLimit
	TargetRateV4 RateLimit
	TargetRateV6 RateLimit

	// Ports restricts the set of probe target ports.
	Ports PortPolicy

	// Address classes blocked by default.
	BlockRFC1918   bool
	BlockLinkLocal bool
	BlockLoopback  bool
	BlockMetadata  bool

	// BlockedNetworks holds operator-defined additional blocked networks.
	BlockedNetworks []*net.IPNet

	// DenyReverseLookup disables reverse DNS (PTR) lookups, even when they
	// are otherwise enabled.
	DenyReverseLookup bool
}

// DefaultConfig returns a configuration with sensitive address classes
// blocked (RFC1918, link-local, loopback and cloud metadata addresses), both
// address families allowed and the historical 2-second probe timeout. All
// rate and concurrency limits are disabled until explicitly configured.
func DefaultConfig() Config {
	return Config{
		Timeout:        defaultProbeTimeout,
		AllowIPv4:      true,
		AllowIPv6:      true,
		BlockRFC1918:   true,
		BlockLinkLocal: true,
		BlockLoopback:  true,
		BlockMetadata:  true,
	}
}

// DialFunc establishes a TCP connection to ip:port, bounded by timeout. The
// returned error is the raw dial error so callers can classify it.
type DialFunc func(ip net.IP, port uint64, timeout time.Duration) error

// defaultDial performs the actual outbound TCP connection.
func defaultDial(ip net.IP, port uint64, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10))
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return err
	}
	return conn.Close()
}

type family int

const (
	ipv4 family = iota
	ipv6
)

func familyOf(ip net.IP) family {
	if ip.To4() != nil {
		return ipv4
	}
	return ipv6
}

func (f family) String() string {
	if f == ipv4 {
		return "ipv4"
	}
	return "ipv6"
}

// familyCounters holds atomically-updated metrics for one address family.
type familyCounters struct {
	attempts           atomic.Int64
	succeeded          atomic.Int64
	failed             atomic.Int64
	blockedPolicy      atomic.Int64
	rateLimited        atomic.Int64
	concurrencyLimited atomic.Int64
	inFlight           atomic.Int64
}

// FamilyStats is a point-in-time metrics snapshot for one family.
type FamilyStats struct {
	Attempts           int64   `json:"attempts_total"`
	Succeeded          int64   `json:"succeeded_total"`
	Failed             int64   `json:"failed_total"`
	Blocked            int64   `json:"blocked_total"`
	RateLimited        int64   `json:"rate_limited_total"`
	ConcurrencyLimited int64   `json:"concurrency_limited_total"`
	InFlight           int64   `json:"in_flight"`
	FailureRate        float64 `json:"failure_rate"`
}

// Stats is a point-in-time snapshot of outbound probe metrics.
type Stats struct {
	Attempts           int64       `json:"attempts_total"`
	Succeeded          int64       `json:"succeeded_total"`
	Failed             int64       `json:"failed_total"`
	Blocked            int64       `json:"blocked_total"`
	RateLimited        int64       `json:"rate_limited_total"`
	ConcurrencyLimited int64       `json:"concurrency_limited_total"`
	InFlight           int64       `json:"in_flight"`
	FailureRate        float64     `json:"failure_rate"`
	IPv4               FamilyStats `json:"ipv4"`
	IPv6               FamilyStats `json:"ipv6"`
}

// Guard enforces Config for outbound probes.
type Guard struct {
	cfg  Config
	dial DialFunc

	counters [2]*familyCounters

	// Concurrency semaphores. A nil channel means unlimited.
	globalSem chan struct{}
	familySem [2]chan struct{}

	sourceLimits [2]*keyedLimiter
	targetLimits [2]*keyedLimiter

	blockedV4 []*net.IPNet
	blockedV6 []*net.IPNet

	stop chan struct{}
	done chan struct{}
}

// NewGuard validates cfg and builds a Guard. If dial is nil, a real TCP
// dialer is used. The returned Guard must be closed with Close when it is no
// longer needed.
func NewGuard(cfg Config, dial DialFunc) (*Guard, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if dial == nil {
		dial = defaultDial
	}
	g := &Guard{
		cfg:       cfg,
		dial:      dial,
		globalSem: makeSem(cfg.MaxConcurrent),
		familySem: [2]chan struct{}{makeSem(cfg.MaxConcurrentV4), makeSem(cfg.MaxConcurrentV6)},
		sourceLimits: [2]*keyedLimiter{
			newKeyedLimiter(normalizeBurst(cfg.SourceRateV4)),
			newKeyedLimiter(normalizeBurst(cfg.SourceRateV6)),
		},
		targetLimits: [2]*keyedLimiter{
			newKeyedLimiter(normalizeBurst(cfg.TargetRateV4)),
			newKeyedLimiter(normalizeBurst(cfg.TargetRateV6)),
		},
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	for i := family(0); i <= ipv6; i++ {
		g.counters[i] = &familyCounters{}
	}
	g.blockedV4, g.blockedV6 = g.compileBlockedNetworks()
	go g.janitor()
	return g, nil
}

func (c *Config) validate() error {
	if c.Timeout < 0 {
		return errors.New("probe timeout must be non-negative")
	}
	negatives := map[string]int{
		"max concurrent":      c.MaxConcurrent,
		"max concurrent ipv4": c.MaxConcurrentV4,
		"max concurrent ipv6": c.MaxConcurrentV6,
	}
	for name, value := range negatives {
		if value < 0 {
			return fmt.Errorf("%s must be non-negative", name)
		}
	}
	for name, rl := range map[string]RateLimit{
		"source rate ipv4": c.SourceRateV4,
		"source rate ipv6": c.SourceRateV6,
		"target rate ipv4": c.TargetRateV4,
		"target rate ipv6": c.TargetRateV6,
	} {
		if rl.Rate < 0 || rl.Burst < 0 {
			return fmt.Errorf("%s must be non-negative", name)
		}
	}
	return nil
}

func normalizeBurst(rl RateLimit) RateLimit {
	if rl.Rate > 0 && rl.Burst <= 0 {
		// Default to a one-second burst, but at least one token.
		if rl.Rate < 1 {
			rl.Burst = 1
		} else {
			rl.Burst = rl.Rate
		}
	}
	return rl
}

func makeSem(size int) chan struct{} {
	if size <= 0 {
		return nil
	}
	return make(chan struct{}, size)
}

func acquire(sem chan struct{}) bool {
	if sem == nil {
		return true
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(sem chan struct{}) {
	if sem == nil {
		return
	}
	<-sem
}

// rfc1918Networks are the address ranges reserved for private networks by
// RFC 1918.
var rfc1918Networks = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// metadataNetworks are well-known cloud instance metadata service addresses
// that must never be reachable from a user-controlled probe.
var metadataNetworks = []string{
	"169.254.169.254/32", // AWS / GCP / Azure / OpenStack
	"fd00:ec2::254/128",  // AWS IMDS over IPv6
	"100.100.100.200/32", // Alibaba Cloud
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return network
}

func (g *Guard) compileBlockedNetworks() (v4, v6 []*net.IPNet) {
	if g.cfg.BlockRFC1918 {
		for _, s := range rfc1918Networks {
			v4 = append(v4, mustParseCIDR(s))
		}
	}
	for _, network := range g.cfg.BlockedNetworks {
		if familyOf(network.IP) == ipv4 {
			v4 = append(v4, network)
		} else {
			v6 = append(v6, network)
		}
	}
	return v4, v6
}

var metadataCIDRs = func() []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(metadataNetworks))
	for _, s := range metadataNetworks {
		networks = append(networks, mustParseCIDR(s))
	}
	return networks
}()

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// checkAddress enforces family toggles and blocked address classes.
func (g *Guard) checkAddress(ip net.IP) *GuardError {
	f := familyOf(ip)
	if f == ipv4 && !g.cfg.AllowIPv4 {
		return policyError(f.String(), "IPv4 probes are disabled")
	}
	if f == ipv6 && !g.cfg.AllowIPv6 {
		return policyError(f.String(), "IPv6 probes are disabled")
	}
	if g.cfg.BlockLoopback && ip.IsLoopback() {
		return policyError(f.String(), "loopback address blocked: %s", ip)
	}
	if g.cfg.BlockMetadata && containsIP(metadataCIDRs, ip) {
		return policyError(f.String(), "cloud metadata address blocked: %s", ip)
	}
	if g.cfg.BlockLinkLocal && ip.IsLinkLocalUnicast() {
		return policyError(f.String(), "link-local address blocked: %s", ip)
	}
	blocked := g.blockedV4
	if f == ipv6 {
		blocked = g.blockedV6
	}
	if containsIP(blocked, ip) {
		return policyError(f.String(), "address in blocked network: %s", ip)
	}
	return nil
}

func (g *Guard) janitor() {
	defer close(g.done)
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case now := <-ticker.C:
			for _, limiters := range [][2]*keyedLimiter{g.sourceLimits, g.targetLimits} {
				for _, l := range limiters {
					l.sweep(now, idleTTL)
				}
			}
		}
	}
}

// Close stops background maintenance of the Guard.
func (g *Guard) Close() error {
	close(g.stop)
	<-g.done
	return nil
}

// Probe applies the full outbound security policy and, when permitted,
// dials dst:port. src is the address of the request initiator and is only
// used for per-source rate limiting. Raw dial errors are returned to the
// caller; policy rejections are returned as *GuardError.
func (g *Guard) Probe(src, dst net.IP, port uint64) error {
	f := familyOf(dst)
	counters := g.counters[f]

	if err := g.checkAddress(dst); err != nil {
		counters.blockedPolicy.Add(1)
		return err
	}
	if !g.cfg.Ports.Allows(port) {
		counters.blockedPolicy.Add(1)
		return policyError("port", "port not in allowed port list: %d", port)
	}

	srcFamily := familyOf(src)
	if !g.sourceLimits[srcFamily].allow(src.String(), timeNow()) {
		counters.rateLimited.Add(1)
		return rateError("source", "rate limit exceeded for source %s", src)
	}
	if !g.targetLimits[f].allow(dst.String(), timeNow()) {
		counters.rateLimited.Add(1)
		return rateError("target", "rate limit exceeded for target %s", dst)
	}

	if !acquire(g.globalSem) {
		counters.concurrencyLimited.Add(1)
		return concurrencyError("global")
	}
	defer release(g.globalSem)
	if !acquire(g.familySem[f]) {
		counters.concurrencyLimited.Add(1)
		return concurrencyError(f.String())
	}
	defer release(g.familySem[f])

	counters.attempts.Add(1)
	counters.inFlight.Add(1)
	defer counters.inFlight.Add(-1)

	timeout := g.cfg.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	if err := g.dial(dst, port, timeout); err != nil {
		counters.failed.Add(1)
		return err
	}
	counters.succeeded.Add(1)
	return nil
}

// timeNow is indirected so tests can control time.
var timeNow = time.Now

func familySnapshot(c *familyCounters) FamilyStats {
	succeeded := c.succeeded.Load()
	failed := c.failed.Load()
	completed := succeeded + failed
	var failureRate float64
	if completed > 0 {
		failureRate = float64(failed) / float64(completed)
	}
	return FamilyStats{
		Attempts:           c.attempts.Load(),
		Succeeded:          succeeded,
		Failed:             failed,
		Blocked:            c.blockedPolicy.Load(),
		RateLimited:        c.rateLimited.Load(),
		ConcurrencyLimited: c.concurrencyLimited.Load(),
		InFlight:           c.inFlight.Load(),
		FailureRate:        failureRate,
	}
}

// Stats returns a point-in-time snapshot of probe metrics, including totals
// across address families and the failure rate of completed connections.
func (g *Guard) Stats() Stats {
	v4 := familySnapshot(g.counters[ipv4])
	v6 := familySnapshot(g.counters[ipv6])
	stats := Stats{IPv4: v4, IPv6: v6}
	stats.Attempts = v4.Attempts + v6.Attempts
	stats.Succeeded = v4.Succeeded + v6.Succeeded
	stats.Failed = v4.Failed + v6.Failed
	stats.Blocked = v4.Blocked + v6.Blocked
	stats.RateLimited = v4.RateLimited + v6.RateLimited
	stats.ConcurrencyLimited = v4.ConcurrencyLimited + v6.ConcurrencyLimited
	stats.InFlight = v4.InFlight + v6.InFlight
	completed := stats.Succeeded + stats.Failed
	if completed > 0 {
		stats.FailureRate = float64(stats.Failed) / float64(completed)
	}
	return stats
}
