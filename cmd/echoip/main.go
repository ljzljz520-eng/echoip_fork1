package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mpolden/echoip/http"
	"github.com/mpolden/echoip/iputil"
	"github.com/mpolden/echoip/iputil/geo"
	"github.com/mpolden/echoip/outbound"
)

type multiValueFlag []string

func (f *multiValueFlag) String() string {
	return strings.Join([]string(*f), ", ")
}

func (f *multiValueFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func init() {
	log.SetPrefix("echoip: ")
	log.SetFlags(log.Lshortfile)
}

func main() {
	countryFile := flag.String("f", "", "Path to GeoIP country database")
	cityFile := flag.String("c", "", "Path to GeoIP city database")
	asnFile := flag.String("a", "", "Path to GeoIP ASN database")
	listen := flag.String("l", ":8080", "Listening address")
	reverseLookup := flag.Bool("r", false, "Perform reverse hostname lookups")
	portLookup := flag.Bool("p", false, "Enable port lookup")
	noCustomIP := flag.Bool("L", false, "Disable custom IP lookup")
	template := flag.String("t", "html", "Path to template dir")
	cacheSize := flag.Int("C", 0, "Size of response cache. Set to 0 to disable")
	profile := flag.Bool("P", false, "Enables profiling handlers")
	sponsor := flag.Bool("s", false, "Show sponsor logo")
	var headers multiValueFlag
	flag.Var(&headers, "H", "Header to trust for remote IP, if present (e.g. X-Real-IP)")

	// Outbound security policy for port probes. See package outbound for
	// details.
	portTimeout := flag.Duration("port-timeout", 2*time.Second, "Timeout for a single port probe TCP connection")
	portMaxConcurrent := flag.Int("port-max-concurrent", 0, "Maximum concurrent outbound port probes, all families (0 = unlimited)")
	portMaxConcurrentV4 := flag.Int("port-max-concurrent-v4", 0, "Maximum concurrent outbound IPv4 port probes (0 = unlimited)")
	portMaxConcurrentV6 := flag.Int("port-max-concurrent-v6", 0, "Maximum concurrent outbound IPv6 port probes (0 = unlimited)")
	portRateSourceV4 := flag.Float64("port-rate-source-v4", 0, "Maximum port probes per second per source IPv4 address (0 = unlimited)")
	portRateSourceV6 := flag.Float64("port-rate-source-v6", 0, "Maximum port probes per second per source IPv6 address (0 = unlimited)")
	portRateTargetV4 := flag.Float64("port-rate-target-v4", 0, "Maximum port probes per second per target IPv4 address (0 = unlimited)")
	portRateTargetV6 := flag.Float64("port-rate-target-v6", 0, "Maximum port probes per second per target IPv6 address (0 = unlimited)")
	portAllow := flag.String("port-allow", "", "Allowed TCP probe ports as comma-separated list of ports and ranges, e.g. 80,443,8000-9000 (default: all ports)")
	portAllowV4 := flag.Bool("port-allow-ipv4", true, "Allow port probes to IPv4 targets")
	portAllowV6 := flag.Bool("port-allow-ipv6", true, "Allow port probes to IPv6 targets")
	portBlockRFC1918 := flag.Bool("port-block-rfc1918", true, "Block port probes to RFC1918 private IPv4 addresses")
	portBlockLinkLocal := flag.Bool("port-block-link-local", true, "Block port probes to link-local addresses (169.254.0.0/16, fe80::/10)")
	portBlockLoopback := flag.Bool("port-block-loopback", true, "Block port probes to loopback addresses (127.0.0.0/8, ::1)")
	portBlockMetadata := flag.Bool("port-block-metadata", true, "Block port probes to cloud instance metadata addresses (e.g. 169.254.169.254)")
	portDenyPTR := flag.Bool("port-deny-ptr", false, "Disable reverse DNS (PTR) lookups even when reverse lookup is enabled")
	var portBlockedCIDRs multiValueFlag
	flag.Var(&portBlockedCIDRs, "port-block-cidr", "Additional CIDR network blocked from port probes (can be repeated)")

	flag.Parse()
	if len(flag.Args()) != 0 {
		flag.Usage()
		return
	}

	portPolicy, err := outbound.ParsePortSpec(*portAllow)
	if err != nil {
		log.Fatal(err)
	}
	var blockedNetworks []*net.IPNet
	for _, cidr := range portBlockedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("invalid -port-block-cidr %q: %s", cidr, err)
		}
		blockedNetworks = append(blockedNetworks, network)
	}
	probeConfig := outbound.Config{
		Timeout:           *portTimeout,
		MaxConcurrent:     *portMaxConcurrent,
		MaxConcurrentV4:   *portMaxConcurrentV4,
		MaxConcurrentV6:   *portMaxConcurrentV6,
		AllowIPv4:         *portAllowV4,
		AllowIPv6:         *portAllowV6,
		SourceRateV4:      outbound.RateLimit{Rate: *portRateSourceV4},
		SourceRateV6:      outbound.RateLimit{Rate: *portRateSourceV6},
		TargetRateV4:      outbound.RateLimit{Rate: *portRateTargetV4},
		TargetRateV6:      outbound.RateLimit{Rate: *portRateTargetV6},
		Ports:             portPolicy,
		BlockRFC1918:      *portBlockRFC1918,
		BlockLinkLocal:    *portBlockLinkLocal,
		BlockLoopback:     *portBlockLoopback,
		BlockMetadata:     *portBlockMetadata,
		BlockedNetworks:   blockedNetworks,
		DenyReverseLookup: *portDenyPTR,
	}

	r, err := geo.Open(*countryFile, *cityFile, *asnFile)
	if err != nil {
		log.Fatal(err)
	}
	cache := http.NewCache(*cacheSize)
	server := http.New(r, cache, *profile)
	server.IPHeaders = headers
	if _, err := os.Stat(*template); err == nil {
		server.Template = *template
	} else {
		log.Printf("Not configuring default handler: Template not found: %s", *template)
	}
	if *reverseLookup {
		if probeConfig.DenyReverseLookup {
			log.Println("Reverse lookup disabled by outbound security policy (-port-deny-ptr)")
		} else {
			log.Println("Enabling reverse lookup")
			server.LookupAddr = iputil.LookupAddr
		}
	}
	if *portLookup {
		guard, err := outbound.NewGuard(probeConfig, nil)
		if err != nil {
			log.Fatal(err)
		}
		server.ProbePort = guard.Probe
		server.PortStats = guard.Stats
		log.Printf("Enabling port lookup with outbound policy: timeout=%s max_concurrent=%d (v4=%d v6=%d) ipv4=%t ipv6=%t blocked: rfc1918=%t link_local=%t loopback=%t metadata=%t cidrs=%s",
			probeConfig.Timeout, probeConfig.MaxConcurrent, probeConfig.MaxConcurrentV4, probeConfig.MaxConcurrentV6,
			probeConfig.AllowIPv4, probeConfig.AllowIPv6, probeConfig.BlockRFC1918, probeConfig.BlockLinkLocal,
			probeConfig.BlockLoopback, probeConfig.BlockMetadata, portBlockedCIDRs.String())
		if *portAllow != "" {
			log.Printf("Restricting port probes to: %s", *portAllow)
		}
		logProbeRates("source", probeConfig.SourceRateV4.Rate, probeConfig.SourceRateV6.Rate)
		logProbeRates("target", probeConfig.TargetRateV4.Rate, probeConfig.TargetRateV6.Rate)
	}
	if *sponsor {
		log.Println("Enabling sponsor logo")
		server.Sponsor = *sponsor
	}
	if *noCustomIP {
		log.Println("Disabling custom IP lookup")
		server.NoCustomIP = true
	}
	if len(headers) > 0 {
		log.Printf("Trusting remote IP from header(s): %s", headers.String())
	}
	if *cacheSize > 0 {
		log.Printf("Cache capacity set to %d", *cacheSize)
	}
	if *profile {
		log.Printf("Enabling profiling handlers")
	}
	log.Printf("Listening on http://%s", *listen)
	if err := server.ListenAndServe(*listen); err != nil {
		log.Fatal(err)
	}
}

func logProbeRates(scope string, v4, v6 float64) {
	if v4 <= 0 && v6 <= 0 {
		return
	}
	log.Printf("Per-%s rate limits (probes/sec): v4=%v v6=%v", scope, v4, v6)
}
