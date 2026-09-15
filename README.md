# echoip

[![ci](https://github.com/mpolden/echoip/actions/workflows/ci.yml/badge.svg)](https://github.com/mpolden/echoip/actions/workflows/ci.yml)

A simple service for looking up your IP address. This is the code that powers
https://ifconfig.co.

## Usage

Just the business, please:

```
$ curl ifconfig.co
127.0.0.1

$ http ifconfig.co
127.0.0.1

$ wget -qO- ifconfig.co
127.0.0.1

$ fetch -qo- https://ifconfig.co
127.0.0.1

$ bat -print=b ifconfig.co/ip
127.0.0.1
```

Country and city lookup:

```
$ curl ifconfig.co/country
Elbonia

$ curl ifconfig.co/country-iso
EB

$ curl ifconfig.co/city
Bornyasherk

$ curl ifconfig.co/asn
AS31337

$ curl ifconfig.co/asn-org
Dilbert Technologies
```

As JSON:

```
$ curl -H 'Accept: application/json' ifconfig.co  # or curl ifconfig.co/json
{
  "city": "Bornyasherk",
  "country": "Elbonia",
  "country_iso": "EB",
  "ip": "127.0.0.1",
  "ip_decimal": 2130706433,
  "asn": "AS31337",
  "asn_org": "Dilbert Technologies"
}
```

Port testing:

```
$ curl ifconfig.co/port/80
{
  "ip": "127.0.0.1",
  "port": 80,
  "reachable": false,
  "status": "refused"
}
```

Pass the appropriate flag (usually `-4` and `-6`) to your client to switch
between IPv4 and IPv6 lookup.

### Port probe security policy

Port probes are outbound TCP connections made by the server, so they are
guarded by an outbound security policy. By default, probes to RFC1918 private
addresses, link-local addresses (`169.254.0.0/16`, `fe80::/10`), loopback
addresses (`127.0.0.0/8`, `::1`) and cloud instance metadata addresses (e.g.
`169.254.169.254`) are blocked. Policy violations return HTTP `403`,
rate-limited requests return `429` and saturated concurrency caps return
`503`.

Available knobs (shown with their defaults):

* `-port-timeout 2s` — timeout for a single probe TCP connection
* `-port-max-concurrent`, `-port-max-concurrent-v4`, `-port-max-concurrent-v6` — global and per-family concurrency caps (`0` = unlimited)
* `-port-rate-source-v4`, `-port-rate-source-v6`, `-port-rate-target-v4`, `-port-rate-target-v6` — per-source/per-target probes per second, separately for IPv4/IPv6 (`0` = unlimited)
* `-port-allow 80,443,8000-9000` — whitelist of individual TCP ports and inclusive port ranges
* `-port-allow-ipv4`, `-port-allow-ipv6` — enable/disable probing per address family
* `-port-block-rfc1918`, `-port-block-link-local`, `-port-block-loopback`, `-port-block-metadata` — toggle the default address blocks (pass `=false` to disable)
* `-port-block-cidr 203.0.113.0/24` — block an additional network; can be repeated
* `-port-deny-ptr` — disable reverse DNS (PTR) lookups even when `-r` is set

When profiling is enabled (`-P`), probe metrics such as connection counts and
failure rate are available at `/debug/port/`.

## Features

* Easy to remember domain name
* Fast
* Supports IPv6
* Supports HTTPS
* Supports common command-line clients (e.g. `curl`, `httpie`, `ht`, `wget` and `fetch`)
* JSON output
* ASN, country and city lookup, using data from MaxMind
* Port testing
* All endpoints (except `/port`) can return information about a custom IP address specified via `?ip=` query parameter
* Open source under the [BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause)

## Why?

* To scratch an itch
* An excuse to use Go for something
* Faster than ifconfig.me and has IPv6 support

## Building

Compiling requires the [Golang compiler](https://golang.org/) to be installed.
This package can be installed with:

`go install github.com/mpolden/echoip/...@latest`

For more information on building a Go project, see the [official Go
documentation](https://golang.org/doc/code.html).

## Docker image

A Docker image is available on [Docker
Hub](https://hub.docker.com/r/mpolden/echoip), which can be downloaded with:

`docker pull mpolden/echoip`

## Geolocation data

`echoip` uses the MaxMind GeoIP databases to show additional information about
IP addresses, such as registered country/city and ASN details.

The databases can be downloaded with:

`GEOIP_LICENSE_KEY=<key> MAXMIND_ACCOUNT_ID=<account-id> make geoip-download`

Downloading requires a MaxMind account and license key. See the following links for more information:

- https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- https://dev.maxmind.com/geoip/updating-databases/#directly-downloading-databases

### Usage

```
$ echoip -h
Usage of echoip:
  -C int
        Size of response cache. Set to 0 to disable
  -H value
        Header to trust for remote IP, if present (e.g. X-Real-IP)
  -L    Disable custom IP lookup
  -P    Enables profiling handlers
  -a string
        Path to GeoIP ASN database
  -c string
        Path to GeoIP city database
  -f string
        Path to GeoIP country database
  -l string
        Listening address (default ":8080")
  -p    Enable port lookup
  -port-allow string
        Allowed TCP probe ports as comma-separated list of ports and ranges, e.g. 80,443,8000-9000 (default: all ports)
  -port-allow-ipv4
        Allow port probes to IPv4 targets (default true)
  -port-allow-ipv6
        Allow port probes to IPv6 targets (default true)
  -port-block-cidr value
        Additional CIDR network blocked from port probes (can be repeated)
  -port-block-link-local
        Block port probes to link-local addresses (169.254.0.0/16, fe80::/10) (default true)
  -port-block-loopback
        Block port probes to loopback addresses (127.0.0.0/8, ::1) (default true)
  -port-block-metadata
        Block port probes to cloud instance metadata addresses (e.g. 169.254.169.254) (default true)
  -port-block-rfc1918
        Block port probes to RFC1918 private IPv4 addresses (default true)
  -port-deny-ptr
        Disable reverse DNS (PTR) lookups even when reverse lookup is enabled
  -port-max-concurrent int
        Maximum concurrent outbound port probes, all families (0 = unlimited)
  -port-max-concurrent-v4 int
        Maximum concurrent outbound IPv4 port probes (0 = unlimited)
  -port-max-concurrent-v6 int
        Maximum concurrent outbound IPv6 port probes (0 = unlimited)
  -port-rate-source-v4 float
        Maximum port probes per second per source IPv4 address (0 = unlimited)
  -port-rate-source-v6 float
        Maximum port probes per second per source IPv6 address (0 = unlimited)
  -port-rate-target-v4 float
        Maximum port probes per second per target IPv4 address (0 = unlimited)
  -port-rate-target-v6 float
        Maximum port probes per second per target IPv6 address (0 = unlimited)
  -port-timeout duration
        Timeout for a single port probe TCP connection (default 2s)
  -r    Perform reverse hostname lookups
  -s    Show sponsor logo
  -t string
        Path to template dir (default "html")
```
