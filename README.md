# CertRecon

Fast subdomain discovery and reconnaissance, written in C++17. CertRecon first enumerates
subdomains **passively** from Certificate Transparency logs (via
[ct.certkit.io](https://ct.certkit.io)), then can **actively** enrich them:

- **DNS brute-force** — expand discovery with a built-in wordlist, with wildcard-DNS
  detection to filter false positives
- **DNS** — A/AAAA resolution and CNAME chains
- **Takeover** — dangling records & subdomain-takeover fingerprints
- **Ports** — TCP connect scan + service/banner discovery
- **HTTP** — status, title, server, tech detection
- **Content** — directory/content brute-forcing
- **Host intel** — TLS certificate inspection (+ SAN harvesting of new subdomains), reverse
  DNS, ASN/org/country (Team Cymru), CDN/WAF detection, Shodan-compatible favicon hash
- **Vuln signals** — missing security headers, CORS misconfiguration, exposed `.git`/`.env`,
  unauthenticated Redis/Elasticsearch — each with a fix suggestion
- **Safety** — global rate limiting, per-request delay, and a `--passive-only` mode that
  sends zero traffic to targets

> Only scan domains you own or are explicitly authorized to test. The active stages
> (`--ports`, `--http`, `--dirs`) send traffic directly to the target hosts.

## Build

Requirements: a C++17 compiler (clang/gcc) and libcurl (preinstalled on macOS).

```sh
make                 # builds ./certrecon
sudo make install    # optional: installs to /usr/local/bin
```

Or with CMake:

```sh
cmake -B build && cmake --build build
```

On Debian/Ubuntu, install libcurl first: `sudo apt install build-essential libcurl4-openssl-dev`.

## Usage

```sh
certrecon --scan google.com                       # passive subdomain list
certrecon --scan example.com --all                # discover + full recon
certrecon --scan example.com --takeover --http    # pick specific stages
certrecon --scan example.com --ports -p 80,443,8080
certrecon -l domains.txt --silent | httpx         # pipe into other tools
echo tesla.com | certrecon --json
```

Without any recon flag, CertRecon just prints the discovered subdomains (one per line, or
JSON lines with `--json`), so it drops cleanly into a pipeline. Add recon flags to enrich each
host; output then becomes a per-host report (or one JSON object per host with `--json`).

### Input
| Flag | Description |
|------|-------------|
| `-s, --scan <domain>` | Domain to enumerate (repeatable; a bare argument also works) |
| `-l, --list <file>` | File with one domain per line (`#` comments allowed) |

Domains are also read from stdin when piped. Input like `https://Example.com/path` is
normalized to `example.com`.

### Discovery
Expands the subdomain set before any recon runs. DNS-only — no traffic to the target hosts.

| Flag | Description |
|------|-------------|
| `--brute` | DNS brute-force with a built-in ~300-label wordlist + wildcard detection |
| `--wordlist-dns <file>` | Custom DNS wordlist, one label per line (implies `--brute`) |

### Recon stages
| Flag | Description |
|------|-------------|
| `-r, --resolve` | Resolve A/AAAA records and the CNAME chain |
| `--takeover` | Detect dangling CNAMEs (NXDOMAIN targets) and subdomain-takeover fingerprints |
| `--ports` | TCP connect scan of common ports + service/banner discovery |
| `--http` | Probe http/https: status, title, `Server`, redirect, tech detection |
| `--dirs` | Directory/content brute-force on live HTTP hosts |
| `--intel` | Host intel: TLS cert + SAN harvest, reverse DNS, ASN, CDN, favicon hash |
| `--vuln` | Vuln signals: security headers, CORS, exposed files, open services |
| `-a, --all` | Enable every stage above |

`--intel` and `--vuln` imply an HTTP probe (for the favicon, header-based CDN detection, and
header/CORS analysis). The open-service checks under `--vuln` (Redis/Elasticsearch) only run
on ports confirmed open, so combine with `--ports` (or `--all`) to enable them.

### Recon tuning
| Flag | Description |
|------|-------------|
| `-p, --port-list <spec>` | Ports to scan, e.g. `80,443,8000-8100` (default: ~28 common ports) |
| `--wordlist <file>` | Custom wordlist for `--dirs` (one path per line) |
| `-c, --concurrency <n>` | Hosts enriched in parallel (default 25) |

### Safety / rate control
Applies to traffic sent to **targets** (not to the CT API, DNS, or ASN lookups).

| Flag | Description |
|------|-------------|
| `--passive-only` | Send zero traffic to targets — only CT, DNS, reverse DNS, ASN and CNAME-based CDN/dangling checks run |
| `--rate <rps>` | Cap target requests per second across all threads (0 = unlimited) |
| `--delay <ms>` | Fixed pause after each target request |

### Output
| Flag | Description |
|------|-------------|
| `-o, --output <file>` | Write results to a file (color is stripped from file output) |
| `-j, --json` | JSON output (JSON lines, or one object per host when enriching) |
| `--silent` | Only print results (no banner, progress or summary) |
| `--no-color` | Disable colors (also honors `NO_COLOR`) |

### CT fetch tuning
| Flag | Description |
|------|-------------|
| `-t, --threads <n>` | Concurrent CT requests per domain (default 3) |
| `--timeout <sec>` | Per-request timeout (default 60) |
| `--retries <n>` | Retries for network/server errors (default 3) |
| `-m, --max <n>` | Max certificates to fetch per domain (default: all) |
| `-w, --wildcards` | Keep `*.example.com` entries instead of stripping `*.` |

Results go to stdout; banners, progress and stats go to stderr, so piping stays clean.
The process exits non-zero if a scan fails outright (not for findings).

## Takeover detection

For each subdomain with a CNAME, CertRecon:

1. Flags a **dangling CNAME** if the CNAME target itself is `NXDOMAIN` (claimable).
2. Matches the CNAME target against built-in fingerprints for ~16 services (GitHub Pages,
   S3, Heroku, Azure, Fastly, Shopify, Netlify, Surge, Bitbucket, Ghost, Pantheon, Zendesk,
   and more). For fingerprintable services it confirms by fetching the page and matching the
   provider's "unclaimed resource" signature before reporting a **HIGH** finding, with a
   remediation hint.

## DNS brute-force (`--brute`)

Certificate Transparency can only reveal names that were issued a logged certificate. It cannot
see hosts behind a wildcard certificate, internal/dev hosts with no public cert, or names not
yet logged. `--brute` closes that gap by resolving `<label>.<domain>` for a built-in wordlist
of ~300 common labels (override with `--wordlist-dns <file>`), merging anything that resolves
into the subdomain set before recon runs.

It is DNS-only, so it sends no traffic to the target web hosts and runs even under
`--passive-only`.

**Wildcard detection:** before brute-forcing, CertRecon resolves several random names under the
domain. If they resolve, the domain uses wildcard DNS, and every brute candidate that resolves
to the same wildcard answer is discarded as a false positive — only names with a distinct
resolution are kept. (Tested against `traefik.me`, which wildcards everything to 127.0.0.1:
all 304 candidates were correctly filtered.)

## Host intelligence (`--intel`)

For each live host CertRecon gathers:

- **TLS certificate** — subject CN, issuer, expiry (with days remaining) and all SANs, read
  via libcurl's `CERTINFO` (no OpenSSL dependency). SANs that are new subdomains of the apex
  are **harvested** and enriched in a second pass. Expired / soon-to-expire certs become findings.
- **Reverse DNS** — the PTR record for the primary IP.
- **ASN / org / country** — looked up over DNS via Team Cymru (no API key).
- **CDN / WAF** — identified from the CNAME chain and response headers (Cloudflare, Akamai,
  Fastly, CloudFront, Azure, Imperva, GitHub Pages, Vercel, Netlify, and more).
- **Favicon hash** — MurmurHash3 of the base64-encoded `/favicon.ico`, compatible with
  Shodan's `http.favicon.hash` for pivoting.

## Vulnerability signals (`--vuln`)

Lightweight, high-signal checks, each reported with a severity and a suggested fix:

- **Missing security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options.
- **CORS misconfiguration** — reflected arbitrary `Origin`, or wildcard ACAO with credentials.
- **Exposed files** — `/.git/HEAD` and `/.env`, confirmed by content (not just status code).
- **Unauthenticated services** — Redis (`PING` → `+PONG`) and Elasticsearch (open cluster
  info on `:9200`), checked only on ports found open by `--ports`.

These are signals to investigate and fix manually, not exploitation.

## How it works

1. `POST https://ct.certkit.io/search` with `{"domain":"...","sort":"","limit":2000,"offset":0}`
   returns the first 2000 certificates and `totalCount`.
2. The remaining pages are fetched in parallel by offset.
3. Names are lowercased, `*.` is stripped, and only exact matches or subdomains of the target
   are kept, de-duplicated and sorted.

The API rate-limits above about 3 concurrent requests. When it returns HTTP 429, every
worker pauses together with exponential backoff (up to 30s), so large domains still finish
completely. If a page still fails, CertRecon prints a warning that the results may be incomplete.

## Layout

```
src/main.cpp       CLI, input/output, orchestration
src/certkit.cpp    CT API client: pagination, threading, rate-limit handling, filtering
src/dnsbrute.cpp   DNS brute-force discovery + wildcard detection
src/pipeline.cpp   runs the recon stages across hosts concurrently
src/resolver.cpp   DNS A/AAAA (getaddrinfo) + CNAME chain / NXDOMAIN (libresolv)
src/portscan.cpp   TCP connect scanner + banner grabbing / service ID
src/probe.cpp      HTTP(S) probing and directory/content brute-forcing (libcurl)
src/takeover.cpp   dangling-record & subdomain-takeover fingerprints
src/tlsinfo.cpp    TLS certificate inspection + SAN harvest (libcurl CERTINFO)
src/netintel.cpp   reverse DNS, ASN (Team Cymru), CDN/WAF, favicon hash
src/vulncheck.cpp  security headers, CORS, exposed files, open services
src/ratelimit.cpp  process-wide rate limiter for target traffic
src/report.cpp     human-readable and JSON rendering
src/http.cpp       libcurl POST wrapper (CT client)
src/json.hpp       small dependency-free JSON parser
src/model.hpp      shared data model (Host, findings, ...)
```

The directory brute-forcing stage filters soft-404s by comparing each response against a
baseline request to a path known not to exist.
