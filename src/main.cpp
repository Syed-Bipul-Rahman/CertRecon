// certrecon - passive subdomain enumeration (via Certificate Transparency) with
// optional active recon: DNS resolution, takeover checks, port scanning,
// HTTP probing and content brute-forcing.
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "certkit.hpp"
#include "dnsbrute.hpp"
#include "http.hpp"
#include "json.hpp"
#include "model.hpp"
#include "pipeline.hpp"
#include "portscan.hpp"
#include "probe.hpp"
#include "ratelimit.hpp"
#include "report.hpp"
#include "version.hpp"

namespace {

struct Config {
    std::vector<std::string> domains;
    std::string list_file;
    std::string output_file;
    bool json = false;
    bool silent = false;
    bool no_color = false;
    certkit::Options scan;

    // Enrichment stages.
    bool r_resolve = false;
    bool r_takeover = false;
    bool r_ports = false;
    bool r_http = false;
    bool r_dirs = false;
    bool r_intel = false;        // host intelligence: TLS cert, rDNS, ASN, CDN, favicon
    bool r_vuln = false;         // vuln signals: headers, CORS, exposed files, open services
    bool passive_only = false;   // send no traffic to targets
    std::string ports_spec;      // e.g. "80,443,8000-8100"
    bool r_brute = false;        // DNS brute-force discovery stage
    std::string wordlist_file;   // custom dir-brute wordlist
    std::string dns_wordlist_file;  // custom DNS brute-force wordlist
    int host_concurrency = 25;
    double rate = 0;             // max target requests/sec (0 = unlimited)
    int delay_ms = 0;            // fixed delay after each target request

    bool any_stage() const {
        return r_resolve || r_takeover || r_ports || r_http || r_dirs || r_intel || r_vuln;
    }
};

bool g_color = true;

const char* c(const char* code) { return g_color ? code : ""; }
#define RESET c("\033[0m")
#define BOLD c("\033[1m")
#define RED c("\033[31m")
#define GREEN c("\033[32m")
#define YELLOW c("\033[33m")
#define CYAN c("\033[36m")
#define DIM c("\033[2m")

void print_banner() {
    std::cerr << CYAN << BOLD
              << R"(
   ___         _   ___
  / __|___ _ _| |_| _ \___ __ ___ _ _
 | (__/ -_) '_|  _|   / -_) _/ _ \ ' \
  \___\___|_|  \__|_|_\___\__\___/_||_|
)" << RESET << DIM << "  v" CERTRECON_VERSION " - subdomain discovery & recon via Certificate Transparency\n\n"
              << RESET;
}

void print_usage(const char* prog) {
    std::cout <<
        "Usage: " << prog << " --scan <domain> [options]\n"
        "\n"
        "Passively enumerates subdomains from Certificate Transparency logs\n"
        "(source: ct.certkit.io), then optionally enriches them with active recon.\n"
        "\n"
        "Input:\n"
        "  -s, --scan <domain>     Domain to enumerate (repeatable)\n"
        "  -l, --list <file>       File with one domain per line\n"
        "                          (domains are also read from stdin when piped)\n"
        "\n"
        "Discovery (expands the subdomain set before recon):\n"
        "      --brute             DNS brute-force with a built-in wordlist + wildcard detection\n"
        "      --wordlist-dns <f>  Custom DNS brute-force wordlist (implies --brute)\n"
        "\n"
        "Recon stages (run against the discovered subdomains):\n"
        "  -r, --resolve           Resolve A/AAAA/CNAME records\n"
        "      --takeover          Detect dangling records & subdomain takeovers\n"
        "      --ports             TCP port scan + service/banner discovery\n"
        "      --http              HTTP(S) probe: status, title, server, tech\n"
        "      --dirs              Directory/content brute-force on live HTTP hosts\n"
        "      --intel             Host intel: TLS cert, SAN harvest, rDNS, ASN, CDN, favicon\n"
        "      --vuln              Vuln signals: security headers, CORS, exposed files, services\n"
        "  -a, --all               Enable all of the above stages\n"
        "\n"
        "Recon tuning:\n"
        "  -p, --port-list <spec>  Ports to scan, e.g. 80,443,8000-8100 (default: top ~28)\n"
        "      --wordlist <file>   Custom wordlist for --dirs (one path per line)\n"
        "  -c, --concurrency <n>   Hosts enriched in parallel (default 25)\n"
        "\n"
        "Safety / rate control (applies to traffic sent to targets):\n"
        "      --passive-only      Send zero traffic to targets (DNS/CT/ASN only)\n"
        "      --rate <rps>        Max target requests per second (0 = unlimited)\n"
        "      --delay <ms>        Fixed delay after each target request\n"
        "\n"
        "Output:\n"
        "  -o, --output <file>     Write results to file\n"
        "  -j, --json              JSON output (one object per host when enriching)\n"
        "      --silent            Only print results (no banner/progress/summary)\n"
        "      --no-color          Disable colored output\n"
        "\n"
        "CT fetch tuning:\n"
        "  -t, --threads <n>       Concurrent CT requests per domain (default 3)\n"
        "      --timeout <sec>     Per-request timeout in seconds (default 60)\n"
        "      --retries <n>       Retries per failed request (default 3)\n"
        "  -m, --max <n>           Max certificates to fetch per domain (default: all)\n"
        "  -w, --wildcards         Keep wildcard entries (*.example.com)\n"
        "\n"
        "  -h, --help              Show this help\n"
        "  -V, --version           Show version\n"
        "\n"
        "Examples:\n"
        "  " << prog << " --scan google.com\n"
        "  " << prog << " --scan example.com --brute\n"
        "  " << prog << " --scan example.com --all\n"
        "  " << prog << " --scan example.com --takeover --http\n"
        "  " << prog << " --scan example.com --intel --vuln\n"
        "  " << prog << " --scan example.com --all --rate 20 --delay 50\n"
        "  " << prog << " --scan example.com --takeover --passive-only\n"
        "  " << prog << " -l domains.txt --resolve --silent | sort -u\n";
}

[[noreturn]] void die(const std::string& msg) {
    std::cerr << RED << "[ERR] " << RESET << msg << "\n";
    std::exit(1);
}

long parse_num(const std::string& flag, const std::string& v, long min) {
    char* end = nullptr;
    long n = std::strtol(v.c_str(), &end, 10);
    if (v.empty() || *end != '\0' || n < min)
        die("invalid value for " + flag + ": '" + v + "'");
    return n;
}

Config parse_args(int argc, char** argv) {
    Config cfg;
    auto need = [&](int& i, const std::string& flag) -> std::string {
        if (i + 1 >= argc) die("missing value for " + flag);
        return argv[++i];
    };

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        std::string inline_val;
        bool has_inline = false;
        if (a.rfind("--", 0) == 0) {
            if (auto eq = a.find('='); eq != std::string::npos) {
                inline_val = a.substr(eq + 1);
                a = a.substr(0, eq);
                has_inline = true;
            }
        }
        auto val = [&]() { return has_inline ? inline_val : need(i, a); };

        if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        } else if (a == "-V" || a == "--version") {
            std::cout << "certrecon " CERTRECON_VERSION "\n";
            std::exit(0);
        } else if (a == "-s" || a == "--scan" || a == "-d" || a == "--domain") {
            cfg.domains.push_back(val());
        } else if (a == "-l" || a == "--list") {
            cfg.list_file = val();
        } else if (a == "-o" || a == "--output") {
            cfg.output_file = val();
        } else if (a == "-j" || a == "--json") {
            cfg.json = true;
        } else if (a == "--silent") {
            cfg.silent = true;
        } else if (a == "--no-color" || a == "-nc") {
            cfg.no_color = true;
        } else if (a == "-r" || a == "--resolve") {
            cfg.r_resolve = true;
        } else if (a == "--takeover") {
            cfg.r_takeover = true;
        } else if (a == "--ports") {
            cfg.r_ports = true;
        } else if (a == "--http" || a == "--probe") {
            cfg.r_http = true;
        } else if (a == "--dirs" || a == "--dirbrute") {
            cfg.r_dirs = true;
        } else if (a == "--brute" || a == "--dns-brute") {
            cfg.r_brute = true;
        } else if (a == "--wordlist-dns" || a == "--dns-wordlist") {
            cfg.dns_wordlist_file = val();
            cfg.r_brute = true;
        } else if (a == "--intel") {
            cfg.r_intel = true;
        } else if (a == "--vuln" || a == "--vulns") {
            cfg.r_vuln = true;
        } else if (a == "--passive-only" || a == "--passive") {
            cfg.passive_only = true;
        } else if (a == "--rate") {
            cfg.rate = std::strtod(val().c_str(), nullptr);
            if (cfg.rate < 0) cfg.rate = 0;
        } else if (a == "--delay") {
            cfg.delay_ms = static_cast<int>(parse_num(a, val(), 0));
        } else if (a == "-a" || a == "--all") {
            cfg.r_resolve = cfg.r_takeover = cfg.r_ports = cfg.r_http = cfg.r_dirs = true;
            cfg.r_intel = cfg.r_vuln = cfg.r_brute = true;
        } else if (a == "-p" || a == "--port-list" || a == "--ports-list") {
            cfg.ports_spec = val();
            cfg.r_ports = true;
        } else if (a == "--wordlist") {
            cfg.wordlist_file = val();
            cfg.r_dirs = true;
        } else if (a == "-c" || a == "--concurrency") {
            cfg.host_concurrency = static_cast<int>(parse_num(a, val(), 1));
            if (cfg.host_concurrency > 200) cfg.host_concurrency = 200;
        } else if (a == "-t" || a == "--threads") {
            cfg.scan.threads = static_cast<int>(parse_num(a, val(), 1));
            if (cfg.scan.threads > 50) cfg.scan.threads = 50;
        } else if (a == "--timeout") {
            cfg.scan.timeout_secs = parse_num(a, val(), 1);
        } else if (a == "--retries") {
            cfg.scan.retries = static_cast<int>(parse_num(a, val(), 0));
        } else if (a == "-m" || a == "--max") {
            cfg.scan.max_results = static_cast<size_t>(parse_num(a, val(), 1));
        } else if (a == "-w" || a == "--wildcards") {
            cfg.scan.keep_wildcards = true;
        } else if (!a.empty() && a[0] != '-') {
            cfg.domains.push_back(a);
        } else {
            die("unknown option: " + a + " (see --help)");
        }
    }
    return cfg;
}

void read_domains(std::istream& in, std::vector<std::string>& out) {
    std::string line;
    while (std::getline(in, line)) {
        if (auto p = line.find('#'); p != std::string::npos) line.erase(p);
        out.push_back(line);
    }
}

std::vector<std::string> load_wordlist(const std::string& path) {
    std::vector<std::string> words;
    std::ifstream f(path);
    if (!f) die("cannot open wordlist: " + path);
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (!line.empty() && line[0] != '#') words.push_back(line);
    }
    if (words.empty()) die("wordlist is empty: " + path);
    return words;
}

pipeline::Options build_pipeline_options(const Config& cfg) {
    pipeline::Options po;
    po.resolve = cfg.any_stage();
    po.takeover = cfg.r_takeover;
    po.ports = cfg.r_ports;
    // dirs, intel (favicon + header-based CDN) and vuln (header audit) all need an HTTP probe.
    po.http = cfg.r_http || cfg.r_dirs || cfg.r_intel || cfg.r_vuln;
    po.dirs = cfg.r_dirs;
    po.tls = cfg.r_intel;
    po.intel = cfg.r_intel;
    po.vuln = cfg.r_vuln;
    po.passive_only = cfg.passive_only;
    po.concurrency = cfg.host_concurrency;

    if (!cfg.ports_spec.empty()) {
        if (!portscan::parse_ports(cfg.ports_spec, po.port_opts.ports))
            die("invalid --port-list: '" + cfg.ports_spec + "'");
    }
    if (!cfg.wordlist_file.empty())
        po.probe_opts.wordlist = load_wordlist(cfg.wordlist_file);
    po.probe_opts.dirs = cfg.r_dirs;
    return po;
}

// Emits one subdomain in the non-enrichment (plain / JSON-lines) mode.
void emit_plain(const std::string& sub, const std::string& domain, bool as_json, std::ostream& cout,
                std::ofstream& out_file) {
    std::string line = as_json ? "{\"host\":\"" + json::escape(sub) + "\",\"input\":\"" +
                                     json::escape(domain) + "\",\"source\":\"certkit\"}"
                               : sub;
    cout << line << "\n";
    if (out_file.is_open()) out_file << line << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    g_color = isatty(STDERR_FILENO) && std::getenv("NO_COLOR") == nullptr;
    Config cfg = parse_args(argc, argv);
    if (cfg.no_color) g_color = false;

    std::vector<std::string> raw = cfg.domains;
    if (!cfg.list_file.empty()) {
        std::ifstream f(cfg.list_file);
        if (!f) die("cannot open list file: " + cfg.list_file);
        read_domains(f, raw);
    }
    if (raw.empty() && !isatty(STDIN_FILENO)) read_domains(std::cin, raw);

    std::vector<std::string> domains;
    std::set<std::string> seen;
    for (const auto& r : raw) {
        if (r.find_first_not_of(" \t\r\n") == std::string::npos) continue;
        std::string d = certkit::normalize_domain(r);
        if (d.empty()) {
            std::cerr << YELLOW << "[WRN] " << RESET << "skipping invalid domain: " << r << "\n";
            continue;
        }
        if (seen.insert(d).second) domains.push_back(d);
    }

    if (domains.empty()) {
        if (!cfg.silent) print_banner();
        print_usage(argv[0]);
        return 1;
    }

    std::ofstream out_file;
    if (!cfg.output_file.empty()) {
        out_file.open(cfg.output_file);
        if (!out_file) die("cannot open output file: " + cfg.output_file);
    }

    if (!cfg.silent) print_banner();

    http::global_init();
    ratelimit::configure(cfg.rate, cfg.delay_ms);
    const bool show_progress = !cfg.silent && isatty(STDERR_FILENO);
    const bool enrich = cfg.any_stage();
    pipeline::Options pipe_opts = enrich ? build_pipeline_options(cfg) : pipeline::Options{};

    size_t grand_total = 0;
    report::FindingTally grand_findings;
    int exit_code = 0;

    for (const auto& domain : domains) {
        if (!cfg.silent)
            std::cerr << CYAN << "[INF] " << RESET << "Enumerating subdomains for "
                      << BOLD << domain << RESET << "\n";

        auto started = std::chrono::steady_clock::now();
        certkit::ScanStats stats;
        std::set<std::string> subs;
        try {
            subs = certkit::scan(domain, cfg.scan, stats, [&](size_t done, size_t total) {
                if (show_progress)
                    std::cerr << "\r" << DIM << "      fetched " << done << "/" << total
                              << " certificates" << RESET << "\033[K" << std::flush;
            });
        } catch (const std::exception& e) {
            if (show_progress) std::cerr << "\r\033[K";
            std::cerr << RED << "[ERR] " << RESET << domain << ": " << e.what() << "\n";
            exit_code = 1;
            continue;
        }
        if (show_progress) std::cerr << "\r\033[K";

        if (!cfg.silent) {
            double secs = std::chrono::duration<double>(
                              std::chrono::steady_clock::now() - started).count();
            char buf[32];
            snprintf(buf, sizeof buf, "%.2fs", secs);
            std::cerr << GREEN << "[INF] " << RESET << "Found " << BOLD << subs.size() << RESET
                      << " subdomains for " << domain << " in " << buf << DIM << " ("
                      << stats.fetched_certs << " of " << stats.total_certs
                      << " certificates scanned)" << RESET << "\n";
            if (stats.failed_pages > 0)
                std::cerr << YELLOW << "[WRN] " << RESET << stats.failed_pages
                          << " page(s) failed after retries (" << stats.last_error
                          << "); results may be incomplete\n";
        }

        // Discovery: DNS brute-force expands the subdomain set before any recon.
        if (cfg.r_brute) {
            dnsbrute::Options bo;
            if (!cfg.dns_wordlist_file.empty()) bo.wordlist = load_wordlist(cfg.dns_wordlist_file);
            if (!cfg.silent)
                std::cerr << CYAN << "[INF] " << RESET << "DNS brute-forcing "
                          << (bo.wordlist.empty() ? dnsbrute::default_wordlist().size()
                                                  : bo.wordlist.size())
                          << " names\n";
            dnsbrute::Result br = dnsbrute::run(domain, bo, [&](size_t d, size_t t) {
                if (show_progress)
                    std::cerr << "\r" << DIM << "      tried " << d << "/" << t << " names" << RESET
                              << "\033[K" << std::flush;
            });
            if (show_progress) std::cerr << "\r\033[K";
            size_t before = subs.size();
            subs.insert(br.found.begin(), br.found.end());
            size_t added = subs.size() - before;
            if (!cfg.silent) {
                std::cerr << GREEN << "[INF] " << RESET << "DNS brute-force resolved "
                          << br.found.size() << " name(s), " << BOLD << "+" << added << RESET
                          << " new";
                if (br.wildcard)
                    std::cerr << YELLOW << "  [wildcard DNS detected" << RESET
                              << (br.wildcard_ips.empty() ? "" : ", filtering false positives")
                              << YELLOW << "]" << RESET;
                std::cerr << "\n";
            }
        }
        grand_total += subs.size();

        if (!enrich) {
            for (const auto& s : subs) emit_plain(s, domain, cfg.json, std::cout, out_file);
            std::cout.flush();
            continue;
        }

        // Active recon on the discovered subdomains.
        if (!cfg.silent) {
            std::vector<std::string> on;
            if (pipe_opts.resolve) on.push_back("resolve");
            if (cfg.r_takeover) on.push_back("takeover");
            if (cfg.r_ports) on.push_back("ports");
            if (cfg.r_http) on.push_back("http");
            if (cfg.r_dirs) on.push_back("dirs");
            if (cfg.r_intel) on.push_back("intel");
            if (cfg.r_vuln) on.push_back("vuln");
            std::string joined;
            for (size_t i = 0; i < on.size(); ++i) joined += (i ? "," : "") + on[i];
            std::cerr << CYAN << "[INF] " << RESET << "Running recon (" << joined << ") on "
                      << subs.size() << " hosts";
            if (cfg.passive_only) std::cerr << DIM << " [passive-only]" << RESET;
            std::cerr << "\n";
        }
        auto enrich_started = std::chrono::steady_clock::now();
        auto progress = [&](size_t done, size_t total) {
            if (show_progress)
                std::cerr << "\r" << DIM << "      enriched " << done << "/" << total << " hosts"
                          << RESET << "\033[K" << std::flush;
        };

        // Run the pipeline, then one extra pass over any new names harvested from
        // TLS SANs (bounded to a single round to avoid runaway recursion).
        std::vector<model::Host> hosts;
        std::set<std::string> done_names(subs.begin(), subs.end());
        std::set<std::string> frontier = subs;
        size_t harvested_total = 0;
        for (int pass = 0; pass <= 1 && !frontier.empty(); ++pass) {
            if (pass > 0 && !cfg.silent) {
                if (show_progress) std::cerr << "\r\033[K";
                std::cerr << CYAN << "[INF] " << RESET << "Enriching " << frontier.size()
                          << " new host(s) harvested from TLS certificates\n";
            }
            std::vector<model::Host> part = pipeline::run(frontier, domain, pipe_opts, progress);
            std::set<std::string> next;
            for (auto& h : part) {
                for (const auto& s : h.harvested)
                    if (done_names.insert(s).second) next.insert(s);
                hosts.push_back(std::move(h));
            }
            harvested_total += next.size();
            frontier = std::move(next);
        }
        if (show_progress) std::cerr << "\r\033[K";
        std::sort(hosts.begin(), hosts.end(),
                  [](const model::Host& a, const model::Host& b) { return a.name < b.name; });

        for (const auto& h : hosts) {
            if (cfg.json) {
                std::string line = report::json(h);
                std::cout << line << "\n";
                if (out_file.is_open()) out_file << line << "\n";
            } else {
                std::cout << report::human(h, g_color);
                if (out_file.is_open()) out_file << report::human(h, false);
            }
        }
        std::cout.flush();

        report::FindingTally t = report::tally(hosts);
        grand_findings.high += t.high;
        grand_findings.medium += t.medium;
        grand_findings.low += t.low;
        grand_findings.info += t.info;

        if (!cfg.silent) {
            double secs = std::chrono::duration<double>(
                              std::chrono::steady_clock::now() - enrich_started).count();
            char buf[32];
            snprintf(buf, sizeof buf, "%.2fs", secs);
            std::cerr << GREEN << "[INF] " << RESET << "Recon complete in " << buf;
            if (t.total() > 0)
                std::cerr << DIM << " (" << t.high << " high, " << t.medium << " medium, "
                          << t.low << " low findings)" << RESET;
            std::cerr << "\n";
            if (harvested_total > 0)
                std::cerr << GREEN << "[INF] " << RESET << "+" << harvested_total
                          << " extra subdomain(s) discovered via TLS certificate SANs\n";
        }
        grand_total += harvested_total;
    }

    if (!cfg.silent && !cfg.output_file.empty())
        std::cerr << GREEN << "[INF] " << RESET << "Results saved to " << cfg.output_file << "\n";
    if (!cfg.silent && domains.size() > 1)
        std::cerr << GREEN << "[INF] " << RESET << "Total: " << grand_total << " subdomains\n";
    if (!cfg.silent && enrich && grand_findings.total() > 0) {
        std::cerr << (grand_findings.high > 0 ? RED : YELLOW) << BOLD << "[!] " << RESET
                  << grand_findings.high << " high, " << grand_findings.medium << " medium, "
                  << grand_findings.low << " low security findings - review above\n";
    }

    http::global_cleanup();
    return exit_code;
}
