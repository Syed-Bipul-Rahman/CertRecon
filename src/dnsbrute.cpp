#include "dnsbrute.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <random>
#include <thread>

#include "resolver.hpp"

namespace dnsbrute {

namespace {

// Canonical signature of a resolution, for comparing against the wildcard baseline.
// Uses CNAME targets when present (wildcards are often CNAME-based), else the IP set.
std::string signature(const model::Dns& dns) {
    if (!dns.cnames.empty()) return "cname:" + dns.cnames.back();
    std::vector<std::string> ips = dns.a;
    ips.insert(ips.end(), dns.aaaa.begin(), dns.aaaa.end());
    std::sort(ips.begin(), ips.end());
    std::string s = "ip:";
    for (const auto& ip : ips) s += ip + ",";
    return s;
}

std::string random_label(std::mt19937& rng) {
    static const char* alnum = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::uniform_int_distribution<int> len(10, 16);
    std::uniform_int_distribution<int> ch(0, 35);
    std::string s;
    int n = len(rng);
    for (int i = 0; i < n; ++i) s += alnum[ch(rng)];
    return s;
}

}  // namespace

const std::vector<std::string>& default_wordlist() {
    static const std::vector<std::string> w = {
        "www", "mail", "ftp", "webmail", "smtp", "pop", "pop3", "imap", "ns", "ns1", "ns2", "ns3",
        "ns4", "mx", "mx1", "mx2", "relay", "mta", "email", "remote", "vpn", "gateway", "gw",
        "proxy", "firewall", "fw", "router", "dns", "ldap", "ad", "dc",
        "api", "api-dev", "api-staging", "api-prod", "dev-api", "apigateway", "api-gateway",
        "graphql", "rest", "ws", "websocket", "socket", "stream", "grpc", "api2", "v1", "v2",
        "dev", "development", "staging", "stage", "test", "testing", "qa", "uat", "sandbox",
        "demo", "beta", "alpha", "preview", "prod", "production", "local", "internal", "intranet",
        "extranet", "corp", "corporate",
        "admin", "administrator", "portal", "panel", "cpanel", "whm", "plesk", "dashboard",
        "manage", "management", "console", "control", "backend", "cms", "wp", "wordpress",
        "login", "signin", "auth", "sso", "oauth", "secure", "account", "accounts", "user",
        "users", "profile", "my", "id", "identity",
        "app", "apps", "app2", "web", "web1", "web2", "www2", "m", "mobile", "wap",
        "cdn", "static", "assets", "img", "images", "media", "video", "videos", "download",
        "downloads", "files", "file", "share", "drive", "storage", "s3", "upload", "uploads",
        "blog", "news", "shop", "store", "cart", "checkout", "pay", "payment", "payments",
        "billing", "invoice", "crm", "erp", "hr", "finance", "support", "help", "helpdesk",
        "docs", "doc", "documentation", "wiki", "kb", "faq", "status", "forum", "community",
        "git", "gitlab", "github", "bitbucket", "svn", "jenkins", "ci", "cd", "build", "deploy",
        "jira", "confluence", "nexus", "artifactory", "registry", "docker", "harbor", "vault",
        "consul", "k8s", "kube", "kubernetes", "rancher", "argo",
        "db", "database", "mysql", "postgres", "postgresql", "mssql", "oracle", "mongo", "mongodb",
        "redis", "memcached", "elastic", "elasticsearch", "es", "kibana", "logstash", "solr",
        "grafana", "prometheus", "monitor", "monitoring", "metrics", "nagios", "zabbix", "log",
        "logs", "syslog", "splunk", "sentry",
        "backup", "backups", "old", "new", "temp", "tmp", "archive", "mirror", "cache", "edge",
        "origin", "lb", "loadbalancer", "balancer", "cluster", "master", "slave", "primary",
        "secondary", "replica", "standby", "failover", "node1", "node2", "srv", "server", "host",
        "smtp2", "ns5", "autodiscover", "autoconfig", "exchange", "owa", "lync", "sip", "voip",
        "pbx", "chat", "im", "meet", "conference", "calendar", "cal",
        "ads", "ad", "ad1", "analytics", "track", "tracking", "pixel", "event", "events",
        "marketing", "newsletter", "campaign", "go", "link", "l", "url", "redirect", "r",
        "partners", "partner", "affiliate", "client", "clients", "customer", "customers",
        "careers", "jobs", "about", "contact", "info", "press", "investor", "legal", "privacy",
        "cloud", "aws", "azure", "gcp", "do", "vps", "colo", "dmz", "test1", "test2", "dev1",
        "dev2", "stage1", "stg", "prd", "pre", "pre-prod", "preprod", "live", "www3",
    };
    return w;
}

Result run(const std::string& domain, const Options& opts, const ProgressFn& progress) {
    Result result;
    const auto& words = opts.wordlist.empty() ? default_wordlist() : opts.wordlist;

    // --- Wildcard detection: resolve several random, almost-certainly-nonexistent names. ---
    std::set<std::string> wildcard_sigs;
    std::set<std::string> wildcard_ip_set;
    {
        std::mt19937 rng(std::random_device{}());
        for (int i = 0; i < opts.wildcard_probes; ++i) {
            model::Dns d = resolver::resolve(random_label(rng) + "." + domain);
            if (d.resolved || !d.cnames.empty()) {
                result.wildcard = true;
                wildcard_sigs.insert(signature(d));
                for (const auto& ip : d.a) wildcard_ip_set.insert(ip);
                for (const auto& ip : d.aaaa) wildcard_ip_set.insert(ip);
            }
        }
        result.wildcard_ips.assign(wildcard_ip_set.begin(), wildcard_ip_set.end());
    }

    // --- Brute-force the wordlist. ---
    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    std::mutex mu;

    auto worker = [&] {
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= words.size()) break;
            std::string fqdn = words[i] + "." + domain;
            model::Dns d = resolver::resolve(fqdn);
            bool keep = false;
            if (d.resolved || !d.cnames.empty()) {
                if (!result.wildcard) {
                    keep = true;
                } else {
                    // Keep only if it differs from the wildcard baseline: a distinct
                    // signature, or at least one IP outside the wildcard pool.
                    if (wildcard_sigs.find(signature(d)) == wildcard_sigs.end()) {
                        keep = true;
                    } else {
                        for (const auto& ip : d.a)
                            if (wildcard_ip_set.find(ip) == wildcard_ip_set.end()) { keep = true; break; }
                    }
                }
            }
            if (keep) {
                std::lock_guard<std::mutex> lk(mu);
                result.found.insert(fqdn);
            }
            size_t n = done.fetch_add(1) + 1;
            if (progress) {
                std::lock_guard<std::mutex> lk(mu);
                progress(n, words.size());
            }
        }
    };

    int n = std::max(1, std::min<int>(opts.concurrency, static_cast<int>(words.size())));
    std::vector<std::thread> pool;
    pool.reserve(n);
    for (int i = 0; i < n; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    result.tried = words.size();
    return result;
}

}  // namespace dnsbrute
