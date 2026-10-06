// Shared data model for an enriched host (one discovered subdomain).
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace model {

struct Dns {
    bool resolved = false;      // has at least one A/AAAA record
    bool nxdomain = false;      // name does not exist
    std::vector<std::string> a;      // IPv4 addresses
    std::vector<std::string> aaaa;   // IPv6 addresses
    std::vector<std::string> cnames; // CNAME chain (first -> ...)
};

struct Port {
    int port = 0;
    std::string service;   // guessed service name
    std::string banner;    // first line of banner, if any
};

struct Http {
    bool alive = false;
    std::string url;            // final URL after redirects
    long status = 0;
    std::string title;
    std::string server;         // Server header
    std::string redirect;       // Location, if this was a redirect
    long content_length = -1;
    std::vector<std::string> tech;  // detected technologies
    std::vector<std::pair<std::string, std::string>> headers;  // all response headers (lowercased keys)

    std::string header(const std::string& key) const {
        for (const auto& kv : headers)
            if (kv.first == key) return kv.second;
        return "";
    }
};

// TLS certificate details (via curl CERTINFO).
struct Tls {
    bool present = false;
    std::string subject_cn;
    std::string issuer;
    std::string not_after;      // human-readable expiry
    int days_left = -1;         // days until expiry (negative = expired)
    std::vector<std::string> sans;  // Subject Alternative Names
};

// Network/hosting intelligence for the host's primary IP.
struct NetIntel {
    std::string ip;             // IP the intel describes
    std::string reverse_dns;    // PTR record
    std::string asn;            // e.g. "AS15169"
    std::string asn_org;        // e.g. "GOOGLE - Google LLC, US"
    std::string country;        // 2-letter country code
    std::string cdn;            // detected CDN/WAF, if any
    std::string favicon_hash;   // mmh3 favicon hash (Shodan-compatible)
};

struct Dir {
    std::string path;
    long status = 0;
    long length = -1;
};

// Severity for a security finding.
enum class Severity { Info, Low, Medium, High };

struct Finding {
    Severity severity = Severity::Info;
    std::string title;        // short label, e.g. "Dangling CNAME"
    std::string detail;       // what was observed
    std::string suggestion;   // remediation hint (optional)
};

struct Host {
    std::string name;      // the subdomain
    std::string input;     // the apex domain it came from
    Dns dns;
    std::vector<Port> ports;
    Http http;
    std::vector<Dir> dirs;
    Tls tls;
    NetIntel intel;
    std::vector<Finding> findings;
    std::vector<std::string> harvested;  // new apex-matching names found via TLS SANs

    bool is_live() const { return dns.resolved; }
};

inline const char* severity_label(Severity s) {
    switch (s) {
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
        default: return "INFO";
    }
}

}  // namespace model
