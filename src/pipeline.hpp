// Orchestrates the enrichment stages across many hosts concurrently.
#pragma once

#include <functional>
#include <set>
#include <string>
#include <vector>

#include "model.hpp"
#include "portscan.hpp"
#include "probe.hpp"

namespace pipeline {

struct Options {
    bool resolve = false;
    bool takeover = false;
    bool ports = false;
    bool http = false;
    bool dirs = false;
    bool tls = false;        // TLS certificate inspection + SAN harvest
    bool intel = false;      // reverse DNS, ASN, CDN, favicon
    bool vuln = false;       // security headers, CORS, exposed files, open services
    bool passive_only = false;  // send no traffic to targets

    int concurrency = 25;        // hosts processed in parallel
    long http_timeout_secs = 10;

    portscan::Options port_opts;
    probe::Options probe_opts;

    bool any_stage() const {
        return resolve || takeover || ports || http || dirs || tls || intel || vuln;
    }
};

using ProgressFn = std::function<void(size_t done, size_t total)>;

// Enriches every subdomain and returns the hosts (sorted by name).
std::vector<model::Host> run(const std::set<std::string>& subdomains, const std::string& input,
                             const Options& opts, const ProgressFn& progress = nullptr);

}  // namespace pipeline
