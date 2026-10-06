// TCP connect scanner with lightweight banner grabbing / service ID.
#pragma once

#include <string>
#include <vector>

#include "model.hpp"

namespace portscan {

struct Options {
    std::vector<int> ports;     // ports to probe
    int connect_timeout_ms = 2000;
    int banner_timeout_ms = 1500;
    int concurrency = 100;      // simultaneous connections per host
};

// Default set of common ports when the user does not supply their own.
const std::vector<int>& default_ports();

// Parses "80,443,8000-8100" into a sorted, de-duplicated port list.
// Returns false (and leaves `out` untouched) on malformed input.
bool parse_ports(const std::string& spec, std::vector<int>& out);

// Scans `host` (resolving to `ip`) and returns the open ports with any banners.
std::vector<model::Port> scan(const std::string& host, const Options& opts);

}  // namespace portscan
