// DNS brute-force subdomain discovery with wildcard-DNS detection.
#pragma once

#include <cstddef>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace dnsbrute {

struct Options {
    std::vector<std::string> wordlist;  // candidate labels; empty => built-in list
    int concurrency = 50;               // parallel DNS lookups
    int wildcard_probes = 4;            // random names used to detect wildcard DNS
};

struct Result {
    std::set<std::string> found;             // discovered FQDNs
    bool wildcard = false;                   // domain has wildcard DNS
    std::vector<std::string> wildcard_ips;   // IPs the wildcard answers with
    size_t tried = 0;                        // candidates attempted
};

// The built-in label list used when Options::wordlist is empty.
const std::vector<std::string>& default_wordlist();

// Progress callback: (labels tried so far, total labels).
using ProgressFn = std::function<void(size_t, size_t)>;

// Resolves <label>.<domain> for every label, filtering wildcard false-positives.
Result run(const std::string& domain, const Options& opts, const ProgressFn& progress = nullptr);

}  // namespace dnsbrute
