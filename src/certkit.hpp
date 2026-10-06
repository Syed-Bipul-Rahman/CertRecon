// Certificate Transparency source: https://ct.certkit.io/search
#pragma once

#include <cstddef>
#include <functional>
#include <set>
#include <string>

namespace certkit {

struct Options {
    int threads = 3;            // concurrent page fetches (API allows ~3)
    long timeout_secs = 60;     // per-request timeout
    int retries = 3;            // retries per page on failure / rate limit
    size_t max_results = 0;     // 0 = fetch every certificate the API reports
    bool keep_wildcards = false;  // keep "*.foo.example.com" instead of stripping "*."
};

struct ScanStats {
    size_t total_certs = 0;    // totalCount reported by the API
    size_t fetched_certs = 0;  // certificates actually downloaded
    size_t failed_pages = 0;
    std::string last_error;    // reason for the first failed page, if any
};

// Progress callback: (certificates fetched so far, total to fetch).
using ProgressFn = std::function<void(size_t, size_t)>;

// Returns the unique, lowercased subdomains of `domain` found in CT logs.
// Throws std::runtime_error if the first request fails.
std::set<std::string> scan(const std::string& domain, const Options& opts,
                           ScanStats& stats, const ProgressFn& progress = nullptr);

// Lowercases, trims and strips scheme/path/port from user input
// ("https://Google.com/foo" -> "google.com"). Returns "" if invalid.
std::string normalize_domain(std::string input);

}  // namespace certkit
