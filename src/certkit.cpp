#include "certkit.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <functional>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include "http.hpp"
#include "json.hpp"

namespace certkit {

namespace {

constexpr const char* kEndpoint = "https://ct.certkit.io/search";
constexpr size_t kPageSize = 2000;  // server-side maximum for "limit"

// Shared across worker threads: when any request is rate-limited (HTTP 429),
// every thread waits until the cooldown expires before sending again.
class RateGate {
public:
    void wait() {
        for (;;) {
            auto until = std::chrono::steady_clock::time_point(
                std::chrono::steady_clock::duration(not_before_.load()));
            auto now = std::chrono::steady_clock::now();
            if (now >= until) return;
            std::this_thread::sleep_for(until - now);
        }
    }

    void cooldown(std::chrono::milliseconds d) {
        auto target = (std::chrono::steady_clock::now() + d).time_since_epoch().count();
        auto cur = not_before_.load();
        while (cur < target && !not_before_.compare_exchange_weak(cur, target)) {
        }
    }

private:
    std::atomic<std::chrono::steady_clock::rep> not_before_{0};
};

constexpr int kMaxRateLimitRetries = 10;

struct Page {
    size_t total = 0;
    size_t count = 0;
};

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool valid_hostname_chars(const std::string& s) {
    if (s.empty() || s.size() > 253) return false;
    for (unsigned char c : s) {
        if (!(std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '*')) return false;
    }
    return true;
}

// Cleans one name from a certificate and, if it belongs to `domain`, inserts it.
void consider(std::string name, const std::string& domain, bool keep_wildcards,
              std::set<std::string>& out) {
    name = to_lower(name);
    while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back()))) name.pop_back();
    while (!name.empty() && name.back() == '.') name.pop_back();
    if (!keep_wildcards) {
        while (name.rfind("*.", 0) == 0) name.erase(0, 2);
    }
    if (!valid_hostname_chars(name)) return;
    if (!keep_wildcards && name.find('*') != std::string::npos) return;
    if (name == domain || ends_with(name, "." + domain)) out.insert(std::move(name));
}

std::string build_payload(const std::string& domain, size_t offset, size_t limit) {
    return "{\"domain\":\"" + json::escape(domain) + "\",\"sort\":\"\",\"limit\":" +
           std::to_string(limit) + ",\"offset\":" + std::to_string(offset) + "}";
}

// Fetches one page with retries. Returns false if every attempt failed.
bool fetch_page(http::Client& client, const std::string& domain, size_t offset, size_t limit,
                const Options& opts, RateGate& gate, std::set<std::string>& names, Page& page,
                std::string& last_error) {
    int errors = 0;       // transport / 5xx / parse failures
    int rate_limits = 0;  // HTTP 429 responses (separate, larger budget)
    for (;;) {
        gate.wait();
        http::Response res = client.post_json(kEndpoint, build_payload(domain, offset, limit));

        if (res.error.empty() && res.status == 429) {
            last_error = "rate limited (HTTP 429)";
            if (++rate_limits > kMaxRateLimitRetries) return false;
            // 2s, 4s, 8s ... capped at 30s, plus jitter so threads don't stampede.
            long base_ms = std::min(30000L, 1000L << std::min(rate_limits, 5));
            long jitter_ms = static_cast<long>(std::hash<std::thread::id>{}(
                                 std::this_thread::get_id()) % 750);
            gate.cooldown(std::chrono::milliseconds(base_ms + jitter_ms));
            continue;
        }

        bool ok = false;
        if (!res.error.empty()) {
            last_error = res.error;
        } else if (res.status != 200) {
            last_error = "HTTP " + std::to_string(res.status);
            // Other 4xx errors won't fix themselves.
            if (res.status >= 400 && res.status < 500) return false;
        } else {
            ok = true;
        }
        if (!ok) {
            if (++errors > opts.retries) return false;
            // Exponential backoff: 1s, 2s, 4s, ...
            std::this_thread::sleep_for(std::chrono::seconds(1LL << (errors - 1)));
            continue;
        }
        try {
            json::Value root = json::parse(res.body);
            if (const auto* tc = root.get("totalCount"); tc && tc->is_number())
                page.total = static_cast<size_t>(tc->num);
            const auto* results = root.get("results");
            if (!results || !results->is_array()) {
                page.count = 0;
                return true;  // no results ("results": null)
            }
            page.count = results->arr.size();
            for (const auto& cert : results->arr) {
                if (const auto* cn = cert.get("commonName"); cn && cn->is_string())
                    consider(cn->str, domain, opts.keep_wildcards, names);
                if (const auto* dns = cert.get("dnsNames"); dns && dns->is_array()) {
                    for (const auto& n : dns->arr)
                        if (n.is_string()) consider(n.str, domain, opts.keep_wildcards, names);
                }
            }
            return true;
        } catch (const std::exception& e) {
            last_error = e.what();
            if (++errors > opts.retries) return false;
        }
    }
}

}  // namespace

std::string normalize_domain(std::string input) {
    input = to_lower(input);
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    input.erase(input.begin(), std::find_if(input.begin(), input.end(), not_space));
    input.erase(std::find_if(input.rbegin(), input.rend(), not_space).base(), input.end());

    if (auto p = input.find("://"); p != std::string::npos) input.erase(0, p + 3);
    if (auto p = input.find_first_of("/?#"); p != std::string::npos) input.erase(p);
    if (auto p = input.find('@'); p != std::string::npos) input.erase(0, p + 1);
    if (auto p = input.find(':'); p != std::string::npos) input.erase(p);
    while (input.rfind("*.", 0) == 0) input.erase(0, 2);
    while (!input.empty() && input.back() == '.') input.pop_back();

    if (input.find('.') == std::string::npos || !valid_hostname_chars(input) ||
        input.find('*') != std::string::npos)
        return "";
    return input;
}

std::set<std::string> scan(const std::string& domain, const Options& opts, ScanStats& stats,
                           const ProgressFn& progress) {
    std::set<std::string> names;
    stats = {};

    // First page: discover how many certificates exist.
    size_t first_limit = kPageSize;
    if (opts.max_results > 0) first_limit = std::min(first_limit, opts.max_results);
    Page first;
    std::string err;
    RateGate gate;
    {
        http::Client client(opts.timeout_secs);
        if (!fetch_page(client, domain, 0, first_limit, opts, gate, names, first, err))
            throw std::runtime_error("request to certkit failed: " + err);
    }
    stats.total_certs = first.total;
    stats.fetched_certs = first.count;

    size_t target = first.total;
    if (opts.max_results > 0) target = std::min(target, opts.max_results);
    if (progress) progress(stats.fetched_certs, target);
    if (first.count == 0 || first.count >= target) return names;

    // Remaining pages, fetched concurrently.
    std::vector<size_t> offsets;
    for (size_t off = first.count; off < target; off += kPageSize) offsets.push_back(off);

    std::atomic<size_t> next{0};
    std::atomic<size_t> fetched{stats.fetched_certs};
    std::atomic<size_t> failed{0};
    std::mutex mu;  // guards `names` and progress output

    auto worker = [&] {
        http::Client client(opts.timeout_secs);
        std::set<std::string> local;
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= offsets.size()) break;
            size_t off = offsets[i];
            size_t limit = std::min(kPageSize, target - off);
            Page page;
            std::string perr;
            if (fetch_page(client, domain, off, limit, opts, gate, local, page, perr)) {
                size_t now = fetched.fetch_add(page.count) + page.count;
                if (progress) {
                    std::lock_guard<std::mutex> lk(mu);
                    progress(now, target);
                }
            } else {
                failed.fetch_add(1);
                std::lock_guard<std::mutex> lk(mu);
                if (stats.last_error.empty()) stats.last_error = perr;
            }
        }
        std::lock_guard<std::mutex> lk(mu);
        names.merge(local);
    };

    int n = std::max(1, std::min<int>(opts.threads, static_cast<int>(offsets.size())));
    std::vector<std::thread> pool;
    pool.reserve(n);
    for (int i = 0; i < n; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    stats.fetched_certs = fetched.load();
    stats.failed_pages = failed.load();
    return names;
}

}  // namespace certkit
