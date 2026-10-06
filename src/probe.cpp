#include "probe.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>

#include "ratelimit.hpp"
#include "techfp.hpp"
#include "version.hpp"

namespace probe {

namespace {

constexpr size_t kMaxBody = 256 * 1024;  // cap body we read for title/fingerprints

struct Capture {
    std::string body;
    std::string server;
    std::string location;
    std::vector<std::pair<std::string, std::string>> headers;  // lowercased keys
    bool body_full = false;
};

size_t body_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* cap = static_cast<Capture*>(userdata);
    size_t total = size * nmemb;
    if (!cap->body_full) {
        size_t room = kMaxBody - cap->body.size();
        cap->body.append(ptr, std::min(total, room));
        if (cap->body.size() >= kMaxBody) cap->body_full = true;
    }
    return total;  // keep draining so the transfer completes cleanly
}

size_t header_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* cap = static_cast<Capture*>(userdata);
    size_t total = size * nmemb;
    std::string line(ptr, total);
    auto lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    };
    auto trim = [](std::string& s) {
        while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
        size_t p = s.find_first_not_of(' ');
        if (p != std::string::npos) s.erase(0, p);
    };
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = lower(line.substr(0, colon));
        std::string val = line.substr(colon + 1);
        trim(val);
        if (key == "set-cookie") {
            // A response sets many cookies; keep them all (joined) so cookie-name
            // fingerprints can see every cookie, not just the last.
            bool merged = false;
            for (auto& kv : cap->headers)
                if (kv.first == key) { kv.second += "; " + val; merged = true; break; }
            if (!merged) cap->headers.emplace_back(key, val);
        } else {
            // On redirects curl replays headers; keep the latest value per key.
            cap->headers.erase(std::remove_if(cap->headers.begin(), cap->headers.end(),
                                              [&](const auto& kv) { return kv.first == key; }),
                               cap->headers.end());
            cap->headers.emplace_back(key, val);
        }
        if (key == "server") cap->server = val;
        else if (key == "location") cap->location = val;
    }
    return total;
}

std::string extract_title(const std::string& body) {
    auto lower_find = [&](const char* needle, size_t from) {
        std::string hay = body;
        std::transform(hay.begin(), hay.end(), hay.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return hay.find(needle, from);
    };
    size_t open = lower_find("<title", 0);
    if (open == std::string::npos) return "";
    size_t gt = body.find('>', open);
    if (gt == std::string::npos) return "";
    size_t close = lower_find("</title>", gt);
    if (close == std::string::npos) return "";
    std::string title = body.substr(gt + 1, close - gt - 1);
    // Collapse whitespace.
    std::string out;
    bool space = false;
    for (char c : title) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            space = true;
        } else {
            if (space && !out.empty()) out += ' ';
            space = false;
            out += c;
        }
    }
    if (out.size() > 120) out = out.substr(0, 117) + "...";
    return out;
}

// Performs one request. Returns true if a response was received.
bool request(CURL* c, const std::string& url, long timeout, bool head, bool follow,
             long& status, Capture& cap, std::string& final_url) {
    ratelimit::acquire();
    curl_easy_reset(c);
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    if (head) curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, follow ? 1L : 0L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_USERAGENT,
                     "Mozilla/5.0 (compatible; certrecon/" CERTRECON_VERSION ")");
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);  // recon: don't fail on bad certs
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &cap);
    if (!head) {
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, body_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &cap);
    }
    if (curl_easy_perform(c) != CURLE_OK) return false;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    char* eff = nullptr;
    if (curl_easy_getinfo(c, CURLINFO_EFFECTIVE_URL, &eff) == CURLE_OK && eff) final_url = eff;
    return true;
}

}  // namespace

const std::vector<std::string>& default_wordlist() {
    static const std::vector<std::string> w = {
        ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
        "admin", "admin/login", "administrator", "api", "api/v1", "app",
        "backup", "backup.zip", "backup.sql", "config", "config.php",
        "dashboard", "db", "debug", "dev", "docs", "login", "logout",
        "phpinfo.php", "robots.txt", "sitemap.xml", "server-status",
        "status", "health", "healthz", "metrics", "actuator", "actuator/health",
        "swagger", "swagger-ui.html", "api-docs", "graphql",
        "test", "tmp", "uploads", "upload", "wp-admin", "wp-login.php",
        ".DS_Store", "web.config", "crossdomain.xml", ".well-known/security.txt",
        "console", "private", "secret", "old", "new", "staging",
    };
    return w;
}

void http_probe(const std::string& host, const Options& opts, model::Http& out) {
    CURL* c = curl_easy_init();
    if (!c) return;

    // Try https first, then http.
    for (const char* scheme : {"https://", "http://"}) {
        std::string url = std::string(scheme) + host + "/";
        Capture cap;
        long status = 0;
        std::string final_url = url;
        if (!request(c, url, opts.timeout_secs, /*head=*/false, opts.follow_redirects, status, cap,
                     final_url))
            continue;
        if (status == 0) continue;

        out.alive = true;
        out.url = final_url;
        out.status = status;
        out.server = cap.server;
        out.title = extract_title(cap.body);
        out.content_length = static_cast<long>(cap.body.size());
        if (!opts.follow_redirects && !cap.location.empty()) out.redirect = cap.location;
        out.headers = cap.headers;
        out.tech = techfp::detect(cap.headers, cap.body);
        break;  // first scheme that answers wins
    }
    curl_easy_cleanup(c);
}

void dir_bruteforce(const model::Http& http, const Options& opts, std::vector<model::Dir>& out) {
    if (!http.alive || http.url.empty()) return;
    const auto& words = opts.wordlist.empty() ? default_wordlist() : opts.wordlist;

    std::string base = http.url;
    if (base.back() != '/') base += '/';

    // Baseline: request a path that should not exist to detect wildcard/soft-404s.
    long baseline_status = 0;
    long baseline_len = -1;
    {
        CURL* c = curl_easy_init();
        if (c) {
            Capture cap;
            long status = 0;
            std::string fu;
            std::string probe_url = base + "certrecon-nonexistent-a9f3c71b2e";
            if (request(c, probe_url, opts.timeout_secs, false, true, status, cap, fu)) {
                baseline_status = status;
                baseline_len = static_cast<long>(cap.body.size());
            }
            curl_easy_cleanup(c);
        }
    }

    std::mutex mu;
    std::atomic<size_t> next{0};

    auto worker = [&] {
        CURL* c = curl_easy_init();
        if (!c) return;
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= words.size()) break;
            std::string path = words[i];
            while (!path.empty() && path.front() == '/') path.erase(0, 1);
            std::string url = base + path;
            Capture cap;
            long status = 0;
            std::string fu;
            if (!request(c, url, opts.timeout_secs, /*head=*/false, /*follow=*/false, status, cap,
                         fu))
                continue;
            long len = static_cast<long>(cap.body.size());

            bool interesting = false;
            switch (status) {
                case 200: case 201: case 202: case 204:
                case 301: case 302: case 307: case 308:
                case 401: case 403: case 405: case 500:
                    interesting = true;
                    break;
                default:
                    interesting = false;
            }
            // Filter soft-404s: same status+size as the baseline non-existent path.
            if (interesting && status == baseline_status && len == baseline_len &&
                (status == 200 || status == 301 || status == 302))
                interesting = false;

            if (interesting) {
                model::Dir d;
                d.path = "/" + path;
                d.status = status;
                d.length = len;
                std::lock_guard<std::mutex> lk(mu);
                out.push_back(std::move(d));
            }
        }
        curl_easy_cleanup(c);
    };

    int n = std::max(1, std::min<int>(opts.dir_concurrency, static_cast<int>(words.size())));
    std::vector<std::thread> pool;
    pool.reserve(n);
    for (int i = 0; i < n; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    std::sort(out.begin(), out.end(),
              [](const model::Dir& a, const model::Dir& b) { return a.path < b.path; });
}

}  // namespace probe
