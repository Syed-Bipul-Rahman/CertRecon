#include "vulncheck.hpp"

#include <curl/curl.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "ratelimit.hpp"
#include "version.hpp"

namespace vulncheck {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool port_open(const model::Host& h, int port) {
    for (const auto& p : h.ports)
        if (p.port == port) return true;
    return false;
}

// --- Security-header audit (uses the already-captured response) ---
void check_security_headers(model::Host& h) {
    if (!h.http.alive) return;
    const auto& http = h.http;
    std::vector<std::string> missing;

    if (http.header("strict-transport-security").empty() && http.url.rfind("https://", 0) == 0)
        missing.push_back("Strict-Transport-Security");
    if (http.header("content-security-policy").empty()) missing.push_back("Content-Security-Policy");

    std::string csp = to_lower(http.header("content-security-policy"));
    if (http.header("x-frame-options").empty() && csp.find("frame-ancestors") == std::string::npos)
        missing.push_back("X-Frame-Options");
    if (to_lower(http.header("x-content-type-options")).find("nosniff") == std::string::npos)
        missing.push_back("X-Content-Type-Options");

    if (!missing.empty()) {
        std::string list;
        for (size_t i = 0; i < missing.size(); ++i) list += (i ? ", " : "") + missing[i];
        h.findings.push_back(
            {model::Severity::Low, "Missing security headers",
             h.name + " is missing: " + list + ".",
             "Add the missing headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options: "
             "nosniff)."});
    }
}

size_t body_cb(char* p, size_t s, size_t n, void* u) {
    auto* out = static_cast<std::string*>(u);
    if (out->size() < 64 * 1024) out->append(p, std::min(s * n, 64 * 1024 - out->size()));
    return s * n;
}
size_t hdr_cb(char* p, size_t s, size_t n, void* u) {
    static_cast<std::string*>(u)->append(p, s * n);
    return s * n;
}

struct Resp {
    long status = 0;
    std::string body;
    std::string headers;  // raw, lowercased
};

bool http_get(const std::string& url, long timeout, Resp& out, const char* origin = nullptr) {
    ratelimit::acquire();
    CURL* c = curl_easy_init();
    if (!c) return false;
    std::string raw_headers;
    struct curl_slist* hdrs = nullptr;
    if (origin) hdrs = curl_slist_append(hdrs, (std::string("Origin: ") + origin).c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "certrecon/" CERTRECON_VERSION);
    if (hdrs) curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, body_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out.body);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, hdr_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &raw_headers);
    bool ok = curl_easy_perform(c) == CURLE_OK;
    if (ok) curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &out.status);
    out.headers = to_lower(raw_headers);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return ok;
}

// --- CORS misconfiguration ---
void check_cors(model::Host& h, long timeout) {
    if (!h.http.alive || h.http.url.empty()) return;
    const char* evil = "https://certrecon-cors-probe.example";
    Resp r;
    if (!http_get(h.http.url, timeout, r, evil)) return;

    auto find_header = [&](const std::string& key) -> std::string {
        size_t p = r.headers.find("\n" + key + ":");
        if (p == std::string::npos && r.headers.rfind(key + ":", 0) == 0) p = 0;
        else if (p != std::string::npos) p += 1;
        if (p == std::string::npos) return "";
        size_t colon = r.headers.find(':', p);
        size_t eol = r.headers.find('\n', colon);
        std::string v = r.headers.substr(colon + 1, eol - colon - 1);
        size_t a = v.find_first_not_of(" \t\r");
        size_t b = v.find_last_not_of(" \t\r");
        return a == std::string::npos ? "" : v.substr(a, b - a + 1);
    };

    std::string acao = find_header("access-control-allow-origin");
    std::string acac = find_header("access-control-allow-credentials");
    if (acao.empty()) return;

    bool reflects = acao.find("certrecon-cors-probe.example") != std::string::npos;
    bool creds = acac.find("true") != std::string::npos;
    if (reflects && creds) {
        h.findings.push_back(
            {model::Severity::High, "CORS misconfiguration (reflected origin + credentials)",
             h.name + " reflects an arbitrary Origin in Access-Control-Allow-Origin with "
                      "Access-Control-Allow-Credentials: true.",
             "Restrict ACAO to a trusted allowlist; never reflect arbitrary origins with "
             "credentials enabled."});
    } else if (reflects) {
        h.findings.push_back(
            {model::Severity::Medium, "CORS reflects arbitrary origin",
             h.name + " reflects any Origin in Access-Control-Allow-Origin.",
             "Reflect only trusted origins from an allowlist."});
    } else if (acao == "*" && creds) {
        h.findings.push_back({model::Severity::Medium, "CORS wildcard with credentials",
                              h.name + " returns Access-Control-Allow-Origin: * with credentials.",
                              "Do not combine a wildcard ACAO with credentialed requests."});
    }
}

// --- Exposed sensitive files (content-confirmed) ---
void check_exposed_files(model::Host& h, long timeout) {
    if (!h.http.alive || h.http.url.empty()) return;
    std::string base = h.http.url;
    if (base.back() != '/') base += '/';

    Resp git;
    if (http_get(base + ".git/HEAD", timeout, git) && git.status == 200 &&
        git.body.rfind("ref:", 0) == 0) {
        h.findings.push_back(
            {model::Severity::High, "Exposed .git repository",
             h.name + " serves /.git/HEAD - the source repository is publicly accessible.",
             "Block access to /.git/ at the web server, or remove it from the web root."});
    }

    Resp env;
    if (http_get(base + ".env", timeout, env) && env.status == 200) {
        // Confirm it looks like a dotenv file (KEY=VALUE lines), not an HTML page.
        const std::string& b = env.body;
        bool looks_env = b.find('<') == std::string::npos &&
                         (b.find("=\n") != std::string::npos || b.find('=') != std::string::npos) &&
                         (b.find("APP_") != std::string::npos || b.find("KEY") != std::string::npos ||
                          b.find("SECRET") != std::string::npos || b.find("DB_") != std::string::npos ||
                          b.find("PASSWORD") != std::string::npos || b.find("TOKEN") != std::string::npos);
        if (looks_env)
            h.findings.push_back(
                {model::Severity::High, "Exposed .env file",
                 h.name + " serves /.env which appears to contain environment secrets.",
                 "Remove /.env from the web root and rotate any exposed credentials."});
    }
}

// --- Raw TCP helper for service probes ---
int connect_tcp(const std::string& host, int port, int timeout_ms) {
    ratelimit::acquire();
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return -1;
    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc == 0) { fcntl(fd, F_SETFL, flags); break; }
        if (errno != EINPROGRESS) { close(fd); fd = -1; continue; }
        struct pollfd pfd{fd, POLLOUT, 0};
        if (poll(&pfd, 1, timeout_ms) <= 0) { close(fd); fd = -1; continue; }
        int err = 0; socklen_t len = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) { close(fd); fd = -1; continue; }
        fcntl(fd, F_SETFL, flags);
        break;
    }
    freeaddrinfo(res);
    return fd;
}

std::string sock_exchange(int fd, const std::string& send_data, int timeout_ms) {
    if (!send_data.empty()) send(fd, send_data.data(), send_data.size(), 0);
    struct pollfd pfd{fd, POLLIN, 0};
    if (poll(&pfd, 1, timeout_ms) <= 0) return "";
    char buf[1024];
    ssize_t n = recv(fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return "";
    return std::string(buf, static_cast<size_t>(n));
}

// --- Unauthenticated services (Redis, Elasticsearch) ---
// Only probes services on ports already confirmed open by the port scanner, so
// --vuln without --ports stays fast and quiet (no blind connects to every host).
void check_open_services(model::Host& h, long timeout) {
    // Redis (6379): an unauthenticated server replies +PONG to PING.
    if (port_open(h, 6379)) {
        int fd = connect_tcp(h.name, 6379, 2000);
        if (fd >= 0) {
            std::string resp = sock_exchange(fd, "PING\r\n", 1500);
            close(fd);
            if (resp.rfind("+PONG", 0) == 0)
                h.findings.push_back(
                    {model::Severity::High, "Unauthenticated Redis",
                     h.name + ":6379 answers PING without authentication.",
                     "Enable requirepass/ACLs and firewall the port; never expose Redis publicly."});
        }
    }

    // Elasticsearch (9200): an open node returns cluster JSON on GET /.
    if (port_open(h, 9200)) {
        Resp r;
        if (http_get("http://" + h.name + ":9200/", timeout, r) && r.status == 200 &&
            r.body.find("cluster_name") != std::string::npos &&
            r.body.find("number") != std::string::npos) {
            h.findings.push_back(
                {model::Severity::High, "Exposed Elasticsearch",
                 h.name + ":9200 is reachable without authentication and returns cluster info.",
                 "Restrict access, enable security/auth, and firewall port 9200."});
        }
    }
}

}  // namespace

void check(model::Host& host, bool allow_active, long timeout_secs) {
    check_security_headers(host);  // passive: uses captured response
    if (!allow_active) return;
    check_cors(host, timeout_secs);
    check_exposed_files(host, timeout_secs);
    if (host.dns.resolved) check_open_services(host, timeout_secs);
}

}  // namespace vulncheck
