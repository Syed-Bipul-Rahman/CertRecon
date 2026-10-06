#include "tlsinfo.hpp"

#include <curl/curl.h>
#include <time.h>

#include <algorithm>
#include <cctype>
#include <cstring>

#include "ratelimit.hpp"
#include "version.hpp"

namespace tlsinfo {

namespace {

size_t discard_cb(char*, size_t size, size_t nmemb, void*) { return size * nmemb; }

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Strips a known "Key:" prefix from a certinfo line.
bool strip_prefix(const std::string& line, const char* prefix, std::string& out) {
    size_t n = std::strlen(prefix);
    if (line.size() >= n && line.compare(0, n, prefix) == 0) {
        out = line.substr(n);
        return true;
    }
    return false;
}

// Parses "Nov 29 23:59:59 2026 GMT" into days-from-now (negative if expired).
int days_until(const std::string& expire) {
    struct tm tm;
    std::memset(&tm, 0, sizeof tm);
    if (strptime(expire.c_str(), "%b %d %H:%M:%S %Y", &tm) == nullptr) return -9999;
    time_t exp = timegm(&tm);
    if (exp == static_cast<time_t>(-1)) return -9999;
    double secs = difftime(exp, time(nullptr));
    return static_cast<int>(secs / 86400.0);
}

void parse_sans(const std::string& field, std::vector<std::string>& out) {
    // field looks like: "DNS:a.com, DNS:b.com, IP Address:1.2.3.4"
    size_t pos = 0;
    while (pos < field.size()) {
        size_t comma = field.find(',', pos);
        std::string tok = field.substr(pos, comma == std::string::npos ? std::string::npos
                                                                        : comma - pos);
        pos = comma == std::string::npos ? field.size() : comma + 1;
        // trim
        size_t a = tok.find_first_not_of(" \t");
        if (a == std::string::npos) continue;
        tok = tok.substr(a);
        if (tok.rfind("DNS:", 0) == 0) {
            std::string name = to_lower(tok.substr(4));
            while (!name.empty() && (name.back() == ' ' || name.back() == '.')) name.pop_back();
            if (name.rfind("*.", 0) == 0) name.erase(0, 2);
            if (!name.empty() &&
                std::find(out.begin(), out.end(), name) == out.end())
                out.push_back(name);
        }
    }
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace

void inspect(model::Host& host, const std::string& apex, long timeout_secs) {
    ratelimit::acquire();
    CURL* c = curl_easy_init();
    if (!c) return;

    std::string url = "https://" + host.name + "/";
    curl_easy_reset(c);
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_CERTINFO, 1L);
    curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_secs);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "certrecon/" CERTRECON_VERSION);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, discard_cb);

    CURLcode rc = curl_easy_perform(c);
    struct curl_certinfo* ci = nullptr;
    if (rc == CURLE_OK && curl_easy_getinfo(c, CURLINFO_CERTINFO, &ci) == CURLE_OK && ci &&
        ci->num_of_certs > 0) {
        model::Tls& tls = host.tls;
        for (struct curl_slist* s = ci->certinfo[0]; s; s = s->next) {
            std::string line = s->data;
            std::string v;
            if (strip_prefix(line, "Subject:", v)) {
                // Pull CN= out of the subject DN.
                auto p = v.find("CN = ");
                if (p == std::string::npos) p = v.find("CN=");
                if (p != std::string::npos) {
                    std::string cn = v.substr(v.find('=', p) + 1);
                    size_t a = cn.find_first_not_of(' ');
                    if (a != std::string::npos) tls.subject_cn = cn.substr(a);
                }
            } else if (strip_prefix(line, "Issuer:", v)) {
                tls.issuer = v;
            } else if (strip_prefix(line, "Expire date:", v)) {
                tls.not_after = v;
                tls.days_left = days_until(v);
            } else if (strip_prefix(line, "X509v3 Subject Alternative Name:", v)) {
                parse_sans(v, tls.sans);
            }
        }
        tls.present = true;

        // Harvest SANs that are new subdomains of the apex.
        std::string suffix = "." + apex;
        for (const auto& san : tls.sans)
            if ((san == apex || ends_with(san, suffix)) && san != host.name)
                host.harvested.push_back(san);

        // Expiry findings.
        if (tls.days_left != -9999) {
            if (tls.days_left < 0) {
                host.findings.push_back({model::Severity::Medium, "Expired TLS certificate",
                                         host.name + " presents a certificate that expired on " +
                                             tls.not_after + ".",
                                         "Renew/replace the certificate."});
            } else if (tls.days_left <= 14) {
                host.findings.push_back(
                    {model::Severity::Low, "TLS certificate expiring soon",
                     host.name + " certificate expires in " + std::to_string(tls.days_left) +
                         " day(s) (" + tls.not_after + ").",
                     "Renew the certificate before it lapses."});
            }
        }
    }
    curl_easy_cleanup(c);
}

}  // namespace tlsinfo
