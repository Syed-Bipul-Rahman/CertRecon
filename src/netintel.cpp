#include "netintel.hpp"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <curl/curl.h>
#include <netdb.h>
#include <resolv.h>
#include <sys/socket.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <vector>

#include "jarm.hpp"
#include "ratelimit.hpp"
#include "version.hpp"

namespace netintel {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    size_t b = s.find_last_not_of(" \t");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

// Issues a TXT query and returns the first TXT record's text.
std::string query_txt(const std::string& name) {
    struct __res_state st;
    std::memset(&st, 0, sizeof st);
    if (res_ninit(&st) != 0) return "";
    unsigned char answer[NS_PACKETSZ * 4];
    std::string result;
    int len = res_nquery(&st, name.c_str(), ns_c_in, ns_t_txt, answer, sizeof answer);
    if (len > 0) {
        ns_msg handle;
        if (ns_initparse(answer, len, &handle) >= 0) {
            int count = ns_msg_count(handle, ns_s_an);
            for (int i = 0; i < count && result.empty(); ++i) {
                ns_rr rr;
                if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
                if (ns_rr_type(rr) != ns_t_txt) continue;
                const unsigned char* rdata = ns_rr_rdata(rr);
                int rdlen = ns_rr_rdlen(rr);
                int p = 0;
                while (p < rdlen) {
                    int txtlen = rdata[p++];
                    if (p + txtlen > rdlen) break;
                    result.append(reinterpret_cast<const char*>(rdata + p), txtlen);
                    p += txtlen;
                }
            }
        }
    }
    res_nclose(&st);
    return result;
}

// Looks up ASN, country and org for an IPv4 address via Team Cymru's DNS service.
void cymru_asn(const std::string& ip, model::NetIntel& intel) {
    // Only IPv4 for the reversed-nibble origin query.
    in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return;
    unsigned char* b = reinterpret_cast<unsigned char*>(&addr);
    std::ostringstream q;
    q << static_cast<int>(b[3]) << "." << static_cast<int>(b[2]) << "." << static_cast<int>(b[1])
      << "." << static_cast<int>(b[0]) << ".origin.asn.cymru.com";
    std::string origin = query_txt(q.str());
    if (origin.empty()) return;

    // "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
    std::vector<std::string> f;
    std::stringstream ss(origin);
    std::string tok;
    while (std::getline(ss, tok, '|')) f.push_back(trim(tok));
    if (!f.empty() && !f[0].empty()) {
        // The first field may hold several ASNs; take the first.
        std::string asn = f[0].substr(0, f[0].find(' '));
        intel.asn = "AS" + asn;
        if (f.size() >= 3) intel.country = f[2];

        std::string as_txt = query_txt("AS" + asn + ".asn.cymru.com");
        if (!as_txt.empty()) {
            // "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
            auto last = as_txt.rfind('|');
            if (last != std::string::npos) intel.asn_org = trim(as_txt.substr(last + 1));
        }
    }
}

void reverse_dns(const std::string& ip, model::NetIntel& intel) {
    struct sockaddr_storage ss;
    std::memset(&ss, 0, sizeof ss);
    socklen_t len = 0;
    in_addr a4;
    in6_addr a6;
    if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) {
        auto* s = reinterpret_cast<sockaddr_in*>(&ss);
        s->sin_family = AF_INET;
        s->sin_addr = a4;
        len = sizeof(sockaddr_in);
    } else if (inet_pton(AF_INET6, ip.c_str(), &a6) == 1) {
        auto* s = reinterpret_cast<sockaddr_in6*>(&ss);
        s->sin6_family = AF_INET6;
        s->sin6_addr = a6;
        len = sizeof(sockaddr_in6);
    } else {
        return;
    }
    char host[NI_MAXHOST];
    if (getnameinfo(reinterpret_cast<sockaddr*>(&ss), len, host, sizeof host, nullptr, 0,
                    NI_NAMEREQD) == 0)
        intel.reverse_dns = host;
}

// CDN/WAF identification from the CNAME chain and HTTP response headers.
std::string detect_cdn(const std::vector<std::string>& cnames, const model::Http& http) {
    struct Sig { const char* needle; const char* name; };
    static const Sig cname_sigs[] = {
        {"cloudflare", "Cloudflare"}, {"akamai", "Akamai"}, {"akamaiedge", "Akamai"},
        {"akamaized", "Akamai"}, {"edgekey", "Akamai"}, {"edgesuite", "Akamai"},
        {"fastly", "Fastly"}, {"cloudfront", "Amazon CloudFront"},
        {"azureedge", "Azure CDN"}, {"azurefd", "Azure Front Door"},
        {"incapdns", "Imperva"}, {"impervadns", "Imperva"},
        {"stackpath", "StackPath"}, {"cdn77", "CDN77"}, {"b-cdn.net", "BunnyCDN"},
        {"llnwd", "Limelight"}, {"edgecastcdn", "Edgecast"}, {"vercel-dns", "Vercel"},
        {"netlify", "Netlify"}, {"github.io", "GitHub Pages"}, {"wpengine", "WP Engine"},
    };
    for (const auto& cn : cnames) {
        std::string l = to_lower(cn);
        for (const auto& s : cname_sigs)
            if (l.find(s.needle) != std::string::npos) return s.name;
    }

    std::string server = to_lower(http.server);
    if (server.find("cloudflare") != std::string::npos) return "Cloudflare";
    if (server.find("akamai") != std::string::npos) return "Akamai";
    if (server.find("vercel") != std::string::npos) return "Vercel";
    if (server.find("awselb") != std::string::npos) return "AWS ELB";

    // Marker headers.
    if (!http.header("cf-ray").empty()) return "Cloudflare";
    if (!http.header("x-amz-cf-id").empty()) return "Amazon CloudFront";
    if (!http.header("x-sucuri-id").empty()) return "Sucuri";
    std::string via = to_lower(http.header("via"));
    if (via.find("varnish") != std::string::npos && !http.header("x-served-by").empty())
        return "Fastly";
    std::string powered = to_lower(http.header("x-powered-by"));
    if (powered.find("aspnet") != std::string::npos) return "";  // not a CDN
    return "";
}

// --- MurmurHash3 x86_32 (for a Shodan-compatible favicon hash) ---
uint32_t rotl32(uint32_t x, int8_t r) { return (x << r) | (x >> (32 - r)); }

int32_t murmur3_32(const std::string& data, uint32_t seed) {
    const uint8_t* d = reinterpret_cast<const uint8_t*>(data.data());
    size_t len = data.size();
    const size_t nblocks = len / 4;
    uint32_t h = seed;
    const uint32_t c1 = 0xcc9e2d51, c2 = 0x1b873593;
    for (size_t i = 0; i < nblocks; ++i) {
        uint32_t k;
        std::memcpy(&k, d + i * 4, 4);
        k *= c1; k = rotl32(k, 15); k *= c2;
        h ^= k; h = rotl32(h, 13); h = h * 5 + 0xe6546b64;
    }
    const uint8_t* tail = d + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= tail[2] << 16; [[fallthrough]];
        case 2: k1 ^= tail[1] << 8; [[fallthrough]];
        case 1: k1 ^= tail[0]; k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; h ^= k1;
    }
    h ^= static_cast<uint32_t>(len);
    h ^= h >> 16; h *= 0x85ebca6b; h ^= h >> 13; h *= 0xc2b2ae35; h ^= h >> 16;
    return static_cast<int32_t>(h);
}

// base64 with a newline every 76 chars + trailing newline (Python encodebytes),
// matching how Shodan computes favicon hashes.
std::string base64_encodebytes(const std::string& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int col = 0;
    auto put = [&](char ch) {
        out += ch;
        if (++col == 76) { out += '\n'; col = 0; }
    };
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        uint32_t n = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8) | uint8_t(in[i + 2]);
        put(tbl[(n >> 18) & 63]); put(tbl[(n >> 12) & 63]);
        put(tbl[(n >> 6) & 63]); put(tbl[n & 63]);
    }
    size_t rem = in.size() - i;
    if (rem == 1) {
        uint32_t n = uint8_t(in[i]) << 16;
        put(tbl[(n >> 18) & 63]); put(tbl[(n >> 12) & 63]); put('='); put('=');
    } else if (rem == 2) {
        uint32_t n = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8);
        put(tbl[(n >> 18) & 63]); put(tbl[(n >> 12) & 63]); put(tbl[(n >> 6) & 63]); put('=');
    }
    out += '\n';
    return out;
}

size_t body_cb(char* p, size_t s, size_t n, void* u) {
    auto* out = static_cast<std::string*>(u);
    out->append(p, s * n);
    return s * n;
}

void favicon_hash(const std::string& base_url, model::NetIntel& intel, long timeout) {
    if (base_url.empty()) return;
    std::string url = base_url;
    if (url.back() != '/') url += '/';
    url += "favicon.ico";

    ratelimit::acquire();
    CURL* c = curl_easy_init();
    if (!c) return;
    std::string body;
    long status = 0;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "certrecon/" CERTRECON_VERSION);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, body_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    if (curl_easy_perform(c) == CURLE_OK) {
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
        if (status == 200 && !body.empty()) {
            int32_t h = murmur3_32(base64_encodebytes(body), 0);
            intel.favicon_hash = std::to_string(h);
        }
    }
    curl_easy_cleanup(c);
}

}  // namespace

void gather(model::Host& host, bool allow_active, long timeout_secs) {
    if (!host.dns.resolved) return;
    std::string ip = !host.dns.a.empty() ? host.dns.a.front()
                                         : (host.dns.aaaa.empty() ? "" : host.dns.aaaa.front());
    host.intel.ip = ip;
    if (!ip.empty()) {
        reverse_dns(ip, host.intel);
        cymru_asn(ip, host.intel);  // IPv4 only; harmless no-op for IPv6
    }
    host.intel.cdn = detect_cdn(host.dns.cnames, host.http);
    if (allow_active) {
        favicon_hash(host.http.url, host.intel, timeout_secs);
        // JARM fingerprints the TLS stack on 443. If a port scan ran and 443 was
        // not open, skip it to avoid 10 pointless handshakes.
        bool attempt = host.ports.empty();  // ports unknown -> attempt anyway
        for (const auto& p : host.ports)
            if (p.port == 443) { attempt = true; break; }
        if (attempt) host.intel.jarm = jarm::fingerprint(host.name, 443, timeout_secs);
    }
}

}  // namespace netintel
