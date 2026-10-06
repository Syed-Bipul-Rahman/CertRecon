#include "resolver.hpp"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>

namespace resolver {

namespace {

// Thread-safe CNAME lookup via a per-call resolver state.
// Appends every CNAME in the chain for `host` to `out`.
// Sets `nxdomain` to true if the name does not exist.
void query_cname(const std::string& host, std::vector<std::string>& out, bool& nxdomain) {
    struct __res_state st;
    std::memset(&st, 0, sizeof st);
    if (res_ninit(&st) != 0) return;
    // Bound DNS latency: 3s per try, 2 tries (defaults are 5s x up to 4).
    st.retrans = 3;
    st.retry = 2;

    std::string name = host;
    // Follow the chain a few hops to avoid loops.
    for (int hop = 0; hop < 10; ++hop) {
        unsigned char answer[NS_PACKETSZ * 4];
        int len = res_nquery(&st, name.c_str(), ns_c_in, ns_t_cname, answer, sizeof answer);
        if (len < 0) {
            if (hop == 0 && st.res_h_errno == HOST_NOT_FOUND) nxdomain = true;
            break;
        }
        ns_msg handle;
        if (ns_initparse(answer, len, &handle) < 0) break;
        int count = ns_msg_count(handle, ns_s_an);
        std::string next;
        for (int i = 0; i < count; ++i) {
            ns_rr rr;
            if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
            if (ns_rr_type(rr) != ns_t_cname) continue;
            char target[NS_MAXDNAME];
            if (dn_expand(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), target,
                          sizeof target) < 0)
                continue;
            next = target;
            break;
        }
        if (next.empty()) break;
        out.push_back(next);
        name = next;
    }
    res_nclose(&st);
}

}  // namespace

model::Dns resolve(const std::string& host) {
    model::Dns dns;

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc == 0) {
        for (auto* p = res; p; p = p->ai_next) {
            char buf[INET6_ADDRSTRLEN] = {0};
            if (p->ai_family == AF_INET) {
                auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof buf)) {
                    std::string ip(buf);
                    if (std::find(dns.a.begin(), dns.a.end(), ip) == dns.a.end())
                        dns.a.push_back(ip);
                }
            } else if (p->ai_family == AF_INET6) {
                auto* sa = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
                if (inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof buf)) {
                    std::string ip(buf);
                    if (std::find(dns.aaaa.begin(), dns.aaaa.end(), ip) == dns.aaaa.end())
                        dns.aaaa.push_back(ip);
                }
            }
        }
        freeaddrinfo(res);
    } else if (rc == EAI_NONAME) {
        dns.nxdomain = true;
    }
    dns.resolved = !dns.a.empty() || !dns.aaaa.empty();

    bool cname_nx = false;
    query_cname(host, dns.cnames, cname_nx);
    if (!dns.resolved && cname_nx) dns.nxdomain = true;

    return dns;
}

bool is_nxdomain(const std::string& host) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc == 0) {
        freeaddrinfo(res);
        return false;
    }
    if (rc == EAI_NONAME) {
        // Confirm via a CNAME query that it is a true NXDOMAIN, not just no A record.
        std::vector<std::string> ignore;
        bool nx = false;
        query_cname(host, ignore, nx);
        return nx || ignore.empty();
    }
    return false;
}

}  // namespace resolver
