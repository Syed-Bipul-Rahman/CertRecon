#include "report.hpp"

#include <sstream>

#include "json.hpp"

namespace report {

namespace {

struct Palette {
    const char *reset, *bold, *dim, *red, *green, *yellow, *cyan, *magenta;
    explicit Palette(bool color) {
        reset = color ? "\033[0m" : "";
        bold = color ? "\033[1m" : "";
        dim = color ? "\033[2m" : "";
        red = color ? "\033[31m" : "";
        green = color ? "\033[32m" : "";
        yellow = color ? "\033[33m" : "";
        cyan = color ? "\033[36m" : "";
        magenta = color ? "\033[35m" : "";
    }
};

const char* severity_color(model::Severity s, const Palette& p) {
    switch (s) {
        case model::Severity::High: return p.red;
        case model::Severity::Medium: return p.yellow;
        case model::Severity::Low: return p.cyan;
        default: return p.dim;
    }
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

}  // namespace

std::string human(const model::Host& h, bool color) {
    Palette p(color);
    std::ostringstream o;

    // Header: name + primary IP (or a dim "no DNS" marker).
    o << p.bold << p.cyan << "▸ " << h.name << p.reset;
    if (h.dns.resolved) {
        std::string ip = !h.dns.a.empty() ? h.dns.a.front()
                                          : (!h.dns.aaaa.empty() ? h.dns.aaaa.front() : "");
        if (!ip.empty()) o << "  " << p.dim << "[" << ip << "]" << p.reset;
    } else if (h.dns.nxdomain) {
        o << "  " << p.dim << "(NXDOMAIN)" << p.reset;
    } else {
        o << "  " << p.dim << "(no A/AAAA)" << p.reset;
    }
    o << "\n";

    if (h.http.alive) {
        o << "    " << p.green << "HTTP " << p.reset << h.http.status << "  " << h.http.url;
        if (!h.http.title.empty()) o << "  " << p.dim << "\"" << h.http.title << "\"" << p.reset;
        if (!h.http.server.empty()) o << "  (" << h.http.server << ")";
        if (!h.http.tech.empty()) o << " " << p.magenta << "[" << join(h.http.tech, ", ") << "]"
                                    << p.reset;
        o << "\n";
    }

    if (!h.ports.empty()) {
        o << "    " << p.green << "PORTS" << p.reset << " ";
        for (size_t i = 0; i < h.ports.size(); ++i) {
            if (i) o << ", ";
            o << h.ports[i].port << "/" << h.ports[i].service;
        }
        o << "\n";
        for (const auto& port : h.ports)
            if (!port.banner.empty())
                o << "          " << p.dim << port.port << ": " << port.banner << p.reset << "\n";
    }

    if (!h.dns.cnames.empty())
        o << "    " << p.green << "CNAME" << p.reset << " " << h.name << " -> "
          << join(h.dns.cnames, " -> ") << "\n";

    if (h.tls.present) {
        o << "    " << p.green << "TLS  " << p.reset;
        if (!h.tls.subject_cn.empty()) o << " CN=" << h.tls.subject_cn;
        if (!h.tls.issuer.empty()) o << "  " << p.dim << "issuer: " << h.tls.issuer << p.reset;
        if (!h.tls.not_after.empty()) {
            o << "  expires " << h.tls.not_after;
            if (h.tls.days_left != -9999) o << " (" << h.tls.days_left << "d)";
        }
        o << "\n";
    }

    const auto& in = h.intel;
    if (!in.reverse_dns.empty() || !in.asn.empty() || !in.cdn.empty() || !in.favicon_hash.empty()) {
        o << "    " << p.green << "INTEL" << p.reset << " ";
        std::vector<std::string> bits;
        if (!in.reverse_dns.empty()) bits.push_back("PTR " + in.reverse_dns);
        if (!in.asn.empty()) {
            std::string a = in.asn;
            if (!in.asn_org.empty()) a += " (" + in.asn_org + ")";
            if (!in.country.empty()) a += " " + in.country;
            bits.push_back(a);
        }
        if (!in.cdn.empty()) bits.push_back("CDN: " + in.cdn);
        if (!in.favicon_hash.empty()) bits.push_back("favicon: " + in.favicon_hash);
        o << join(bits, "  ") << "\n";
    }

    if (!h.dirs.empty()) {
        o << "    " << p.green << "DIRS " << p.reset << " ";
        for (size_t i = 0; i < h.dirs.size(); ++i) {
            if (i) o << ", ";
            o << h.dirs[i].path << " (" << h.dirs[i].status << ")";
        }
        o << "\n";
    }

    for (const auto& f : h.findings) {
        o << "    " << severity_color(f.severity, p) << p.bold << "["
          << model::severity_label(f.severity) << "] " << f.title << p.reset << "\n";
        o << "          " << f.detail << "\n";
        if (!f.suggestion.empty())
            o << "          " << p.dim << "↳ fix: " << f.suggestion << p.reset << "\n";
    }

    return o.str();
}

std::string json(const model::Host& h) {
    std::ostringstream o;
    auto arr = [&](const std::vector<std::string>& v) {
        o << "[";
        for (size_t i = 0; i < v.size(); ++i) {
            if (i) o << ",";
            o << "\"" << json::escape(v[i]) << "\"";
        }
        o << "]";
    };

    o << "{\"host\":\"" << json::escape(h.name) << "\",\"input\":\"" << json::escape(h.input)
      << "\",\"source\":\"certkit\"";

    o << ",\"dns\":{\"resolved\":" << (h.dns.resolved ? "true" : "false")
      << ",\"nxdomain\":" << (h.dns.nxdomain ? "true" : "false") << ",\"a\":";
    arr(h.dns.a);
    o << ",\"aaaa\":";
    arr(h.dns.aaaa);
    o << ",\"cname\":";
    arr(h.dns.cnames);
    o << "}";

    o << ",\"ports\":[";
    for (size_t i = 0; i < h.ports.size(); ++i) {
        if (i) o << ",";
        o << "{\"port\":" << h.ports[i].port << ",\"service\":\""
          << json::escape(h.ports[i].service) << "\",\"banner\":\""
          << json::escape(h.ports[i].banner) << "\"}";
    }
    o << "]";

    o << ",\"http\":";
    if (h.http.alive) {
        o << "{\"alive\":true,\"status\":" << h.http.status << ",\"url\":\""
          << json::escape(h.http.url) << "\",\"title\":\"" << json::escape(h.http.title)
          << "\",\"server\":\"" << json::escape(h.http.server) << "\",\"tech\":";
        arr(h.http.tech);
        o << "}";
    } else {
        o << "{\"alive\":false}";
    }

    o << ",\"dirs\":[";
    for (size_t i = 0; i < h.dirs.size(); ++i) {
        if (i) o << ",";
        o << "{\"path\":\"" << json::escape(h.dirs[i].path) << "\",\"status\":" << h.dirs[i].status
          << ",\"length\":" << h.dirs[i].length << "}";
    }
    o << "]";

    o << ",\"tls\":";
    if (h.tls.present) {
        o << "{\"present\":true,\"subject_cn\":\"" << json::escape(h.tls.subject_cn)
          << "\",\"issuer\":\"" << json::escape(h.tls.issuer) << "\",\"not_after\":\""
          << json::escape(h.tls.not_after) << "\",\"days_left\":" << h.tls.days_left << ",\"sans\":";
        arr(h.tls.sans);
        o << "}";
    } else {
        o << "{\"present\":false}";
    }

    o << ",\"intel\":{\"ip\":\"" << json::escape(h.intel.ip) << "\",\"reverse_dns\":\""
      << json::escape(h.intel.reverse_dns) << "\",\"asn\":\"" << json::escape(h.intel.asn)
      << "\",\"asn_org\":\"" << json::escape(h.intel.asn_org) << "\",\"country\":\""
      << json::escape(h.intel.country) << "\",\"cdn\":\"" << json::escape(h.intel.cdn)
      << "\",\"favicon_hash\":\"" << json::escape(h.intel.favicon_hash) << "\"}";

    o << ",\"findings\":[";
    for (size_t i = 0; i < h.findings.size(); ++i) {
        if (i) o << ",";
        const auto& f = h.findings[i];
        o << "{\"severity\":\"" << model::severity_label(f.severity) << "\",\"title\":\""
          << json::escape(f.title) << "\",\"detail\":\"" << json::escape(f.detail)
          << "\",\"suggestion\":\"" << json::escape(f.suggestion) << "\"}";
    }
    o << "]}";
    return o.str();
}

FindingTally tally(const std::vector<model::Host>& hosts) {
    FindingTally t;
    for (const auto& h : hosts)
        for (const auto& f : h.findings) {
            switch (f.severity) {
                case model::Severity::High: ++t.high; break;
                case model::Severity::Medium: ++t.medium; break;
                case model::Severity::Low: ++t.low; break;
                default: ++t.info; break;
            }
        }
    return t;
}

}  // namespace report
