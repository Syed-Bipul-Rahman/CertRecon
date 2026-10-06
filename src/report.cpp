#include "report.hpp"

#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
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

// Display width of a UTF-8 string, counting code points (good enough for the
// Latin text / punctuation we render; em dashes, ·, … all count as one column).
size_t vwidth(const std::string& s) {
    size_t n = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80) ++n;
    return n;
}

// Truncates `s` to at most `cols` display columns, appending … when cut.
std::string vtrunc(const std::string& s, size_t cols) {
    if (vwidth(s) <= cols) return s;
    if (cols == 0) return "";
    size_t keep = cols - 1, count = 0, i = 0;
    while (i < s.size() && count < keep) {
        unsigned char c = s[i];
        size_t len = (c & 0x80) == 0      ? 1
                     : (c & 0xE0) == 0xC0 ? 2
                     : (c & 0xF0) == 0xE0 ? 3
                                          : 4;
        i += len;
        ++count;
    }
    return s.substr(0, i) + "…";
}

int detect_term_width() {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
    if (const char* c = std::getenv("COLUMNS")) {
        int w = std::atoi(c);
        if (w > 0) return w;
    }
    return 120;
}

std::string dashes(size_t n) {
    std::string out;
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) out += "─";  // ─
    return out;
}

std::string primary_ip(const model::Host& h) {
    if (!h.dns.a.empty()) return h.dns.a.front();
    if (!h.dns.aaaa.empty()) return h.dns.aaaa.front();
    return "";
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
    if (!in.reverse_dns.empty() || !in.asn.empty() || !in.cdn.empty() || !in.favicon_hash.empty() ||
        !in.jarm.empty()) {
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
        if (!in.jarm.empty())
            o << "          " << p.dim << "JARM: " << in.jarm << p.reset << "\n";
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

std::string table(const std::vector<model::Host>& hosts, bool color, int max_width) {
    Palette p(color);
    std::ostringstream o;

    enum { C_HOST, C_IP, C_CODE, C_TITLE, C_TECH, C_CDN, C_FND, NCOL };
    struct ColDef { const char* header; size_t cap; size_t minw; bool droppable; };
    const ColDef defs[NCOL] = {
        {"HOST", 44, 20, false}, {"IP", 18, 11, false}, {"CODE", 4, 3, false},
        {"TITLE", 30, 12, true}, {"TECH", 22, 8, true}, {"CDN", 14, 6, true},
        {"FND", 11, 3, false},
    };

    struct Cell { std::string text; const char* color; };
    std::vector<std::vector<Cell>> rows;

    for (const auto& h : hosts) {
        std::vector<Cell> r(NCOL);
        r[C_HOST] = {h.name, p.cyan};
        r[C_IP] = {primary_ip(h), p.dim};

        if (h.http.alive) {
            long s = h.http.status;
            const char* cc = s < 300 ? p.green : s < 400 ? p.cyan : s < 500 ? p.yellow : p.red;
            r[C_CODE] = {std::to_string(s), cc};
        } else if (h.dns.nxdomain) {
            r[C_CODE] = {"nx", p.dim};
        } else {
            r[C_CODE] = {"-", p.dim};
        }

        r[C_TITLE] = {h.http.title, p.dim};
        r[C_TECH] = {join(h.http.tech, ","), p.magenta};
        r[C_CDN] = {h.intel.cdn, p.reset};

        int hi = 0, me = 0, lo = 0;
        for (const auto& f : h.findings) {
            if (f.severity == model::Severity::High) ++hi;
            else if (f.severity == model::Severity::Medium) ++me;
            else if (f.severity == model::Severity::Low) ++lo;
        }
        std::string fnd;
        if (hi) fnd += "H" + std::to_string(hi) + " ";
        if (me) fnd += "M" + std::to_string(me) + " ";
        if (lo) fnd += "L" + std::to_string(lo) + " ";
        if (!fnd.empty() && fnd.back() == ' ') fnd.pop_back();
        const char* fc = hi ? p.red : me ? p.yellow : lo ? p.cyan : p.dim;
        r[C_FND] = {fnd, fc};

        rows.push_back(std::move(r));
    }

    // Natural (capped) column widths.
    size_t w[NCOL];
    for (int i = 0; i < NCOL; ++i) w[i] = vwidth(defs[i].header);
    for (const auto& r : rows)
        for (int i = 0; i < NCOL; ++i)
            w[i] = std::max(w[i], std::min(defs[i].cap, vwidth(r[i].text)));

    bool active[NCOL];
    for (int i = 0; i < NCOL; ++i) active[i] = true;

    int target = max_width > 0 ? max_width : detect_term_width();
    auto total = [&]() {
        int t = 1;  // trailing │
        for (int i = 0; i < NCOL; ++i)
            if (active[i]) t += static_cast<int>(w[i]) + 3;  // "│ " + cell + " "
        return t;
    };

    // Fit to width. The HOST column is the identifier and must stay readable, so
    // sacrifice the descriptive columns (CDN, TECH, TITLE) first: shrink them
    // toward their minimum, then drop them outright, and only squeeze HOST (then
    // IP) as a last resort on very narrow terminals.
    auto shrink = [&](std::initializer_list<int> cols_list) {
        for (;;) {
            int best = -1;
            for (int ci : cols_list)
                if (active[ci] && w[ci] > defs[ci].minw && (best < 0 || w[ci] > w[best])) best = ci;
            if (best < 0 || total() <= target) break;
            --w[best];
        }
    };
    shrink({C_CDN, C_TECH, C_TITLE});
    const int drop_order[] = {C_CDN, C_TECH, C_TITLE};
    for (int di : drop_order) {
        if (total() <= target) break;
        active[di] = false;
    }
    shrink({C_HOST, C_IP});  // last resort

    auto rule = [&](const char* l, const char* m, const char* rt) {
        o << p.dim << l;
        bool first = true;
        for (int i = 0; i < NCOL; ++i) {
            if (!active[i]) continue;
            if (!first) o << m;
            first = false;
            o << dashes(w[i] + 2);
        }
        o << rt << p.reset << "\n";
    };

    auto emit_row = [&](const std::vector<Cell>& r, bool header) {
        for (int i = 0; i < NCOL; ++i) {
            if (!active[i]) continue;
            o << p.dim << "│" << p.reset << " ";
            std::string txt = vtrunc(r[i].text, w[i]);
            size_t pad = w[i] - vwidth(txt);
            if (header)
                o << p.bold << txt << p.reset;
            else
                o << r[i].color << txt << p.reset;
            o << std::string(pad, ' ') << " ";
        }
        o << p.dim << "│" << p.reset << "\n";
    };

    std::vector<Cell> head(NCOL);
    for (int i = 0; i < NCOL; ++i) head[i] = {defs[i].header, p.bold};

    rule("┌", "┬", "┐");  // ┌ ┬ ┐
    emit_row(head, true);
    rule("├", "┼", "┤");  // ├ ┼ ┤
    for (const auto& r : rows) emit_row(r, false);
    rule("└", "┴", "┘");  // └ ┴ ┘

    // Findings section (severity-ordered), with detail + fix lines.
    struct FRef { const model::Host* host; const model::Finding* f; };
    std::vector<FRef> frefs;
    for (const auto& h : hosts)
        for (const auto& f : h.findings) frefs.push_back({&h, &f});
    std::stable_sort(frefs.begin(), frefs.end(), [](const FRef& a, const FRef& b) {
        return static_cast<int>(a.f->severity) > static_cast<int>(b.f->severity);
    });

    if (!frefs.empty()) {
        o << "\n" << p.bold << "FINDINGS" << p.reset << "\n";
        for (const auto& fr : frefs) {
            const auto& f = *fr.f;
            o << "  " << severity_color(f.severity, p) << p.bold << "["
              << model::severity_label(f.severity) << "]" << p.reset << " " << p.cyan
              << fr.host->name << p.reset << "  " << f.title << "\n";
            if (!f.detail.empty()) o << "      " << p.dim << f.detail << p.reset << "\n";
            if (!f.suggestion.empty())
                o << "      " << p.dim << "↳ fix: " << f.suggestion << p.reset << "\n";
        }
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
      << "\",\"favicon_hash\":\"" << json::escape(h.intel.favicon_hash) << "\",\"jarm\":\""
      << json::escape(h.intel.jarm) << "\"}";

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
