#include "jarm.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "ratelimit.hpp"
#include "sha256.hpp"

// Faithful C++ port of Salesforce's JARM reference tool (BSD 3-Clause):
//   https://github.com/salesforce/jarm  (c) 2020 salesforce.com, inc.
// Probe table, packet construction and fuzzy hash mirror the reference so the
// 62-char output matches public JARM datasets.

namespace jarm {

namespace {

using Bytes = std::string;  // byte-safe buffer

// --- small helpers -----------------------------------------------------------
Bytes u16(unsigned v) {
    Bytes b(2, 0);
    b[0] = static_cast<char>((v >> 8) & 0xff);
    b[1] = static_cast<char>(v & 0xff);
    return b;
}
Bytes u8(unsigned v) { return Bytes(1, static_cast<char>(v & 0xff)); }

Bytes from_hex2(uint16_t v) {
    Bytes b(2, 0);
    b[0] = static_cast<char>((v >> 8) & 0xff);
    b[1] = static_cast<char>(v & 0xff);
    return b;
}

std::string hex_of(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string o;
    o.reserve(b.size() * 2);
    for (unsigned char c : b) {
        o.push_back(d[c >> 4]);
        o.push_back(d[c & 0xf]);
    }
    return o;
}

std::mt19937& rng() {
    static thread_local std::mt19937 g(std::random_device{}());
    return g;
}

Bytes urandom(size_t n) {
    Bytes b(n, 0);
    std::uniform_int_distribution<int> d(0, 255);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<char>(d(rng()));
    return b;
}

Bytes choose_grease() {
    static const uint16_t g[] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                                 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
    std::uniform_int_distribution<int> d(0, 15);
    return from_hex2(g[d(rng())]);
}

// A single JARM probe definition (reference field order).
struct Probe {
    const char* version;      // TLS_1.1 / TLS_1.2 / TLS_1.3
    const char* cipher_list;  // ALL / NO1.3
    const char* cipher_order; // FORWARD / REVERSE / TOP_HALF / BOTTOM_HALF / MIDDLE_OUT
    bool grease;              // GREASE vs NO_GREASE
    const char* alpn;         // APLN / RARE_APLN
    const char* support;      // 1.2_SUPPORT / NO_SUPPORT / 1.3_SUPPORT
    const char* ext_order;    // FORWARD / REVERSE
};

std::vector<Bytes> cipher_list_all() {
    static const uint16_t v[] = {
        0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f,
        0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b,
        0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14,
        0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076,
        0xc077, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c,
        0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0,
        0x0007, 0x0004, 0x0005};
    std::vector<Bytes> out;
    for (uint16_t x : v) out.push_back(from_hex2(x));
    return out;
}

std::vector<Bytes> cipher_list_no13() {
    static const uint16_t v[] = {
        0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f,
        0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b,
        0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0xcc14, 0xc007, 0xc012,
        0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8,
        0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d,
        0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005};
    std::vector<Bytes> out;
    for (uint16_t x : v) out.push_back(from_hex2(x));
    return out;
}

// Reorders a list per the JARM mung rules (used for ciphers, ALPN, versions).
std::vector<Bytes> mung(const std::vector<Bytes>& in, const std::string& req) {
    std::vector<Bytes> out;
    int n = static_cast<int>(in.size());
    if (req == "REVERSE") {
        out.assign(in.rbegin(), in.rend());
    } else if (req == "BOTTOM_HALF") {
        int start = (n % 2 == 1) ? (n / 2 + 1) : (n / 2);
        for (int i = start; i < n; ++i) out.push_back(in[i]);
    } else if (req == "TOP_HALF") {
        if (n % 2 == 1) out.push_back(in[n / 2]);
        std::vector<Bytes> rev = mung(in, "REVERSE");
        std::vector<Bytes> bh = mung(rev, "BOTTOM_HALF");
        out.insert(out.end(), bh.begin(), bh.end());
    } else if (req == "MIDDLE_OUT") {
        int middle = n / 2;
        if (n % 2 == 1) {
            out.push_back(in[middle]);
            for (int i = 1; i <= middle; ++i) {
                out.push_back(in[middle + i]);
                out.push_back(in[middle - i]);
            }
        } else {
            for (int i = 1; i <= middle; ++i) {
                out.push_back(in[middle - 1 + i]);
                out.push_back(in[middle - i]);
            }
        }
    } else {
        out = in;
    }
    return out;
}

Bytes get_ciphers(const Probe& p) {
    std::vector<Bytes> list =
        std::string(p.cipher_list) == "ALL" ? cipher_list_all() : cipher_list_no13();
    if (std::string(p.cipher_order) != "FORWARD") list = mung(list, p.cipher_order);
    if (p.grease) list.insert(list.begin(), choose_grease());
    Bytes out;
    for (const auto& c : list) out += c;
    return out;
}

Bytes extension_server_name(const std::string& host) {
    Bytes e;
    e += from_hex2(0x0000);
    e += u16(static_cast<unsigned>(host.size()) + 5);
    e += u16(static_cast<unsigned>(host.size()) + 3);
    e += u8(0);
    e += u16(static_cast<unsigned>(host.size()));
    e += host;
    return e;
}

Bytes alpn_extension(const Probe& p) {
    Bytes ext = from_hex2(0x0010);
    std::vector<Bytes> alpns;
    if (std::string(p.alpn) == "RARE_APLN") {
        alpns = {Bytes("\x08http/0.9", 9), Bytes("\x08http/1.0", 9), Bytes("\x06spdy/1", 7),
                 Bytes("\x06spdy/2", 7),   Bytes("\x06spdy/3", 7),   Bytes("\x03h2c", 4),
                 Bytes("\x02hq", 3)};
    } else {
        alpns = {Bytes("\x08http/0.9", 9), Bytes("\x08http/1.0", 9), Bytes("\x08http/1.1", 9),
                 Bytes("\x06spdy/1", 7),   Bytes("\x06spdy/2", 7),   Bytes("\x06spdy/3", 7),
                 Bytes("\x02h2", 3),       Bytes("\x03h2c", 4),      Bytes("\x02hq", 3)};
    }
    if (std::string(p.ext_order) != "FORWARD") alpns = mung(alpns, p.ext_order);
    Bytes all;
    for (const auto& a : alpns) all += a;
    ext += u16(static_cast<unsigned>(all.size()) + 2);
    ext += u16(static_cast<unsigned>(all.size()));
    ext += all;
    return ext;
}

Bytes key_share(bool grease) {
    Bytes ext = from_hex2(0x0033);
    Bytes share;
    if (grease) {
        share += choose_grease();
        share += Bytes("\x00\x01\x00", 3);
    }
    share += from_hex2(0x001d);  // group x25519
    share += from_hex2(0x0020);  // key exchange length
    share += urandom(32);
    ext += u16(static_cast<unsigned>(share.size()) + 2);
    ext += u16(static_cast<unsigned>(share.size()));
    ext += share;
    return ext;
}

Bytes supported_versions(const Probe& p, bool grease) {
    std::vector<Bytes> tls;
    if (std::string(p.support) == "1.2_SUPPORT")
        tls = {from_hex2(0x0301), from_hex2(0x0302), from_hex2(0x0303)};
    else
        tls = {from_hex2(0x0301), from_hex2(0x0302), from_hex2(0x0303), from_hex2(0x0304)};
    if (std::string(p.ext_order) != "FORWARD") tls = mung(tls, p.ext_order);
    Bytes ext = from_hex2(0x002b);
    Bytes versions;
    if (grease) versions += choose_grease();
    for (const auto& v : tls) versions += v;
    ext += u16(static_cast<unsigned>(versions.size()) + 1);
    ext += u8(static_cast<unsigned>(versions.size()));
    ext += versions;
    return ext;
}

Bytes get_extensions(const Probe& p, const std::string& host) {
    Bytes all;
    bool grease = p.grease;
    if (grease) {
        all += choose_grease();
        all += from_hex2(0x0000);
    }
    all += extension_server_name(host);
    all += Bytes("\x00\x17\x00\x00", 4);                  // extended_master_secret
    all += Bytes("\x00\x01\x00\x01\x01", 5);              // max_fragment_length
    all += Bytes("\xff\x01\x00\x01\x00", 5);              // renegotiation_info
    all += Bytes("\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19", 14);  // supported_groups
    all += Bytes("\x00\x0b\x00\x02\x01\x00", 6);          // ec_point_formats
    all += Bytes("\x00\x23\x00\x00", 4);                  // session_ticket
    all += alpn_extension(p);
    all += Bytes("\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06"
                 "\x06\x01\x02\x01",
                 24);  // signature_algorithms
    all += key_share(grease);
    all += Bytes("\x00\x2d\x00\x02\x01\x01", 6);          // psk_key_exchange_modes
    if (std::string(p.version) == "TLS_1.3" || std::string(p.support) == "1.2_SUPPORT")
        all += supported_versions(p, grease);
    Bytes out = u16(static_cast<unsigned>(all.size()));
    out += all;
    return out;
}

Bytes build_packet(const Probe& p, const std::string& host) {
    Bytes payload(1, '\x16');
    Bytes client_hello;
    std::string ver = p.version;
    if (ver == "TLS_1.3") { payload += Bytes("\x03\x01", 2); client_hello = Bytes("\x03\x03", 2); }
    else if (ver == "TLS_1")   { payload += Bytes("\x03\x01", 2); client_hello = Bytes("\x03\x01", 2); }
    else if (ver == "TLS_1.1") { payload += Bytes("\x03\x02", 2); client_hello = Bytes("\x03\x02", 2); }
    else                       { payload += Bytes("\x03\x03", 2); client_hello = Bytes("\x03\x03", 2); }

    client_hello += urandom(32);
    Bytes session_id = urandom(32);
    client_hello += u8(static_cast<unsigned>(session_id.size()));
    client_hello += session_id;
    Bytes ciphers = get_ciphers(p);
    client_hello += u16(static_cast<unsigned>(ciphers.size()));
    client_hello += ciphers;
    client_hello += u8(1);  // compression methods length
    client_hello += u8(0);  // null compression
    client_hello += get_extensions(p, host);

    Bytes handshake = u8(1);          // handshake type: client hello
    handshake += u8(0);               // 3-byte length, high byte
    handshake += u16(static_cast<unsigned>(client_hello.size()));
    handshake += client_hello;

    payload += u16(static_cast<unsigned>(handshake.size()));
    payload += handshake;
    return payload;
}

// --- networking --------------------------------------------------------------
enum class SendResult { Data, Timeout, Error };

SendResult send_packet(const struct addrinfo* ai, const Bytes& packet, long timeout_secs,
                       Bytes& out) {
    out.clear();
    int fd = ::socket(ai->ai_family, SOCK_STREAM, 0);
    if (fd < 0) return SendResult::Error;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    SendResult rc = SendResult::Error;
    int cr = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (cr != 0) {
        if (errno != EINPROGRESS) { ::close(fd); return SendResult::Error; }
        struct pollfd pfd{fd, POLLOUT, 0};
        int pr = ::poll(&pfd, 1, static_cast<int>(timeout_secs * 1000));
        if (pr == 0) { ::close(fd); return SendResult::Timeout; }
        if (pr < 0) { ::close(fd); return SendResult::Error; }
        int err = 0;
        socklen_t len = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) { ::close(fd); return SendResult::Error; }
    }
    fcntl(fd, F_SETFL, flags);  // back to blocking

    struct timeval tv{timeout_secs, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    if (::send(fd, packet.data(), packet.size(), 0) < 0) { ::close(fd); return SendResult::Error; }

    char buf[1600];
    for (int reads = 0; reads < 4 && out.size() < 1484; ++reads) {
        ssize_t n = ::recv(fd, buf, sizeof buf, 0);
        if (n > 0) {
            out.append(buf, static_cast<size_t>(n));
            rc = SendResult::Data;
        } else if (n == 0) {
            break;  // peer closed
        } else {
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && out.empty())
                rc = SendResult::Timeout;
            break;
        }
    }
    if (!out.empty()) rc = SendResult::Data;
    ::close(fd);
    return rc;
}

// --- server hello parsing ----------------------------------------------------
bool safe_eq(const Bytes& d, size_t pos, std::initializer_list<unsigned char> want) {
    if (pos + want.size() > d.size()) return false;
    size_t i = 0;
    for (unsigned char w : want)
        if (static_cast<unsigned char>(d[pos + i++]) != w) return false;
    return true;
}

std::string extract_extension_info(const Bytes& d, size_t counter, size_t server_hello_length) {
    try {
        auto at = [&](size_t i) { return static_cast<unsigned char>(d.at(i)); };
        if (at(counter + 47) == 11) return "|";
        if (safe_eq(d, counter + 50, {0x0e, 0xac, 0x0b}) || safe_eq(d, 82, {0x0f, 0xf0, 0x0b}))
            return "|";
        if (counter + 42 >= server_hello_length) return "|";

        size_t count = 49 + counter;
        size_t length = (static_cast<size_t>(at(counter + 47)) << 8) | at(counter + 48);
        size_t maximum = length + (count - 1);

        std::vector<Bytes> types;
        std::vector<Bytes> values;
        while (count < maximum) {
            types.push_back(d.substr(count, 2));
            size_t ext_length = (static_cast<size_t>(at(count + 2)) << 8) | at(count + 3);
            if (ext_length == 0) {
                count += 4;
                values.push_back("");
            } else {
                values.push_back(d.substr(count + 4, ext_length));
                count += ext_length + 4;
            }
        }

        // ALPN value (extension type 0x0010), ASCII protocol id after its 3-byte prefix.
        std::string alpn;
        for (size_t i = 0; i < types.size(); ++i) {
            if (types[i] == from_hex2(0x0010)) {
                alpn = values[i].size() > 3 ? values[i].substr(3) : "";
                break;
            }
        }
        std::string result = alpn + "|";
        for (size_t i = 0; i < types.size(); ++i) {
            result += hex_of(types[i]);
            if (i + 1 != types.size()) result += "-";
        }
        return result;
    } catch (const std::out_of_range&) {
        return "|";
    }
}

std::string read_packet(const Bytes& d, const Probe&) {
    try {
        if (d.empty()) return "|||";
        auto at = [&](size_t i) { return static_cast<unsigned char>(d.at(i)); };
        if (at(0) == 21) return "|||";
        if (at(0) == 22 && at(5) == 2) {
            size_t server_hello_length = (static_cast<size_t>(at(3)) << 8) | at(4);
            size_t counter = at(43);
            Bytes selected_cipher = d.substr(counter + 44, 2);
            Bytes version = d.substr(9, 2);
            if (selected_cipher.size() < 2 || version.size() < 2) return "|||";
            std::string jarm = hex_of(selected_cipher) + "|" + hex_of(version) + "|";
            jarm += extract_extension_info(d, counter, server_hello_length);
            return jarm;
        }
        return "|||";
    } catch (const std::out_of_range&) {
        return "|||";
    }
}

// --- fuzzy hash --------------------------------------------------------------
const std::vector<std::string>& cipher_index_list() {
    static const std::vector<std::string> list = {
        "0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035", "0039", "003c", "003d",
        "0041", "0045", "0067", "006b", "0084", "0088", "009a", "009c", "009d", "009e", "009f",
        "00ba", "00be", "00c0", "00c4", "c007", "c008", "c009", "c00a", "c011", "c012", "c013",
        "c014", "c023", "c024", "c027", "c028", "c02b", "c02c", "c02f", "c030", "c060", "c061",
        "c072", "c073", "c076", "c077", "c09c", "c09d", "c09e", "c09f", "c0a0", "c0a1", "c0a2",
        "c0a3", "c0ac", "c0ad", "c0ae", "c0af", "cc13", "cc14", "cca8", "cca9", "1301", "1302",
        "1303", "1304", "1305"};
    return list;
}

std::string cipher_bytes(const std::string& cipher) {
    if (cipher.empty()) return "00";
    const auto& list = cipher_index_list();
    size_t count = 1;
    bool found = false;
    for (const auto& c : list) {
        if (cipher == c) { found = true; break; }
        ++count;
    }
    if (!found) count = list.size() + 1;
    static const char* d = "0123456789abcdef";
    std::string hv;
    if (count < 16) { hv.push_back('0'); hv.push_back(d[count]); }
    else { hv.push_back(d[(count >> 4) & 0xf]); hv.push_back(d[count & 0xf]); }
    return hv;
}

std::string version_byte(const std::string& version) {
    if (version.size() < 4) return "0";
    static const char* options = "abcdef";
    int c = version[3] - '0';
    if (c < 0 || c > 5) return "0";
    return std::string(1, options[c]);
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        size_t p = s.find(sep, start);
        if (p == std::string::npos) { out.push_back(s.substr(start)); break; }
        out.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    return out;
}

std::string jarm_hash(const std::string& raw) {
    if (raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||") return std::string(62, '0');
    std::string fuzzy;
    std::string alpns_and_ext;
    for (const auto& hs : split(raw, ',')) {
        std::vector<std::string> c = split(hs, '|');
        c.resize(4);  // tolerate malformed handshakes
        fuzzy += cipher_bytes(c[0]);
        fuzzy += version_byte(c[1]);
        alpns_and_ext += c[2];
        alpns_and_ext += c[3];
    }
    fuzzy += sha256::hex(alpns_and_ext).substr(0, 32);
    return fuzzy;
}

}  // namespace

std::string fingerprint(const std::string& host, int port, long timeout_secs) {
    static const Probe probes[10] = {
        {"TLS_1.2", "ALL", "FORWARD", false, "APLN", "1.2_SUPPORT", "REVERSE"},
        {"TLS_1.2", "ALL", "REVERSE", false, "APLN", "1.2_SUPPORT", "FORWARD"},
        {"TLS_1.2", "ALL", "TOP_HALF", false, "APLN", "NO_SUPPORT", "FORWARD"},
        {"TLS_1.2", "ALL", "BOTTOM_HALF", false, "RARE_APLN", "NO_SUPPORT", "FORWARD"},
        {"TLS_1.2", "ALL", "MIDDLE_OUT", true, "RARE_APLN", "NO_SUPPORT", "REVERSE"},
        {"TLS_1.1", "ALL", "FORWARD", false, "APLN", "NO_SUPPORT", "FORWARD"},
        {"TLS_1.3", "ALL", "FORWARD", false, "APLN", "1.3_SUPPORT", "REVERSE"},
        {"TLS_1.3", "ALL", "REVERSE", false, "APLN", "1.3_SUPPORT", "FORWARD"},
        {"TLS_1.3", "NO1.3", "FORWARD", false, "APLN", "1.3_SUPPORT", "FORWARD"},
        {"TLS_1.3", "ALL", "MIDDLE_OUT", true, "APLN", "1.3_SUPPORT", "REVERSE"},
    };

    long tmo = std::max<long>(2, std::min<long>(timeout_secs, 8));

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
        return "";

    std::string raw;
    for (int i = 0; i < 10; ++i) {
        ratelimit::acquire();
        Bytes packet = build_packet(probes[i], host);
        Bytes server_hello;
        SendResult sr = send_packet(res, packet, tmo, server_hello);
        if (sr == SendResult::Timeout) {
            raw = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||";
            break;
        }
        raw += read_packet(server_hello, probes[i]);
        if (i != 9) raw += ",";
    }
    freeaddrinfo(res);

    std::string result = jarm_hash(raw);
    if (result == std::string(62, '0')) return "";  // no usable TLS fingerprint
    return result;
}

}  // namespace jarm
