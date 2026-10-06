#include "portscan.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>

#include "ratelimit.hpp"

namespace portscan {

namespace {

// Well-known service names for common ports (fallback when no banner is seen).
const std::map<int, const char*>& service_names() {
    static const std::map<int, const char*> m = {
        {21, "ftp"},     {22, "ssh"},      {23, "telnet"},  {25, "smtp"},
        {53, "dns"},     {80, "http"},     {110, "pop3"},   {111, "rpcbind"},
        {135, "msrpc"},  {139, "netbios"}, {143, "imap"},   {443, "https"},
        {445, "smb"},    {465, "smtps"},   {587, "submission"}, {993, "imaps"},
        {995, "pop3s"},  {1433, "mssql"},  {1521, "oracle"},{2049, "nfs"},
        {2375, "docker"},{2376, "docker-tls"}, {3000, "http-dev"}, {3306, "mysql"},
        {3389, "rdp"},   {5432, "postgres"}, {5601, "kibana"}, {5900, "vnc"},
        {6379, "redis"}, {7001, "weblogic"}, {8000, "http-alt"}, {8008, "http-alt"},
        {8080, "http-proxy"}, {8081, "http-alt"}, {8443, "https-alt"}, {8888, "http-alt"},
        {9000, "http-alt"}, {9200, "elasticsearch"}, {9300, "elasticsearch"},
        {11211, "memcached"}, {15672, "rabbitmq"}, {27017, "mongodb"},
    };
    return m;
}

// TLS ports: a plaintext probe only yields a binary TLS alert, so skip banners.
bool is_tls_port(int port) {
    switch (port) {
        case 443: case 465: case 636: case 989: case 990: case 993: case 995:
        case 8443: case 9443:
            return true;
        default:
            return false;
    }
}

// Ports where sending a tiny probe elicits a useful banner.
bool is_http_like(int port) {
    switch (port) {
        case 80: case 443: case 3000: case 8000: case 8008: case 8080:
        case 8081: case 8443: case 8888: case 9000: case 9200: case 5601:
            return true;
        default:
            return false;
    }
}

std::string first_line(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\r' || c == '\n') break;
        if (std::isprint(static_cast<unsigned char>(c)))
            out += c;
        else
            out += '.';
        if (out.size() >= 200) break;
    }
    return out;
}

// Connects to ip:port with a timeout. Returns the connected fd, or -1.
int connect_timeout(const std::string& ip, int port, int timeout_ms) {
    ratelimit::acquire();
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(ip.c_str(), port_str.c_str(), &hints, &res) != 0) return -1;

    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc == 0) {
            fcntl(fd, F_SETFL, flags);
            break;
        }
        if (errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        struct pollfd pfd{fd, POLLOUT, 0};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) {
            close(fd);
            fd = -1;
            continue;
        }
        int err = 0;
        socklen_t len = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        fcntl(fd, F_SETFL, flags);
        break;
    }
    freeaddrinfo(res);
    return fd;
}

// Reads whatever the service volunteers within the timeout.
std::string grab_banner(int fd, int port, const std::string& host, int timeout_ms) {
    if (is_tls_port(port)) return "";  // plaintext probe is useless against TLS
    if (is_http_like(port)) {
        std::string req = "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: certrecon\r\n\r\n";
        send(fd, req.data(), req.size(), 0);
    }
    struct pollfd pfd{fd, POLLIN, 0};
    if (poll(&pfd, 1, timeout_ms) <= 0) return "";
    char buf[512];
    ssize_t n = recv(fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return "";
    buf[n] = '\0';
    return first_line(std::string(buf, static_cast<size_t>(n)));
}

model::Port probe_port(const std::string& host, const std::string& ip, int port,
                       const Options& opts) {
    model::Port result;
    int fd = connect_timeout(ip, port, opts.connect_timeout_ms);
    if (fd < 0) return result;  // port == 0 signals "closed"
    result.port = port;
    auto it = service_names().find(port);
    result.service = it != service_names().end() ? it->second : "unknown";
    result.banner = grab_banner(fd, port, host, opts.banner_timeout_ms);
    close(fd);
    return result;
}

}  // namespace

const std::vector<int>& default_ports() {
    static const std::vector<int> p = {
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
        1433, 3000, 3306, 3389, 5432, 5601, 6379, 8000, 8080, 8443,
        8888, 9000, 9200, 11211, 27017,
    };
    return p;
}

bool parse_ports(const std::string& spec, std::vector<int>& out) {
    std::vector<int> ports;
    size_t i = 0;
    while (i < spec.size()) {
        size_t comma = spec.find(',', i);
        std::string tok = spec.substr(i, comma == std::string::npos ? std::string::npos : comma - i);
        i = comma == std::string::npos ? spec.size() : comma + 1;
        if (tok.empty()) continue;

        auto dash = tok.find('-');
        try {
            if (dash == std::string::npos) {
                int v = std::stoi(tok);
                if (v < 1 || v > 65535) return false;
                ports.push_back(v);
            } else {
                int lo = std::stoi(tok.substr(0, dash));
                int hi = std::stoi(tok.substr(dash + 1));
                if (lo < 1 || hi > 65535 || lo > hi || hi - lo > 65535) return false;
                for (int v = lo; v <= hi; ++v) ports.push_back(v);
            }
        } catch (...) {
            return false;
        }
    }
    if (ports.empty()) return false;
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    out = std::move(ports);
    return true;
}

std::vector<model::Port> scan(const std::string& host, const Options& opts) {
    const auto& ports = opts.ports.empty() ? default_ports() : opts.ports;
    std::vector<model::Port> open;
    std::mutex mu;
    std::atomic<size_t> next{0};

    auto worker = [&] {
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= ports.size()) break;
            model::Port r = probe_port(host, host, ports[i], opts);
            if (r.port != 0) {
                std::lock_guard<std::mutex> lk(mu);
                open.push_back(std::move(r));
            }
        }
    };

    int n = std::max(1, std::min<int>(opts.concurrency, static_cast<int>(ports.size())));
    std::vector<std::thread> pool;
    pool.reserve(n);
    for (int i = 0; i < n; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    std::sort(open.begin(), open.end(),
              [](const model::Port& a, const model::Port& b) { return a.port < b.port; });
    return open;
}

}  // namespace portscan
