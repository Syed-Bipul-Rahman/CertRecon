#include "pipeline.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>

#include "netintel.hpp"
#include "resolver.hpp"
#include "takeover.hpp"
#include "tlsinfo.hpp"
#include "vulncheck.hpp"

namespace pipeline {

namespace {

void process_host(model::Host& h, const Options& opts, const std::string& apex) {
    const bool active = !opts.passive_only;
    if (opts.resolve || opts.any_stage()) h.dns = resolver::resolve(h.name);

    if (opts.takeover) takeover::check(h, active, opts.http_timeout_secs);

    // Active stages only make sense against resolvable hosts.
    if (!h.dns.resolved) return;

    if (opts.ports && active) h.ports = portscan::scan(h.name, opts.port_opts);

    if ((opts.http || opts.dirs) && active) {
        probe::http_probe(h.name, opts.probe_opts, h.http);
        if (opts.dirs && h.http.alive)
            probe::dir_bruteforce(h.http, opts.probe_opts, h.dirs);
    }

    if (opts.tls && active) tlsinfo::inspect(h, apex, opts.http_timeout_secs);
    if (opts.intel) netintel::gather(h, active, opts.http_timeout_secs);
    if (opts.vuln) vulncheck::check(h, active, opts.http_timeout_secs);
}

}  // namespace

std::vector<model::Host> run(const std::set<std::string>& subdomains, const std::string& input,
                             const Options& opts, const ProgressFn& progress) {
    std::vector<model::Host> hosts;
    hosts.reserve(subdomains.size());
    for (const auto& name : subdomains) {
        model::Host h;
        h.name = name;
        h.input = input;
        hosts.push_back(std::move(h));
    }

    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    std::mutex progress_mu;

    auto worker = [&] {
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= hosts.size()) break;
            process_host(hosts[i], opts, input);
            size_t n = done.fetch_add(1) + 1;
            if (progress) {
                std::lock_guard<std::mutex> lk(progress_mu);
                progress(n, hosts.size());
            }
        }
    };

    int n = std::max(1, std::min<int>(opts.concurrency, static_cast<int>(hosts.size())));
    std::vector<std::thread> pool;
    pool.reserve(n);
    for (int i = 0; i < n; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    return hosts;
}

}  // namespace pipeline
