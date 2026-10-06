#include "ratelimit.hpp"

#include <chrono>
#include <mutex>
#include <thread>

namespace ratelimit {

namespace {

std::mutex g_mu;
double g_rps = 0;       // <= 0 => unlimited
int g_delay_ms = 0;
std::chrono::steady_clock::time_point g_next;  // earliest time the next request may go
bool g_configured = false;

}  // namespace

void configure(double rps, int delay_ms) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_rps = rps;
    g_delay_ms = delay_ms < 0 ? 0 : delay_ms;
    g_next = std::chrono::steady_clock::now();
    g_configured = true;
}

void acquire() {
    if (!g_configured) return;
    std::chrono::steady_clock::time_point wait_until;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_rps <= 0 && g_delay_ms == 0) return;

        auto now = std::chrono::steady_clock::now();
        auto slot = g_next > now ? g_next : now;

        // Schedule the following request one interval (plus any fixed delay) later.
        auto interval = std::chrono::nanoseconds(0);
        if (g_rps > 0)
            interval += std::chrono::nanoseconds(static_cast<long long>(1e9 / g_rps));
        interval += std::chrono::milliseconds(g_delay_ms);
        g_next = slot + interval;
        wait_until = slot;
    }
    auto now = std::chrono::steady_clock::now();
    if (wait_until > now) std::this_thread::sleep_for(wait_until - now);
}

}  // namespace ratelimit
