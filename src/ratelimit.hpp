// Process-wide rate limiter for traffic sent to scan targets.
#pragma once

namespace ratelimit {

// Configures the global limiter. rps <= 0 means unlimited; delay_ms adds a
// fixed pause after each acquire(). Call once before scanning starts.
void configure(double rps, int delay_ms);

// Blocks until another request to a target is permitted. No-op when unlimited.
// Thread-safe. Used by all stages that connect to target hosts.
void acquire();

}  // namespace ratelimit
