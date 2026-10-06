// Lightweight vulnerability signals: security headers, CORS, exposed files,
// and unauthenticated services. Each produces a Finding with a fix suggestion.
#pragma once

#include "model.hpp"

namespace vulncheck {

// Appends findings to host.findings. Header analysis uses the already-captured
// HTTP response; the active probes (CORS, exposed files, open services) are
// gated by `allow_active` so they are skipped in passive mode.
void check(model::Host& host, bool allow_active, long timeout_secs);

}  // namespace vulncheck
