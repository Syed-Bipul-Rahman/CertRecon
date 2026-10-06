// Detection of dangling DNS records and subdomain-takeover candidates.
#pragma once

#include "model.hpp"

namespace takeover {

// Inspects a host's DNS (CNAME chain, resolution) and, where relevant, its HTTP
// response, appending any dangling-record or takeover findings to host.findings.
// `dns` must already be populated. When `allow_active` is false (passive mode),
// only DNS-based findings (dangling CNAMEs) are produced - no page is fetched.
void check(model::Host& host, bool allow_active, long http_timeout_secs);

}  // namespace takeover
