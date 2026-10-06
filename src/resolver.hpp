// DNS resolution: A/AAAA via getaddrinfo, CNAME chain + NXDOMAIN via libresolv.
#pragma once

#include <string>

#include "model.hpp"

namespace resolver {

// Resolves A/AAAA records and follows the CNAME chain for `host`.
model::Dns resolve(const std::string& host);

// True if `host` does not exist in DNS (NXDOMAIN). Used for takeover checks.
bool is_nxdomain(const std::string& host);

}  // namespace resolver
