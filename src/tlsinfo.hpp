// TLS certificate inspection via libcurl's CERTINFO (no OpenSSL dependency).
#pragma once

#include <string>

#include "model.hpp"

namespace tlsinfo {

// Fetches the leaf certificate for `host` over TLS and fills host.tls.
// Harvests SANs that are subdomains of `apex` (and new) into host.harvested,
// and appends expiry findings. Does nothing if TLS can't be established.
void inspect(model::Host& host, const std::string& apex, long timeout_secs);

}  // namespace tlsinfo
