// Network/hosting intelligence: reverse DNS, ASN (Team Cymru), CDN/WAF, favicon.
#pragma once

#include <string>

#include "model.hpp"

namespace netintel {

// Fills host.intel. Reverse DNS and ASN use DNS only (safe in passive mode);
// the favicon hash fetches from the target, so it is gated by `allow_active`.
void gather(model::Host& host, bool allow_active, long timeout_secs);

}  // namespace netintel
