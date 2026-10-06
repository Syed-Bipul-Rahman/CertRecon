// Wappalyzer-style technology fingerprinting from HTTP response headers and body.
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace techfp {

// Returns detected technologies (de-duplicated, with versions where derivable),
// given the response headers (lowercased keys) and the response body.
std::vector<std::string> detect(const std::vector<std::pair<std::string, std::string>>& headers,
                                const std::string& body);

}  // namespace techfp
