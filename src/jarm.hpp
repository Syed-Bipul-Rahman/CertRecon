// JARM active TLS server fingerprinting.
//
// This is a C++ port of Salesforce's reference JARM tool
// (https://github.com/salesforce/jarm), BSD 3-Clause licensed:
//   Copyright (c) 2020, salesforce.com, inc. All rights reserved.
// The 10 TLS Client Hello probes and the fuzzy-hash construction are kept
// byte-for-byte faithful to the reference so the resulting fingerprints match
// public JARM databases (e.g. Shodan's ssl.jarm).
#pragma once

#include <string>

namespace jarm {

// Computes the 62-character JARM fingerprint for host:port by sending the 10
// JARM TLS Client Hello probes and hashing the Server Hello responses.
// Returns "" when the host offers no usable TLS service (an all-zero hash),
// so callers can simply skip empty results.
std::string fingerprint(const std::string& host, int port, long timeout_secs);

}  // namespace jarm
