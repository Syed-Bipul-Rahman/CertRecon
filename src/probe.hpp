// HTTP(S) probing and directory/content brute-forcing via libcurl.
#pragma once

#include <string>
#include <vector>

#include "model.hpp"

namespace probe {

struct Options {
    long timeout_secs = 10;
    bool follow_redirects = true;
    // Directory brute-forcing:
    bool dirs = false;
    std::vector<std::string> wordlist;  // paths to try (without leading slash)
    int dir_concurrency = 20;
};

// The built-in directory/content wordlist used when none is supplied.
const std::vector<std::string>& default_wordlist();

// Probes http:// then https:// for `host`, filling `out.http`.
void http_probe(const std::string& host, const Options& opts, model::Http& out);

// Brute-forces paths under the host's live base URL, filling `out`.
// Does nothing if the host has no live HTTP service.
void dir_bruteforce(const model::Http& http, const Options& opts, std::vector<model::Dir>& out);

}  // namespace probe
