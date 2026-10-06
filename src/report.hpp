// Rendering of enriched hosts: human-readable report and JSON.
#pragma once

#include <string>
#include <vector>

#include "model.hpp"

namespace report {

// One host as an indented, optionally colored human-readable block.
std::string human(const model::Host& h, bool color);

// All hosts as a boxed summary table, followed by a findings section.
// `max_width` is the target terminal width (columns are trimmed/dropped to fit);
// pass 0 to auto-detect from the terminal (or a sensible default when piped).
std::string table(const std::vector<model::Host>& hosts, bool color, int max_width = 0);

// One host as a single-line JSON object.
std::string json(const model::Host& h);

// Counts findings by severity across all hosts.
struct FindingTally {
    size_t high = 0, medium = 0, low = 0, info = 0;
    size_t total() const { return high + medium + low + info; }
};
FindingTally tally(const std::vector<model::Host>& hosts);

}  // namespace report
