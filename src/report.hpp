// Rendering of enriched hosts: human-readable report and JSON.
#pragma once

#include <string>
#include <vector>

#include "model.hpp"

namespace report {

// One host as an indented, optionally colored human-readable block.
std::string human(const model::Host& h, bool color);

// One host as a single-line JSON object.
std::string json(const model::Host& h);

// Counts findings by severity across all hosts.
struct FindingTally {
    size_t high = 0, medium = 0, low = 0, info = 0;
    size_t total() const { return high + medium + low + info; }
};
FindingTally tally(const std::vector<model::Host>& hosts);

}  // namespace report
