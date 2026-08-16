#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace pvc1 {

typedef std::array<std::uint8_t, 32> ResearchKey256;
typedef std::array<std::uint8_t, 32> ResearchOutput;

ResearchOutput research_keyed_return_output_a2(
    const ResearchKey256& key,
    const std::vector<std::uint8_t>& message);

} // namespace pvc1
