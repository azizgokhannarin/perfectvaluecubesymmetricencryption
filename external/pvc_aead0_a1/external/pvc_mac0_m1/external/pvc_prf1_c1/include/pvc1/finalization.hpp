#pragma once

#include "pvc1/controller.hpp"
#include "pvc1/controller_b.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace pvc1 {

using ResearchOutput = std::array<std::uint8_t, 32>;

// Controller-bound finalization functions. In v0.9.0, the A2 default-profile
// path is frozen as Candidate C1. B remains an audit comparator. Both remain
// experimental and must not be used as production cryptography.
[[nodiscard]] ResearchOutput research_bound_output_a2(WorkingState state,
                                                       std::uint64_t message_length,
                                                       std::size_t final_moves = 4,
                                                       std::size_t squeeze_moves = 2);
[[nodiscard]] ResearchOutput research_bound_output_b(WorkingStateB state,
                                                      std::uint64_t message_length,
                                                      std::size_t final_moves = 4,
                                                      std::size_t squeeze_moves = 2);

[[nodiscard]] std::size_t output_bit_distance(const ResearchOutput& left,
                                              const ResearchOutput& right);

} // namespace pvc1
