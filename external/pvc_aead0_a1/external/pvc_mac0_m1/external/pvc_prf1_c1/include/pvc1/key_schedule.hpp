#pragma once

#include "pvc1/finalization.hpp"
#include "pvc1/return_pass.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pvc1 {

// PVC-PRF-1 Candidate C1 fixed key size. The construction remains experimental;
// the 256-bit width is frozen for bit-exact public review.
using ResearchKey256 = std::array<std::uint8_t, 32>;

struct KeyScheduleProfile {
    std::size_t forward_moves = 4;
    std::size_t return_moves = 4;
    std::size_t seal_moves = 4;
};

// Build a keyed initial WorkingState without compressing the 256-bit key through
// a scalar seed. All key bytes are injected directly in three domain-separated,
// position-framed passes. These are research APIs, not production cryptography.
[[nodiscard]] WorkingState make_keyed_state_a2(
    const ResearchKey256& key,
    KeyScheduleProfile profile = {},
    std::vector<MoveTrace>* trace = nullptr);

[[nodiscard]] WorkingStateB make_keyed_state_b(
    const ResearchKey256& key,
    KeyScheduleProfile profile = {},
    std::vector<MoveTraceB>* trace = nullptr);

[[nodiscard]] WorkingState evaluate_keyed_a2(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t moves_per_symbol = 8,
    KeyScheduleProfile profile = {});

[[nodiscard]] WorkingStateB evaluate_keyed_b(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t moves_per_symbol = 8,
    KeyScheduleProfile profile = {});

[[nodiscard]] ResearchOutput research_keyed_output_a2(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t moves_per_symbol = 8,
    std::size_t final_moves = 4,
    std::size_t squeeze_moves = 2,
    KeyScheduleProfile profile = {});

[[nodiscard]] ResearchOutput research_keyed_output_b(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t moves_per_symbol = 8,
    std::size_t final_moves = 4,
    std::size_t squeeze_moves = 2,
    KeyScheduleProfile profile = {});

[[nodiscard]] WorkingState evaluate_keyed_return_a2(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t forward_moves = 8,
    ReturnProfile return_profile = {},
    KeyScheduleProfile key_profile = {},
    std::vector<MoveTrace>* return_trace = nullptr);

[[nodiscard]] WorkingStateB evaluate_keyed_return_b(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t forward_moves = 8,
    ReturnProfile return_profile = {},
    KeyScheduleProfile key_profile = {},
    std::vector<MoveTraceB>* return_trace = nullptr);

[[nodiscard]] ResearchOutput research_keyed_return_output_a2(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t forward_moves = 8,
    ReturnProfile return_profile = {},
    std::size_t final_moves = 4,
    std::size_t squeeze_moves = 2,
    KeyScheduleProfile key_profile = {});

[[nodiscard]] ResearchOutput research_keyed_return_output_b(
    const ResearchKey256& key,
    std::span<const std::uint8_t> message,
    std::size_t forward_moves = 8,
    ReturnProfile return_profile = {},
    std::size_t final_moves = 4,
    std::size_t squeeze_moves = 2,
    KeyScheduleProfile key_profile = {});

} // namespace pvc1
