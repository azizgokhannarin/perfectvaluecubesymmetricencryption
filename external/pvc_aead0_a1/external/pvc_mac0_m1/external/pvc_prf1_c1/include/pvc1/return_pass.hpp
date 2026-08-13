#pragma once

#include "pvc1/controller.hpp"
#include "pvc1/controller_b.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pvc1 {

// Research-only message return/foldback profile.  v0.9.0 deliberately keeps
// these counts explicit so reduced-profile attacks can shrink each component
// independently.
struct ReturnProfile {
    std::size_t init_symbols = 16;
    std::size_t init_moves = 4;
    std::size_t message_moves = 8;
    std::size_t seal_symbols = 8;
    std::size_t seal_moves = 4;
};

void apply_transcript_return_a2(WorkingState& state,
                                std::span<const std::uint8_t> message,
                                ReturnProfile profile = {},
                                std::vector<MoveTrace>* trace = nullptr);

void apply_transcript_return_b(WorkingStateB& state,
                               std::span<const std::uint8_t> message,
                               ReturnProfile profile = {},
                               std::vector<MoveTraceB>* trace = nullptr);

[[nodiscard]] std::size_t common_move_prefix(std::span<const MoveTrace> left,
                                             std::span<const MoveTrace> right);
[[nodiscard]] std::size_t common_move_prefix_b(std::span<const MoveTraceB> left,
                                               std::span<const MoveTraceB> right);

} // namespace pvc1
