#pragma once

#include "pvc1/controller.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pvc1 {

// PVC-PRF-1 Controller Prototype B is intentionally architecturally distinct
// from A2. It uses a four-lane ring controller and competitive amount scoring.
struct ControllerStateB {
    std::array<std::uint32_t, 4> lane{};
    std::uint64_t path{};

    friend constexpr bool operator==(const ControllerStateB&, const ControllerStateB&) = default;
};

struct WorkingStateB {
    Cube cube = Cube::perfect();
    Coord cursor{0, 0, 0};
    Axis previous_axis = Axis::X;
    ControllerStateB controller{};
    std::uint64_t symbol_index{};

    friend bool operator==(const WorkingStateB&, const WorkingStateB&) = default;
};

struct ProbeSetB {
    Coord axis_coord_0{};
    Coord axis_coord_1{};
    Coord amount_coord_0{};
    Coord amount_coord_1{};
    std::uint8_t axis_probe_0{};
    std::uint8_t axis_probe_1{};
    std::uint8_t amount_probe_0{};
    std::uint8_t amount_probe_1{};
};

struct MoveDecisionB {
    Axis axis{};
    std::uint8_t amount{};
    std::array<std::uint32_t, 2> axis_scores{};
    std::array<std::uint32_t, 7> amount_scores{};
    std::array<std::uint8_t, 7> candidate_probes{};
    ProbeSetB probes{};
};

struct MoveTraceB {
    std::uint64_t symbol_index{};
    std::uint8_t phase{};
    std::uint8_t symbol{};
    Domain domain = Domain::InputForward;
    Coord cursor_before{};
    Coord cursor_after{};
    Axis previous_axis{};
    MoveDecisionB decision{};
    ControllerStateB controller_before{};
    ControllerStateB controller_after{};
    std::uint32_t line_feedback{};
};

[[nodiscard]] WorkingStateB make_initial_state_b(std::uint64_t research_seed);
void enter_domain_b(WorkingStateB& state, Domain domain, std::uint64_t sequence_length);
[[nodiscard]] MoveDecisionB preview_move_b(const WorkingStateB& state,
                                           std::uint8_t symbol,
                                           Domain domain,
                                           std::uint8_t phase);
[[nodiscard]] MoveTraceB apply_move_b(WorkingStateB& state,
                                      std::uint8_t symbol,
                                      Domain domain,
                                      std::uint8_t phase);
void absorb_symbol_b(WorkingStateB& state,
                     std::uint8_t symbol,
                     Domain domain,
                     std::size_t moves_per_symbol,
                     std::vector<MoveTraceB>* trace = nullptr);
void absorb_sequence_b(WorkingStateB& state,
                       std::span<const std::uint8_t> symbols,
                       Domain domain,
                       std::size_t moves_per_symbol,
                       std::vector<MoveTraceB>* trace = nullptr);

[[nodiscard]] std::size_t controller_bit_distance_b(const ControllerStateB& left,
                                                     const ControllerStateB& right);
[[nodiscard]] std::uint64_t state_fingerprint_b(const WorkingStateB& state);

} // namespace pvc1
