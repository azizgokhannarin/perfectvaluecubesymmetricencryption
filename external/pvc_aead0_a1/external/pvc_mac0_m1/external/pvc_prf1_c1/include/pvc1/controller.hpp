#pragma once

#include "pvc1/cube.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pvc1 {

// PVC-PRF-1 v0.9.0 freezes Controller A2 as Candidate C1; the code remains experimental and non-production.
enum class Domain : std::uint8_t {
    KeyForward   = 0x31,
    KeyReturn    = 0x72,
    KeySeal      = 0x9C,
    InputForward = 0xA5,
    InputReturn  = 0xC6,
    ReturnInit   = 0xD3,
    ReturnSeal   = 0x8B,
    Finalization = 0xE9,
    Squeeze      = 0x5A,
};

struct ControllerState {
    std::uint16_t axis_control{};
    std::uint16_t amount_control{};
    std::uint32_t feedback{};
    std::uint64_t transcript{};

    friend constexpr bool operator==(const ControllerState&, const ControllerState&) = default;
};

struct WorkingState {
    Cube cube = Cube::perfect();
    Coord cursor{0, 0, 0};
    Axis previous_axis = Axis::X;
    ControllerState controller{};
    std::uint64_t symbol_index{};

    friend bool operator==(const WorkingState&, const WorkingState&) = default;
};

struct ProbeSet {
    Coord axis_coord_0{};
    Coord axis_coord_1{};
    Coord amount_coord_0{};
    Coord amount_coord_1{};
    std::uint8_t axis_probe_0{};
    std::uint8_t axis_probe_1{};
    std::uint8_t amount_probe_0{};
    std::uint8_t amount_probe_1{};
};

struct MoveDecision {
    Axis axis{};
    std::uint8_t amount{};
    std::uint16_t axis_word{};
    std::uint16_t amount_word{};
    std::uint8_t axis_selector_bit{};
    std::uint8_t amount_slot{};
    std::uint16_t amount_permutation_seed{};
    std::array<std::uint8_t, 7> amount_permutation{};
    ProbeSet probes{};
};

struct MoveTrace {
    std::uint64_t symbol_index{};
    std::uint8_t phase{};
    std::uint8_t symbol{};
    Domain domain = Domain::InputForward;
    Coord cursor_before{};
    Coord cursor_after{};
    Axis previous_axis{};
    MoveDecision decision{};
    ControllerState controller_before{};
    ControllerState controller_after{};
    std::uint32_t line_feedback{};
};

[[nodiscard]] WorkingState make_initial_state(std::uint64_t research_seed);

// Re-key the controller lanes at a phase boundary. This is intended to prevent a
// forward-controller relation from carrying unchanged into a return phase.
void enter_domain(WorkingState& state, Domain domain, std::uint64_t sequence_length);

[[nodiscard]] MoveDecision preview_move(const WorkingState& state,
                                        std::uint8_t symbol,
                                        Domain domain,
                                        std::uint8_t phase);

[[nodiscard]] MoveTrace apply_move(WorkingState& state,
                                   std::uint8_t symbol,
                                   Domain domain,
                                   std::uint8_t phase);

void absorb_symbol(WorkingState& state,
                   std::uint8_t symbol,
                   Domain domain,
                   std::size_t moves_per_symbol,
                   std::vector<MoveTrace>* trace = nullptr);

void absorb_sequence(WorkingState& state,
                     std::span<const std::uint8_t> symbols,
                     Domain domain,
                     std::size_t moves_per_symbol,
                     std::vector<MoveTrace>* trace = nullptr);

[[nodiscard]] std::size_t cube_byte_distance(const Cube& left, const Cube& right);
[[nodiscard]] std::size_t controller_bit_distance(const ControllerState& left,
                                                  const ControllerState& right);
[[nodiscard]] std::uint64_t state_fingerprint(const WorkingState& state);
[[nodiscard]] const char* domain_name(Domain domain);

// Research inspection helper for auditing the bespoke amount mapper.
// This is not a cryptographic API and may change between prototype releases.
[[nodiscard]] std::array<std::uint8_t, 7> research_amount_permutation(std::uint16_t seed);

} // namespace pvc1
