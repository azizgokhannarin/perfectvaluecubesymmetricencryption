#include "pvc1/finalization.hpp"

#include <array>
#include <bit>
#include <stdexcept>

namespace pvc1 {
namespace {

constexpr std::uint8_t rotl8(std::uint8_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 7U));
}
constexpr std::uint64_t rotl64(std::uint64_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 63U));
}
constexpr std::uint8_t byte32(std::uint32_t value, unsigned index) noexcept {
    return static_cast<std::uint8_t>(value >> ((index & 3U) * 8U));
}
constexpr std::uint8_t byte64(std::uint64_t value, unsigned index) noexcept {
    return static_cast<std::uint8_t>(value >> ((index & 7U) * 8U));
}

Coord output_coord(std::uint64_t selector, std::size_t round, std::uint8_t lane) noexcept {
    const auto mixed = rotl64(selector + static_cast<std::uint64_t>(round + 1U)
                              * 0x9E3779B185EBCA87ULL,
                              static_cast<unsigned>(lane * 13U + round));
    return Coord{
        static_cast<std::uint8_t>(mixed & 7U),
        static_cast<std::uint8_t>((mixed >> 17U) & 7U),
        static_cast<std::uint8_t>((mixed >> 41U) & 7U),
    };
}

std::array<std::uint8_t, 16> controller_bytes_a2(const ControllerState& c) noexcept {
    return {
        static_cast<std::uint8_t>(c.axis_control),
        static_cast<std::uint8_t>(c.axis_control >> 8U),
        static_cast<std::uint8_t>(c.amount_control),
        static_cast<std::uint8_t>(c.amount_control >> 8U),
        byte32(c.feedback, 0U), byte32(c.feedback, 1U), byte32(c.feedback, 2U), byte32(c.feedback, 3U),
        byte64(c.transcript, 0U), byte64(c.transcript, 1U), byte64(c.transcript, 2U), byte64(c.transcript, 3U),
        byte64(c.transcript, 4U), byte64(c.transcript, 5U), byte64(c.transcript, 6U), byte64(c.transcript, 7U),
    };
}

std::array<std::uint8_t, 24> controller_bytes_b(const ControllerStateB& c) noexcept {
    std::array<std::uint8_t, 24> bytes{};
    std::size_t out = 0;
    for (const auto lane : c.lane) {
        for (unsigned i = 0; i < 4U; ++i) bytes[out++] = byte32(lane, i);
    }
    for (unsigned i = 0; i < 8U; ++i) bytes[out++] = byte64(c.path, i);
    return bytes;
}

} // namespace

ResearchOutput research_bound_output_a2(WorkingState state,
                                         std::uint64_t message_length,
                                         std::size_t final_moves,
                                         std::size_t squeeze_moves) {
    if (final_moves == 0U || squeeze_moves == 0U) {
        throw std::invalid_argument("finalization move counts must be positive");
    }
    enter_domain(state, Domain::Finalization, message_length);
    const auto binding = controller_bytes_a2(state.controller);
    for (std::size_t i = 0; i < binding.size(); ++i) {
        const auto symbol = static_cast<std::uint8_t>(binding[i]
                          ^ byte64(message_length, static_cast<unsigned>(i))
                          ^ static_cast<std::uint8_t>(i * 29U + 0x53U));
        absorb_symbol(state, symbol, Domain::Finalization, final_moves);
    }
    enter_domain(state, Domain::Squeeze, 32U);

    ResearchOutput output{};
    for (std::size_t round = 0; round < output.size(); ++round) {
        const auto selector = state.controller.transcript
                            ^ (static_cast<std::uint64_t>(state.controller.feedback) << 19U)
                            ^ (static_cast<std::uint64_t>(state.controller.axis_control) << 3U)
                            ^ (static_cast<std::uint64_t>(state.controller.amount_control) << 43U);
        const auto c0 = output_coord(selector, round, 0U);
        const auto c1 = output_coord(rotl64(selector, 23U), round, 1U);
        const auto c2 = output_coord(rotl64(selector, 47U), round, 2U);
        const auto cube_mix = static_cast<std::uint8_t>(
            static_cast<std::uint8_t>(state.cube.unchecked(c0)
            + rotl8(state.cube.unchecked(c1), static_cast<unsigned>(round)))
            ^ rotl8(state.cube.unchecked(c2), static_cast<unsigned>(round + 3U)));
        const auto controller_mix = static_cast<std::uint8_t>(
            byte64(state.controller.transcript, static_cast<unsigned>(round))
            ^ byte32(state.controller.feedback, static_cast<unsigned>(round + 1U))
            ^ static_cast<std::uint8_t>(state.controller.axis_control >> ((round & 1U) * 8U))
            ^ static_cast<std::uint8_t>(state.controller.amount_control >> (((round + 1U) & 1U) * 8U)));
        output[round] = static_cast<std::uint8_t>(cube_mix + controller_mix
                                                 + static_cast<std::uint8_t>(round * 37U));
        absorb_symbol(state, static_cast<std::uint8_t>(output[round] ^ round),
                      Domain::Squeeze, squeeze_moves);
    }
    return output;
}

ResearchOutput research_bound_output_b(WorkingStateB state,
                                        std::uint64_t message_length,
                                        std::size_t final_moves,
                                        std::size_t squeeze_moves) {
    if (final_moves == 0U || squeeze_moves == 0U) {
        throw std::invalid_argument("finalization move counts must be positive");
    }
    enter_domain_b(state, Domain::Finalization, message_length);
    const auto binding = controller_bytes_b(state.controller);
    for (std::size_t i = 0; i < binding.size(); ++i) {
        const auto symbol = static_cast<std::uint8_t>(binding[i]
                          ^ byte64(message_length, static_cast<unsigned>(i))
                          ^ static_cast<std::uint8_t>(i * 31U + 0xA7U));
        absorb_symbol_b(state, symbol, Domain::Finalization, final_moves);
    }
    enter_domain_b(state, Domain::Squeeze, 32U);

    ResearchOutput output{};
    for (std::size_t round = 0; round < output.size(); ++round) {
        const auto selector = state.controller.path
                            ^ (static_cast<std::uint64_t>(state.controller.lane[0]) << 32U)
                            ^ state.controller.lane[3];
        const auto c0 = output_coord(selector, round, 3U);
        const auto c1 = output_coord(rotl64(selector, 29U), round, 5U);
        const auto c2 = output_coord(rotl64(selector, 53U), round, 7U);
        const auto cube_mix = static_cast<std::uint8_t>(
            state.cube.unchecked(c0)
            ^ static_cast<std::uint8_t>(rotl8(state.cube.unchecked(c1), static_cast<unsigned>(round + 1U))
            + rotl8(state.cube.unchecked(c2), static_cast<unsigned>(round + 5U))));
        const auto lane_index = round & 3U;
        const auto controller_mix = static_cast<std::uint8_t>(
            byte32(state.controller.lane[lane_index], static_cast<unsigned>(round))
            ^ byte32(state.controller.lane[(lane_index + 2U) & 3U], static_cast<unsigned>(round + 1U))
            ^ byte64(state.controller.path, static_cast<unsigned>(round + 3U)));
        output[round] = static_cast<std::uint8_t>(cube_mix + controller_mix
                                                 + static_cast<std::uint8_t>(round * 41U));
        absorb_symbol_b(state, static_cast<std::uint8_t>(output[round] ^ (round * 3U)),
                        Domain::Squeeze, squeeze_moves);
    }
    return output;
}

std::size_t output_bit_distance(const ResearchOutput& left,
                                const ResearchOutput& right) {
    std::size_t distance = 0;
    for (std::size_t i = 0; i < left.size(); ++i) {
        distance += static_cast<std::size_t>(std::popcount(
            static_cast<std::uint8_t>(left[i] ^ right[i])));
    }
    return distance;
}

} // namespace pvc1
