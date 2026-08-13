#include "pvc1/return_pass.hpp"

#include <algorithm>
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
constexpr std::uint8_t byte16(std::uint16_t value, unsigned index) noexcept {
    return static_cast<std::uint8_t>(value >> ((index & 1U) * 8U));
}
constexpr std::uint8_t byte32(std::uint32_t value, unsigned index) noexcept {
    return static_cast<std::uint8_t>(value >> ((index & 3U) * 8U));
}
constexpr std::uint8_t byte64(std::uint64_t value, unsigned index) noexcept {
    return static_cast<std::uint8_t>(value >> ((index & 7U) * 8U));
}

void validate_profile(const ReturnProfile& profile) {
    const auto count_ok = [](std::size_t value) { return value > 0U && value <= 255U; };
    if (!count_ok(profile.init_symbols) || !count_ok(profile.init_moves)
        || !count_ok(profile.message_moves) || !count_ok(profile.seal_symbols)
        || !count_ok(profile.seal_moves)) {
        throw std::invalid_argument("return profile values must be in [1,255]");
    }
}

constexpr Coord coord_from_selector(std::uint64_t selector,
                                    std::size_t index,
                                    unsigned lane) noexcept {
    const auto mixed = rotl64(selector
        + static_cast<std::uint64_t>(index + 1U) * 0x9E3779B185EBCA87ULL
        + static_cast<std::uint64_t>(lane + 1U) * 0xD1342543DE82EF95ULL,
        static_cast<unsigned>(index * 11U + lane * 17U));
    return Coord{
        static_cast<std::uint8_t>(mixed & 7U),
        static_cast<std::uint8_t>((mixed >> 21U) & 7U),
        static_cast<std::uint8_t>((mixed >> 43U) & 7U),
    };
}

std::array<std::uint8_t, 16> controller_bytes(const ControllerState& controller) noexcept {
    return {
        byte16(controller.axis_control, 0U), byte16(controller.axis_control, 1U),
        byte16(controller.amount_control, 0U), byte16(controller.amount_control, 1U),
        byte32(controller.feedback, 0U), byte32(controller.feedback, 1U),
        byte32(controller.feedback, 2U), byte32(controller.feedback, 3U),
        byte64(controller.transcript, 0U), byte64(controller.transcript, 1U),
        byte64(controller.transcript, 2U), byte64(controller.transcript, 3U),
        byte64(controller.transcript, 4U), byte64(controller.transcript, 5U),
        byte64(controller.transcript, 6U), byte64(controller.transcript, 7U),
    };
}

std::array<std::uint8_t, 24> controller_bytes(const ControllerStateB& controller) noexcept {
    std::array<std::uint8_t, 24> bytes{};
    std::size_t output = 0;
    for (const auto lane : controller.lane) {
        for (unsigned i = 0; i < 4U; ++i) bytes[output++] = byte32(lane, i);
    }
    for (unsigned i = 0; i < 8U; ++i) bytes[output++] = byte64(controller.path, i);
    return bytes;
}

std::uint8_t init_symbol_a2(const WorkingState& snapshot,
                            std::uint64_t message_length,
                            std::size_t index) noexcept {
    const auto bytes = controller_bytes(snapshot.controller);
    const auto selector = snapshot.controller.transcript
        ^ (static_cast<std::uint64_t>(snapshot.controller.feedback) << 17U)
        ^ (static_cast<std::uint64_t>(snapshot.controller.axis_control) << 49U)
        ^ (static_cast<std::uint64_t>(snapshot.controller.amount_control) << 3U)
        ^ rotl64(message_length, static_cast<unsigned>(index + 7U))
        ^ snapshot.symbol_index;
    const auto c0 = coord_from_selector(selector, index, 0U);
    const auto c1 = coord_from_selector(rotl64(selector, 29U), index, 1U);
    const auto p0 = snapshot.cube.unchecked(c0);
    const auto p1 = snapshot.cube.unchecked(c1);
    const auto geometry = static_cast<std::uint8_t>(
        c0.x * 3U + c0.y * 5U + c0.z * 7U
        + c1.x * 11U + c1.y * 13U + c1.z * 17U
        + static_cast<std::uint8_t>(snapshot.previous_axis) * 19U);
    return static_cast<std::uint8_t>(
        bytes[index % bytes.size()]
        ^ rotl8(bytes[(index * 7U + 5U) % bytes.size()], static_cast<unsigned>(index))
        ^ static_cast<std::uint8_t>(p0 + rotl8(p1, static_cast<unsigned>(index + 3U)))
        ^ byte64(message_length, static_cast<unsigned>(index))
        ^ geometry ^ static_cast<std::uint8_t>(index * 0x5BU + 0xD3U));
}

std::uint8_t init_symbol_b(const WorkingStateB& snapshot,
                           std::uint64_t message_length,
                           std::size_t index) noexcept {
    const auto bytes = controller_bytes(snapshot.controller);
    const auto selector = snapshot.controller.path
        ^ (static_cast<std::uint64_t>(snapshot.controller.lane[0]) << 32U)
        ^ snapshot.controller.lane[3]
        ^ rotl64(message_length, static_cast<unsigned>(index + 11U))
        ^ snapshot.symbol_index;
    const auto c0 = coord_from_selector(selector, index, 2U);
    const auto c1 = coord_from_selector(rotl64(selector, 37U), index, 3U);
    const auto p0 = snapshot.cube.unchecked(c0);
    const auto p1 = snapshot.cube.unchecked(c1);
    const auto geometry = static_cast<std::uint8_t>(
        c0.x * 5U + c0.y * 7U + c0.z * 11U
        + c1.x * 13U + c1.y * 17U + c1.z * 19U
        + static_cast<std::uint8_t>(snapshot.previous_axis) * 23U);
    return static_cast<std::uint8_t>(
        bytes[index % bytes.size()]
        ^ rotl8(bytes[(index * 11U + 7U) % bytes.size()], static_cast<unsigned>(index + 1U))
        ^ static_cast<std::uint8_t>(rotl8(p0, 1U) + rotl8(p1, static_cast<unsigned>(index + 5U)))
        ^ byte64(message_length, static_cast<unsigned>(index + 2U))
        ^ geometry ^ static_cast<std::uint8_t>(index * 0x6DU + 0xB7U));
}

std::uint8_t return_symbol_a2(const WorkingState& snapshot,
                              const WorkingState& current,
                              std::uint8_t message_byte,
                              std::uint64_t message_length,
                              std::size_t reverse_index) noexcept {
    const auto bytes = controller_bytes(snapshot.controller);
    const auto selector = current.controller.transcript
        ^ rotl64(snapshot.controller.transcript, 23U)
        ^ (static_cast<std::uint64_t>(current.controller.feedback) << 29U)
        ^ static_cast<std::uint64_t>(reverse_index) * 0xA0761D6478BD642FULL;
    const auto coord = coord_from_selector(selector, reverse_index, 4U);
    const auto probe = current.cube.unchecked(coord);
    return static_cast<std::uint8_t>(
        message_byte
        ^ bytes[(reverse_index * 5U + 3U) % bytes.size()]
        ^ rotl8(probe, static_cast<unsigned>(reverse_index))
        ^ byte64(message_length, static_cast<unsigned>(reverse_index + 3U))
        ^ static_cast<std::uint8_t>(reverse_index * 0x3DU + 0xC6U));
}

std::uint8_t return_symbol_b(const WorkingStateB& snapshot,
                             const WorkingStateB& current,
                             std::uint8_t message_byte,
                             std::uint64_t message_length,
                             std::size_t reverse_index) noexcept {
    const auto bytes = controller_bytes(snapshot.controller);
    const auto selector = current.controller.path
        ^ rotl64(snapshot.controller.path, 31U)
        ^ (static_cast<std::uint64_t>(current.controller.lane[1]) << 32U)
        ^ current.controller.lane[2]
        ^ static_cast<std::uint64_t>(reverse_index) * 0xE7037ED1A0B428DBULL;
    const auto coord = coord_from_selector(selector, reverse_index, 5U);
    const auto probe = current.cube.unchecked(coord);
    return static_cast<std::uint8_t>(
        message_byte
        ^ bytes[(reverse_index * 7U + 5U) % bytes.size()]
        ^ rotl8(probe, static_cast<unsigned>(reverse_index + 2U))
        ^ byte64(message_length, static_cast<unsigned>(reverse_index + 5U))
        ^ static_cast<std::uint8_t>(reverse_index * 0x47U + 0xC6U));
}

std::uint8_t seal_symbol_a2(const WorkingState& snapshot,
                            const WorkingState& current,
                            std::uint64_t message_length,
                            std::size_t index) noexcept {
    const auto old_bytes = controller_bytes(snapshot.controller);
    const auto new_bytes = controller_bytes(current.controller);
    const auto selector = current.controller.transcript
        ^ rotl64(snapshot.controller.transcript, 41U)
        ^ static_cast<std::uint64_t>(index) * 0x8EBC6AF09C88C6E3ULL;
    const auto coord = coord_from_selector(selector, index, 6U);
    return static_cast<std::uint8_t>(
        old_bytes[(index * 3U + 1U) % old_bytes.size()]
        ^ new_bytes[(index * 11U + 7U) % new_bytes.size()]
        ^ current.cube.unchecked(coord)
        ^ byte64(message_length, static_cast<unsigned>(index + 1U))
        ^ static_cast<std::uint8_t>(index * 0x71U + 0x8BU));
}

std::uint8_t seal_symbol_b(const WorkingStateB& snapshot,
                           const WorkingStateB& current,
                           std::uint64_t message_length,
                           std::size_t index) noexcept {
    const auto old_bytes = controller_bytes(snapshot.controller);
    const auto new_bytes = controller_bytes(current.controller);
    const auto selector = current.controller.path
        ^ rotl64(snapshot.controller.path, 47U)
        ^ static_cast<std::uint64_t>(index) * 0x589965CC75374CC3ULL;
    const auto coord = coord_from_selector(selector, index, 7U);
    return static_cast<std::uint8_t>(
        old_bytes[(index * 5U + 2U) % old_bytes.size()]
        ^ new_bytes[(index * 13U + 9U) % new_bytes.size()]
        ^ rotl8(current.cube.unchecked(coord), static_cast<unsigned>(index + 1U))
        ^ byte64(message_length, static_cast<unsigned>(index + 4U))
        ^ static_cast<std::uint8_t>(index * 0x79U + 0x8BU));
}

template <typename Trace>
bool same_physical_move(const Trace& left, const Trace& right) noexcept {
    return left.decision.axis == right.decision.axis
        && left.decision.amount == right.decision.amount
        && left.cursor_before == right.cursor_before
        && left.cursor_after == right.cursor_after
        && left.domain == right.domain
        && left.phase == right.phase;
}

} // namespace

void apply_transcript_return_a2(WorkingState& state,
                                std::span<const std::uint8_t> message,
                                ReturnProfile profile,
                                std::vector<MoveTrace>* trace) {
    validate_profile(profile);
    const auto snapshot = state;
    const auto boundary = state_fingerprint(snapshot)
        ^ static_cast<std::uint64_t>(message.size()) * 0x9E3779B185EBCA87ULL
        ^ snapshot.symbol_index;
    enter_domain(state, Domain::ReturnInit, boundary);
    for (std::size_t i = 0; i < profile.init_symbols; ++i) {
        absorb_symbol(state, init_symbol_a2(snapshot, message.size(), i),
                      Domain::ReturnInit, profile.init_moves, trace);
    }

    enter_domain(state, Domain::InputReturn,
                 boundary ^ rotl64(snapshot.controller.transcript, 17U));
    for (std::size_t i = 0; i < message.size(); ++i) {
        const auto message_byte = message[message.size() - 1U - i];
        absorb_symbol(state, return_symbol_a2(snapshot, state, message_byte,
                                              message.size(), i),
                      Domain::InputReturn, profile.message_moves, trace);
    }

    enter_domain(state, Domain::ReturnSeal,
                 boundary ^ rotl64(state.controller.transcript, 43U));
    for (std::size_t i = 0; i < profile.seal_symbols; ++i) {
        absorb_symbol(state, seal_symbol_a2(snapshot, state, message.size(), i),
                      Domain::ReturnSeal, profile.seal_moves, trace);
    }
}

void apply_transcript_return_b(WorkingStateB& state,
                               std::span<const std::uint8_t> message,
                               ReturnProfile profile,
                               std::vector<MoveTraceB>* trace) {
    validate_profile(profile);
    const auto snapshot = state;
    const auto boundary = state_fingerprint_b(snapshot)
        ^ static_cast<std::uint64_t>(message.size()) * 0xD1342543DE82EF95ULL
        ^ snapshot.symbol_index;
    enter_domain_b(state, Domain::ReturnInit, boundary);
    for (std::size_t i = 0; i < profile.init_symbols; ++i) {
        absorb_symbol_b(state, init_symbol_b(snapshot, message.size(), i),
                        Domain::ReturnInit, profile.init_moves, trace);
    }

    enter_domain_b(state, Domain::InputReturn,
                   boundary ^ rotl64(snapshot.controller.path, 19U));
    for (std::size_t i = 0; i < message.size(); ++i) {
        const auto message_byte = message[message.size() - 1U - i];
        absorb_symbol_b(state, return_symbol_b(snapshot, state, message_byte,
                                               message.size(), i),
                        Domain::InputReturn, profile.message_moves, trace);
    }

    enter_domain_b(state, Domain::ReturnSeal,
                   boundary ^ rotl64(state.controller.path, 41U));
    for (std::size_t i = 0; i < profile.seal_symbols; ++i) {
        absorb_symbol_b(state, seal_symbol_b(snapshot, state, message.size(), i),
                        Domain::ReturnSeal, profile.seal_moves, trace);
    }
}

std::size_t common_move_prefix(std::span<const MoveTrace> left,
                               std::span<const MoveTrace> right) {
    const auto limit = std::min(left.size(), right.size());
    std::size_t prefix = 0;
    while (prefix < limit && same_physical_move(left[prefix], right[prefix])) ++prefix;
    return prefix;
}

std::size_t common_move_prefix_b(std::span<const MoveTraceB> left,
                                 std::span<const MoveTraceB> right) {
    const auto limit = std::min(left.size(), right.size());
    std::size_t prefix = 0;
    while (prefix < limit && same_physical_move(left[prefix], right[prefix])) ++prefix;
    return prefix;
}

} // namespace pvc1
