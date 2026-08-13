#include "pvc1/key_schedule.hpp"

#include <array>
#include <bit>
#include <stdexcept>

namespace pvc1 {
namespace {

constexpr std::uint64_t kPublicBootstrapSeed = 0x5056433150524631ULL; // "PVC1PRF1"

constexpr std::uint8_t rotl8(std::uint8_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 7U));
}

void validate_profile(const KeyScheduleProfile& profile) {
    const auto valid = [](std::size_t value) { return value > 0U && value <= 255U; };
    if (!valid(profile.forward_moves) || !valid(profile.return_moves)
        || !valid(profile.seal_moves)) {
        throw std::invalid_argument("key-schedule move counts must be in [1,255]");
    }
}

constexpr std::uint8_t position_mask(std::size_t index, std::uint8_t domain_tag) noexcept {
    const auto i = static_cast<std::uint8_t>(index);
    return static_cast<std::uint8_t>(i * 0x5BU + rotl8(i, 3U) + domain_tag);
}

constexpr std::uint8_t forward_cross_symbol(const ResearchKey256& key,
                                            std::size_t index) noexcept {
    const auto a = key[index];
    const auto b = key[(index + 11U) & 31U];
    const auto c = key[(index + 23U) & 31U];
    return static_cast<std::uint8_t>(
        a ^ rotl8(b, static_cast<unsigned>((index % 7U) + 1U))
          ^ static_cast<std::uint8_t>(rotl8(c, 3U) + position_mask(index, 0x31U)));
}

constexpr std::uint8_t return_symbol(const ResearchKey256& key,
                                     std::size_t reverse_index) noexcept {
    const auto index = 31U - reverse_index;
    const auto a = key[index];
    const auto b = key[(index + 7U) & 31U];
    const auto c = key[(index + 19U) & 31U];
    return static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(a + rotl8(b, 3U) + rotl8(c, 5U))
        ^ position_mask(reverse_index, 0x72U));
}

constexpr std::uint8_t seal_symbol(const ResearchKey256& key,
                                   std::size_t index) noexcept {
    const auto a = key[index];
    const auto b = key[index + 16U];
    const auto c = key[(index + 5U) & 31U];
    const auto d = key[(index + 27U) & 31U];
    return static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(a + rotl8(b, 1U) + rotl8(c, 4U))
        ^ rotl8(d, 6U) ^ position_mask(index, 0x9CU));
}

std::array<std::uint8_t, 8> key_header() noexcept {
    return {0x50U, 0x56U, 0x43U, 0x31U, 0x4BU, 0x45U, 0x59U, 0x20U};
}

void absorb_key_a2(WorkingState& state,
                   const ResearchKey256& key,
                   KeyScheduleProfile profile,
                   std::vector<MoveTrace>* trace) {
    enter_domain(state, Domain::KeyForward, key.size());
    const auto header = key_header();
    absorb_sequence(state, header, Domain::KeyForward, profile.forward_moves, trace);
    for (std::size_t i = 0; i < key.size(); ++i) {
        const std::array<std::uint8_t, 2> symbols{
            static_cast<std::uint8_t>(key[i] ^ position_mask(i, 0xA5U)),
            forward_cross_symbol(key, i),
        };
        absorb_sequence(state, symbols, Domain::KeyForward, profile.forward_moves, trace);
    }

    enter_domain(state, Domain::KeyReturn, key.size());
    for (std::size_t i = 0; i < key.size(); ++i) {
        absorb_symbol(state, return_symbol(key, i), Domain::KeyReturn,
                      profile.return_moves, trace);
    }

    enter_domain(state, Domain::KeySeal, 256U);
    for (std::size_t i = 0; i < 16U; ++i) {
        absorb_symbol(state, seal_symbol(key, i), Domain::KeySeal,
                      profile.seal_moves, trace);
    }
    state.symbol_index = 0U;
}

void absorb_key_b(WorkingStateB& state,
                  const ResearchKey256& key,
                  KeyScheduleProfile profile,
                  std::vector<MoveTraceB>* trace) {
    enter_domain_b(state, Domain::KeyForward, key.size());
    const auto header = key_header();
    absorb_sequence_b(state, header, Domain::KeyForward, profile.forward_moves, trace);
    for (std::size_t i = 0; i < key.size(); ++i) {
        const std::array<std::uint8_t, 2> symbols{
            static_cast<std::uint8_t>(key[i] ^ position_mask(i, 0xA5U)),
            forward_cross_symbol(key, i),
        };
        absorb_sequence_b(state, symbols, Domain::KeyForward, profile.forward_moves, trace);
    }

    enter_domain_b(state, Domain::KeyReturn, key.size());
    for (std::size_t i = 0; i < key.size(); ++i) {
        absorb_symbol_b(state, return_symbol(key, i), Domain::KeyReturn,
                        profile.return_moves, trace);
    }

    enter_domain_b(state, Domain::KeySeal, 256U);
    for (std::size_t i = 0; i < 16U; ++i) {
        absorb_symbol_b(state, seal_symbol(key, i), Domain::KeySeal,
                        profile.seal_moves, trace);
    }
    state.symbol_index = 0U;
}

} // namespace

WorkingState make_keyed_state_a2(const ResearchKey256& key,
                                 KeyScheduleProfile profile,
                                 std::vector<MoveTrace>* trace) {
    validate_profile(profile);
    auto state = make_initial_state(kPublicBootstrapSeed);
    absorb_key_a2(state, key, profile, trace);
    return state;
}

WorkingStateB make_keyed_state_b(const ResearchKey256& key,
                                 KeyScheduleProfile profile,
                                 std::vector<MoveTraceB>* trace) {
    validate_profile(profile);
    auto state = make_initial_state_b(kPublicBootstrapSeed);
    absorb_key_b(state, key, profile, trace);
    return state;
}

WorkingState evaluate_keyed_a2(const ResearchKey256& key,
                               std::span<const std::uint8_t> message,
                               std::size_t moves_per_symbol,
                               KeyScheduleProfile profile) {
    auto state = make_keyed_state_a2(key, profile);
    enter_domain(state, Domain::InputForward, message.size());
    absorb_sequence(state, message, Domain::InputForward, moves_per_symbol);
    return state;
}

WorkingStateB evaluate_keyed_b(const ResearchKey256& key,
                               std::span<const std::uint8_t> message,
                               std::size_t moves_per_symbol,
                               KeyScheduleProfile profile) {
    auto state = make_keyed_state_b(key, profile);
    enter_domain_b(state, Domain::InputForward, message.size());
    absorb_sequence_b(state, message, Domain::InputForward, moves_per_symbol);
    return state;
}

ResearchOutput research_keyed_output_a2(const ResearchKey256& key,
                                        std::span<const std::uint8_t> message,
                                        std::size_t moves_per_symbol,
                                        std::size_t final_moves,
                                        std::size_t squeeze_moves,
                                        KeyScheduleProfile profile) {
    return research_bound_output_a2(
        evaluate_keyed_a2(key, message, moves_per_symbol, profile),
        message.size(), final_moves, squeeze_moves);
}

ResearchOutput research_keyed_output_b(const ResearchKey256& key,
                                       std::span<const std::uint8_t> message,
                                       std::size_t moves_per_symbol,
                                       std::size_t final_moves,
                                       std::size_t squeeze_moves,
                                       KeyScheduleProfile profile) {
    return research_bound_output_b(
        evaluate_keyed_b(key, message, moves_per_symbol, profile),
        message.size(), final_moves, squeeze_moves);
}


WorkingState evaluate_keyed_return_a2(const ResearchKey256& key,
                                      std::span<const std::uint8_t> message,
                                      std::size_t forward_moves,
                                      ReturnProfile return_profile,
                                      KeyScheduleProfile key_profile,
                                      std::vector<MoveTrace>* return_trace) {
    auto state = evaluate_keyed_a2(key, message, forward_moves, key_profile);
    apply_transcript_return_a2(state, message, return_profile, return_trace);
    return state;
}

WorkingStateB evaluate_keyed_return_b(const ResearchKey256& key,
                                      std::span<const std::uint8_t> message,
                                      std::size_t forward_moves,
                                      ReturnProfile return_profile,
                                      KeyScheduleProfile key_profile,
                                      std::vector<MoveTraceB>* return_trace) {
    auto state = evaluate_keyed_b(key, message, forward_moves, key_profile);
    apply_transcript_return_b(state, message, return_profile, return_trace);
    return state;
}

ResearchOutput research_keyed_return_output_a2(const ResearchKey256& key,
                                               std::span<const std::uint8_t> message,
                                               std::size_t forward_moves,
                                               ReturnProfile return_profile,
                                               std::size_t final_moves,
                                               std::size_t squeeze_moves,
                                               KeyScheduleProfile key_profile) {
    return research_bound_output_a2(
        evaluate_keyed_return_a2(key, message, forward_moves, return_profile, key_profile),
        message.size(), final_moves, squeeze_moves);
}

ResearchOutput research_keyed_return_output_b(const ResearchKey256& key,
                                               std::span<const std::uint8_t> message,
                                               std::size_t forward_moves,
                                               ReturnProfile return_profile,
                                               std::size_t final_moves,
                                               std::size_t squeeze_moves,
                                               KeyScheduleProfile key_profile) {
    return research_bound_output_b(
        evaluate_keyed_return_b(key, message, forward_moves, return_profile, key_profile),
        message.size(), final_moves, squeeze_moves);
}

} // namespace pvc1
