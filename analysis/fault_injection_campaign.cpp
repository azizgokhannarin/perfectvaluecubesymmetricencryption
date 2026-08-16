#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include "pvc1/key_schedule.hpp"
#include "pvcaead0/aead.hpp"
#include "pvcmac0/mac.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using pvcrotsymenc1::Key256;
using pvcrotsymenc1::KeyPair512;
using pvcrotsymenc1::Nonce192;
using pvcrotsymenc1::SealedMessage;
using pvcrotsymenc1::TagSize;

constexpr std::uint64_t kSeed = UINT64_C(0x4641554C54494E4A);
constexpr std::size_t kPlaintextBytes = 96U;
constexpr std::size_t kAssociatedDataBytes = 33U;
constexpr std::size_t kCubeStateBits = 512U * 8U;
constexpr std::size_t kControllerStateBits = 16U + 16U + 32U + 64U;
constexpr std::size_t kC1StateBits = kCubeStateBits + kControllerStateBits;
constexpr std::size_t kStreamBlockBytes = 32U;
constexpr std::size_t kReplicationCasesPerProfile = 8U;
constexpr std::size_t kExtendedOutputBytes = 64U;
constexpr std::size_t kFinalizationBindingBytes = 16U;
constexpr std::size_t kCanonicalOutputBytes = 32U;
constexpr std::size_t kTraceStageCount = 19U + kExtendedOutputBytes;
constexpr std::size_t kNoIndex = std::numeric_limits<std::size_t>::max();
constexpr std::uint64_t kFamilySeed = UINT64_C(0x4641554C5446414D);

struct CampaignCase {
    KeyPair512 keys;
    Nonce192 nonce;
    std::vector<std::uint8_t> associated_data;
    std::vector<std::uint8_t> plaintext;
    TagSize tag_size{};
    SealedMessage sealed;
};

struct DistanceStats {
    std::uint64_t attempts{};
    std::uint64_t unchanged{};
    std::uint64_t one_bit{};
    std::uint64_t distance_sum{};
    std::size_t minimum = std::numeric_limits<std::size_t>::max();
    std::size_t maximum{};
};

enum class StateRegion : std::size_t {
    Cube,
    AxisControl,
    AmountControl,
    Feedback,
    Transcript,
    Count,
};

struct StateLocalization {
    std::array<std::uint64_t, static_cast<std::size_t>(StateRegion::Count)>
        unchanged_by_region{};
    std::vector<std::array<std::size_t, 2>> one_bit_candidates;
};

struct StateDistance {
    std::size_t cube_bits{};
    std::size_t controller_bits{};
    std::size_t metadata_bits{};

    [[nodiscard]] std::size_t total() const noexcept {
        return cube_bits + controller_bits + metadata_bits;
    }
};

struct FinalizationTrace {
    std::array<std::uint8_t, kExtendedOutputBytes> output{};
    std::array<pvc1::WorkingState, kTraceStageCount> stages{};
};

struct DiagnosticRecord {
    std::size_t profile_bits{};
    std::size_t case_index{};
    std::size_t state_bit{};
    std::size_t prefix_distance{};
    std::size_t full_distance{};
    std::size_t extended_distance{};
    std::size_t first_changed_byte = kNoIndex;
    std::size_t changed_prefix_bit = kNoIndex;
    std::size_t first_controller_stage = kNoIndex;
    std::size_t first_non_single_stage = kNoIndex;
    bool single_bit_until_first_output{};
};

struct GeometryCounts {
    std::array<std::uint64_t, 8> x{};
    std::array<std::uint64_t, 8> y{};
    std::array<std::uint64_t, 8> z{};
    std::array<std::uint64_t, 8> cell_bit{};
    std::uint64_t non_cube{};
};

struct DiagnosticAggregate {
    std::uint64_t count{};
    std::uint64_t entry_checks{};
    std::uint64_t mirror_checks{};
    std::uint64_t full_unchanged{};
    std::uint64_t full_one_bit{};
    std::uint64_t extended_unchanged{};
    std::uint64_t extended_one_bit{};
    std::uint64_t first_change_after_prefix{};
    std::uint64_t no_change_in_extended{};
    std::uint64_t single_bit_until_first_output{};
    std::uint64_t controller_diverged_during_finalization_entry{};
    std::uint64_t controller_diverged_during_binding{};
    std::uint64_t controller_diverged_during_squeeze_entry{};
    std::uint64_t controller_diverged_during_squeeze{};
    std::uint64_t controller_never_diverged{};
    DistanceStats full_distance;
    DistanceStats extended_distance;
    GeometryCounts geometry;
};

using CubeFaultSet = std::bitset<kCubeStateBits>;

struct FamilyFaultSets {
    CubeFaultSet unchanged;
    CubeFaultSet one_bit;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

void require(bool condition, const std::string& message) {
    if (!condition) fail(message);
}

std::uint64_t next_random(std::uint64_t& state) noexcept {
    state += UINT64_C(0x9E3779B97F4A7C15);
    auto value = state;
    value = (value ^ (value >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31U);
}

template <std::size_t Size>
std::array<std::uint8_t, Size> random_array(std::uint64_t& state) {
    std::array<std::uint8_t, Size> output{};
    std::uint64_t word{};
    for (std::size_t index = 0U; index < output.size(); ++index) {
        if ((index % 8U) == 0U) word = next_random(state);
        output[index] = static_cast<std::uint8_t>(word & UINT64_C(0xFF));
        word >>= 8U;
    }
    return output;
}

std::vector<std::uint8_t> random_vector(std::uint64_t& state, std::size_t size) {
    std::vector<std::uint8_t> output(size);
    std::uint64_t word{};
    for (std::size_t index = 0U; index < output.size(); ++index) {
        if ((index % 8U) == 0U) word = next_random(state);
        output[index] = static_cast<std::uint8_t>(word & UINT64_C(0xFF));
        word >>= 8U;
    }
    return output;
}

pvcaead0::TagSize to_a1_tag_size(TagSize size) {
    switch (size) {
        case TagSize::Bits128: return pvcaead0::TagSize::Bits128;
        case TagSize::Bits192: return pvcaead0::TagSize::Bits192;
        case TagSize::Bits256: return pvcaead0::TagSize::Bits256;
    }
    fail("invalid RotSymEnc tag size");
}

pvcmac0::TagSize to_mac_tag_size(TagSize size) {
    switch (size) {
        case TagSize::Bits128: return pvcmac0::TagSize::Bits128;
        case TagSize::Bits192: return pvcmac0::TagSize::Bits192;
        case TagSize::Bits256: return pvcmac0::TagSize::Bits256;
    }
    fail("invalid RotSymEnc tag size");
}

void flip_vector_bit(std::vector<std::uint8_t>& value, std::size_t bit) {
    require(bit < value.size() * 8U, "vector fault bit is outside value");
    value[bit / 8U] ^= static_cast<std::uint8_t>(1U << (bit % 8U));
}

void flip_nonce_bit(Nonce192& nonce, std::size_t bit) {
    require(bit < nonce.size() * 8U, "nonce fault bit is outside value");
    nonce[bit / 8U] ^= static_cast<std::uint8_t>(1U << (bit % 8U));
}

std::size_t bit_distance(std::span<const std::uint8_t> left,
                         std::span<const std::uint8_t> right) {
    require(left.size() == right.size(), "bit distance length mismatch");
    std::size_t distance = 0U;
    for (std::size_t index = 0U; index < left.size(); ++index) {
        distance += static_cast<std::size_t>(std::popcount(
            static_cast<unsigned>(left[index] ^ right[index])));
    }
    return distance;
}

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

pvc1::Coord diagnostic_output_coord(std::uint64_t selector,
                                    std::size_t round,
                                    std::uint8_t lane) noexcept {
    const auto mixed = rotl64(
        selector + static_cast<std::uint64_t>(round + 1U)
                 * UINT64_C(0x9E3779B185EBCA87),
        static_cast<unsigned>(lane * 13U + round));
    return pvc1::Coord{
        static_cast<std::uint8_t>(mixed & 7U),
        static_cast<std::uint8_t>((mixed >> 17U) & 7U),
        static_cast<std::uint8_t>((mixed >> 41U) & 7U),
    };
}

std::array<std::uint8_t, kFinalizationBindingBytes> diagnostic_controller_bytes(
    const pvc1::ControllerState& controller) noexcept {
    return {
        static_cast<std::uint8_t>(controller.axis_control),
        static_cast<std::uint8_t>(controller.axis_control >> 8U),
        static_cast<std::uint8_t>(controller.amount_control),
        static_cast<std::uint8_t>(controller.amount_control >> 8U),
        byte32(controller.feedback, 0U),
        byte32(controller.feedback, 1U),
        byte32(controller.feedback, 2U),
        byte32(controller.feedback, 3U),
        byte64(controller.transcript, 0U),
        byte64(controller.transcript, 1U),
        byte64(controller.transcript, 2U),
        byte64(controller.transcript, 3U),
        byte64(controller.transcript, 4U),
        byte64(controller.transcript, 5U),
        byte64(controller.transcript, 6U),
        byte64(controller.transcript, 7U),
    };
}

std::uint8_t diagnostic_output_byte(const pvc1::WorkingState& state,
                                    std::size_t round) noexcept {
    const auto selector = state.controller.transcript
                        ^ (static_cast<std::uint64_t>(state.controller.feedback) << 19U)
                        ^ (static_cast<std::uint64_t>(state.controller.axis_control) << 3U)
                        ^ (static_cast<std::uint64_t>(state.controller.amount_control) << 43U);
    const auto c0 = diagnostic_output_coord(selector, round, 0U);
    const auto c1 = diagnostic_output_coord(rotl64(selector, 23U), round, 1U);
    const auto c2 = diagnostic_output_coord(rotl64(selector, 47U), round, 2U);
    const auto cube_mix = static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(state.cube.unchecked(c0)
        + rotl8(state.cube.unchecked(c1), static_cast<unsigned>(round)))
        ^ rotl8(state.cube.unchecked(c2), static_cast<unsigned>(round + 3U)));
    const auto controller_mix = static_cast<std::uint8_t>(
        byte64(state.controller.transcript, static_cast<unsigned>(round))
        ^ byte32(state.controller.feedback, static_cast<unsigned>(round + 1U))
        ^ static_cast<std::uint8_t>(
            state.controller.axis_control >> ((round & 1U) * 8U))
        ^ static_cast<std::uint8_t>(
            state.controller.amount_control >> (((round + 1U) & 1U) * 8U)));
    return static_cast<std::uint8_t>(
        cube_mix + controller_mix + static_cast<std::uint8_t>(round * 37U));
}

StateDistance working_state_distance(const pvc1::WorkingState& left,
                                     const pvc1::WorkingState& right) {
    StateDistance distance;
    for (std::size_t index = 0U; index < left.cube.storage().size(); ++index) {
        distance.cube_bits += static_cast<std::size_t>(std::popcount(
            static_cast<unsigned>(
                left.cube.storage()[index] ^ right.cube.storage()[index])));
    }
    distance.controller_bits = pvc1::controller_bit_distance(
        left.controller, right.controller);
    distance.metadata_bits += static_cast<std::size_t>(std::popcount(
        static_cast<unsigned>(left.cursor.x ^ right.cursor.x)));
    distance.metadata_bits += static_cast<std::size_t>(std::popcount(
        static_cast<unsigned>(left.cursor.y ^ right.cursor.y)));
    distance.metadata_bits += static_cast<std::size_t>(std::popcount(
        static_cast<unsigned>(left.cursor.z ^ right.cursor.z)));
    distance.metadata_bits += static_cast<std::size_t>(std::popcount(
        static_cast<unsigned>(left.previous_axis)
        ^ static_cast<unsigned>(right.previous_axis)));
    distance.metadata_bits += static_cast<std::size_t>(std::popcount(
        left.symbol_index ^ right.symbol_index));
    return distance;
}

FinalizationTrace trace_finalization(pvc1::WorkingState state,
                                     std::uint64_t message_length) {
    FinalizationTrace trace;
    std::size_t stage = 0U;
    trace.stages[stage++] = state;

    pvc1::enter_domain(state, pvc1::Domain::Finalization, message_length);
    trace.stages[stage++] = state;
    const auto binding = diagnostic_controller_bytes(state.controller);
    for (std::size_t index = 0U; index < binding.size(); ++index) {
        const auto symbol = static_cast<std::uint8_t>(
            binding[index]
            ^ byte64(message_length, static_cast<unsigned>(index))
            ^ static_cast<std::uint8_t>(index * 29U + 0x53U));
        pvc1::absorb_symbol(state, symbol, pvc1::Domain::Finalization, 4U);
        trace.stages[stage++] = state;
    }

    pvc1::enter_domain(state, pvc1::Domain::Squeeze, kCanonicalOutputBytes);
    trace.stages[stage++] = state;
    for (std::size_t round = 0U; round < trace.output.size(); ++round) {
        trace.output[round] = diagnostic_output_byte(state, round);
        pvc1::absorb_symbol(
            state,
            static_cast<std::uint8_t>(trace.output[round] ^ round),
            pvc1::Domain::Squeeze,
            2U);
        trace.stages[stage++] = state;
    }
    require(stage == trace.stages.size(), "diagnostic trace stage count mismatch");
    return trace;
}

std::size_t first_changed_byte(
    const std::array<std::uint8_t, kExtendedOutputBytes>& left,
    const std::array<std::uint8_t, kExtendedOutputBytes>& right) noexcept {
    for (std::size_t index = 0U; index < left.size(); ++index) {
        if (left[index] != right[index]) return index;
    }
    return kNoIndex;
}

std::size_t first_controller_stage(const FinalizationTrace& canonical,
                                   const FinalizationTrace& faulted) {
    for (std::size_t stage = 0U; stage < canonical.stages.size(); ++stage) {
        if (pvc1::controller_bit_distance(
                canonical.stages[stage].controller,
                faulted.stages[stage].controller) != 0U) {
            return stage;
        }
    }
    return kNoIndex;
}

std::size_t first_non_single_stage(const FinalizationTrace& canonical,
                                   const FinalizationTrace& faulted) {
    for (std::size_t stage = 0U; stage < canonical.stages.size(); ++stage) {
        if (working_state_distance(
                canonical.stages[stage], faulted.stages[stage]).total() != 1U) {
            return stage;
        }
    }
    return kNoIndex;
}

bool remains_single_bit_until_output(const FinalizationTrace& canonical,
                                     const FinalizationTrace& faulted,
                                     std::size_t output_byte) {
    const auto last_state_stage = 18U + output_byte;
    require(last_state_stage < canonical.stages.size(),
            "diagnostic output byte exceeds trace stages");
    for (std::size_t stage = 0U; stage <= last_state_stage; ++stage) {
        if (working_state_distance(
                canonical.stages[stage], faulted.stages[stage]).total() != 1U) {
            return false;
        }
    }
    return true;
}

void observe(DistanceStats& stats, std::size_t distance) {
    ++stats.attempts;
    stats.distance_sum += static_cast<std::uint64_t>(distance);
    stats.minimum = std::min(stats.minimum, distance);
    stats.maximum = std::max(stats.maximum, distance);
    if (distance == 0U) ++stats.unchanged;
    if (distance == 1U) ++stats.one_bit;
}

StateRegion state_region(std::size_t bit) {
    require(bit < kC1StateBits, "state-region bit is outside model");
    if (bit < kCubeStateBits) return StateRegion::Cube;
    bit -= kCubeStateBits;
    if (bit < 16U) return StateRegion::AxisControl;
    bit -= 16U;
    if (bit < 16U) return StateRegion::AmountControl;
    bit -= 16U;
    if (bit < 32U) return StateRegion::Feedback;
    return StateRegion::Transcript;
}

const char* state_region_name(StateRegion region) {
    switch (region) {
        case StateRegion::Cube: return "cube";
        case StateRegion::AxisControl: return "axis_control";
        case StateRegion::AmountControl: return "amount_control";
        case StateRegion::Feedback: return "feedback";
        case StateRegion::Transcript: return "transcript";
        case StateRegion::Count: break;
    }
    fail("invalid C1 state region");
}

std::size_t changed_bit(std::span<const std::uint8_t> left,
                        std::span<const std::uint8_t> right) {
    require(bit_distance(left, right) == 1U,
            "changed-bit localization requires distance one");
    for (std::size_t bit = 0U; bit < left.size() * 8U; ++bit) {
        const auto mask = static_cast<std::uint8_t>(1U << (bit % 8U));
        if (((left[bit / 8U] ^ right[bit / 8U]) & mask) != 0U) return bit;
    }
    fail("distance-one output did not expose a changed bit");
}

void localize_state_fault(StateLocalization& localization,
                          std::size_t state_bit,
                          std::size_t distance,
                          std::span<const std::uint8_t> canonical,
                          std::span<const std::uint8_t> faulted) {
    if (distance == 0U) {
        const auto region = static_cast<std::size_t>(state_region(state_bit));
        ++localization.unchanged_by_region[region];
    }
    if (distance == 1U) {
        localization.one_bit_candidates.push_back(
            {state_bit, changed_bit(canonical, faulted)});
    }
}

void print_localization(const char* label,
                        std::size_t profile_bits,
                        const StateLocalization& localization) {
    std::cout << label << " profile_bits=" << profile_bits;
    for (std::size_t index = 0U;
         index < static_cast<std::size_t>(StateRegion::Count);
         ++index) {
        const auto region = static_cast<StateRegion>(index);
        std::cout << " unchanged_" << state_region_name(region)
                  << '=' << localization.unchanged_by_region[index];
    }
    std::cout << '\n';
    for (const auto& candidate : localization.one_bit_candidates) {
        std::cout << label << "-one-bit-candidate profile_bits=" << profile_bits
                  << " state_bit=" << candidate[0]
                  << " state_region=" << state_region_name(state_region(candidate[0]))
                  << " tag_or_output_bit=" << candidate[1] << '\n';
    }
}

void print_distance(const char* label, const DistanceStats& stats) {
    require(stats.attempts > 0U, "cannot print empty distance statistics");
    std::cout << label
              << " faults=" << stats.attempts
              << " unchanged=" << stats.unchanged
              << " one_bit=" << stats.one_bit
              << " distance_min=" << stats.minimum
              << " distance_max=" << stats.maximum
              << " distance_sum=" << stats.distance_sum << '\n';
}

CampaignCase make_case(std::uint64_t& state, TagSize tag_size) {
    CampaignCase test_case;
    test_case.keys.encryption_key = random_array<32U>(state);
    test_case.keys.authentication_key = random_array<32U>(state);
    require(test_case.keys.encryption_key != test_case.keys.authentication_key,
            "deterministic role keys unexpectedly match");
    test_case.nonce = random_array<24U>(state);
    test_case.associated_data = random_vector(state, kAssociatedDataBytes);
    test_case.plaintext = random_vector(state, kPlaintextBytes);
    test_case.tag_size = tag_size;
    test_case.sealed = pvcrotsymenc1::seal(
        test_case.keys,
        test_case.nonce,
        test_case.associated_data,
        test_case.plaintext,
        tag_size);
    const auto opened = pvcrotsymenc1::open(
        test_case.keys,
        test_case.nonce,
        test_case.associated_data,
        test_case.sealed.ciphertext,
        test_case.sealed.tag);
    require(opened.has_value() && *opened == test_case.plaintext,
            "baseline canonical round trip failed");
    return test_case;
}

std::array<CampaignCase, 3> make_cases() {
    std::uint64_t state = kSeed;
    return {
        make_case(state, TagSize::Bits128),
        make_case(state, TagSize::Bits192),
        make_case(state, TagSize::Bits256),
    };
}

bool comparison_model(std::span<const std::uint8_t> expected,
                      std::span<const std::uint8_t> supplied,
                      std::size_t comparison_length,
                      std::optional<std::size_t> skipped_byte = std::nullopt) {
    require(comparison_length <= expected.size(), "comparison exceeds expected tag");
    require(comparison_length <= supplied.size(), "comparison exceeds supplied tag");
    std::uint8_t difference = 0U;
    for (std::size_t index = 0U; index < comparison_length; ++index) {
        if (skipped_byte.has_value() && index == *skipped_byte) continue;
        difference = static_cast<std::uint8_t>(
            difference | (expected[index] ^ supplied[index]));
    }
    return difference == 0U;
}

pvc1::ResearchOutput stream_output(const Key256& key,
                                   const Nonce192& nonce,
                                   std::uint64_t counter,
                                   TagSize tag_size) {
    const auto frame = pvcaead0::frame_stream_block(
        nonce, counter, to_a1_tag_size(tag_size));
    return pvc1::research_keyed_return_output_a2(key, frame);
}

std::vector<std::uint8_t> apply_stream(
    const Key256& key,
    const Nonce192& nonce,
    std::span<const std::uint8_t> input,
    TagSize tag_size,
    std::optional<std::size_t> faulted_block = std::nullopt,
    std::uint64_t counter_xor = 0U) {
    std::vector<std::uint8_t> output(input.size());
    const auto blocks = input.empty()
        ? 0U
        : 1U + ((input.size() - 1U) / kStreamBlockBytes);
    for (std::size_t block = 0U; block < blocks; ++block) {
        auto counter = static_cast<std::uint64_t>(block);
        if (faulted_block.has_value() && block == *faulted_block) {
            counter ^= counter_xor;
        }
        const auto stream = stream_output(key, nonce, counter, tag_size);
        const auto offset = block * kStreamBlockBytes;
        const auto take = std::min(kStreamBlockBytes, input.size() - offset);
        for (std::size_t index = 0U; index < take; ++index) {
            output[offset + index] = static_cast<std::uint8_t>(
                input[offset + index] ^ stream[index]);
        }
    }
    return output;
}

void flip_c1_state_bit(pvc1::WorkingState& state, std::size_t bit) {
    require(bit < kC1StateBits, "C1 state fault bit is outside model");
    if (bit < kCubeStateBits) {
        const auto cell = bit / 8U;
        const auto bit_in_cell = bit % 8U;
        const pvc1::Coord coordinate{
            static_cast<std::uint8_t>(cell & 7U),
            static_cast<std::uint8_t>((cell >> 3U) & 7U),
            static_cast<std::uint8_t>((cell >> 6U) & 7U),
        };
        state.cube.at(coordinate) ^= static_cast<std::uint8_t>(1U << bit_in_cell);
        return;
    }

    auto controller_bit = bit - kCubeStateBits;
    if (controller_bit < 16U) {
        state.controller.axis_control ^= static_cast<std::uint16_t>(
            std::uint16_t{1U} << controller_bit);
        return;
    }
    controller_bit -= 16U;
    if (controller_bit < 16U) {
        state.controller.amount_control ^= static_cast<std::uint16_t>(
            std::uint16_t{1U} << controller_bit);
        return;
    }
    controller_bit -= 16U;
    if (controller_bit < 32U) {
        state.controller.feedback ^= static_cast<std::uint32_t>(
            std::uint32_t{1U} << controller_bit);
        return;
    }
    controller_bit -= 32U;
    require(controller_bit < 64U, "C1 transcript fault bit is outside model");
    state.controller.transcript ^= UINT64_C(1) << controller_bit;
}

void observe_geometry(GeometryCounts& geometry, std::size_t state_bit) {
    if (state_bit >= kCubeStateBits) {
        ++geometry.non_cube;
        return;
    }
    const auto cell = state_bit / 8U;
    ++geometry.x[cell & 7U];
    ++geometry.y[(cell >> 3U) & 7U];
    ++geometry.z[(cell >> 6U) & 7U];
    ++geometry.cell_bit[state_bit & 7U];
}

template <std::size_t Size>
void print_count_array(const char* name,
                       const std::array<std::uint64_t, Size>& values) {
    std::cout << ' ' << name << '=';
    for (std::size_t index = 0U; index < values.size(); ++index) {
        if (index != 0U) std::cout << ',';
        std::cout << values[index];
    }
}

void observe_diagnostic(DiagnosticAggregate& aggregate,
                        const DiagnosticRecord& record,
                        std::size_t tag_bytes) {
    ++aggregate.count;
    ++aggregate.entry_checks;
    ++aggregate.mirror_checks;
    observe(aggregate.full_distance, record.full_distance);
    observe(aggregate.extended_distance, record.extended_distance);
    if (record.full_distance == 0U) ++aggregate.full_unchanged;
    if (record.full_distance == 1U) ++aggregate.full_one_bit;
    if (record.extended_distance == 0U) ++aggregate.extended_unchanged;
    if (record.extended_distance == 1U) ++aggregate.extended_one_bit;
    if (record.first_changed_byte == kNoIndex) {
        ++aggregate.no_change_in_extended;
    } else if (record.first_changed_byte >= tag_bytes) {
        ++aggregate.first_change_after_prefix;
    }
    if (record.single_bit_until_first_output) {
        ++aggregate.single_bit_until_first_output;
    }
    switch (record.first_controller_stage) {
        case 1U:
            ++aggregate.controller_diverged_during_finalization_entry;
            break;
        case 2U: case 3U: case 4U: case 5U:
        case 6U: case 7U: case 8U: case 9U:
        case 10U: case 11U: case 12U: case 13U:
        case 14U: case 15U: case 16U: case 17U:
            ++aggregate.controller_diverged_during_binding;
            break;
        case 18U:
            ++aggregate.controller_diverged_during_squeeze_entry;
            break;
        default:
            if (record.first_controller_stage == kNoIndex) {
                ++aggregate.controller_never_diverged;
            } else {
                ++aggregate.controller_diverged_during_squeeze;
            }
            break;
    }
    observe_geometry(aggregate.geometry, record.state_bit);
}

void print_diagnostic_aggregate(const char* category,
                                std::size_t profile_bits,
                                const DiagnosticAggregate& aggregate) {
    require(aggregate.count > 0U, "cannot print empty diagnostic aggregate");
    std::cout << "fault-diagnosis category=" << category
              << " profile_bits=" << profile_bits
              << " selected=" << aggregate.count
              << " entry_checks=" << aggregate.entry_checks
              << " mirror_checks=" << aggregate.mirror_checks
              << " full32_unchanged=" << aggregate.full_unchanged
              << " full32_one_bit=" << aggregate.full_one_bit
              << " extended64_unchanged=" << aggregate.extended_unchanged
              << " extended64_one_bit=" << aggregate.extended_one_bit
              << " first_change_after_prefix=" << aggregate.first_change_after_prefix
              << " no_change_in_extended=" << aggregate.no_change_in_extended
              << " single_bit_until_first_output="
              << aggregate.single_bit_until_first_output
              << " controller_first_entry="
              << aggregate.controller_diverged_during_finalization_entry
              << " controller_first_binding="
              << aggregate.controller_diverged_during_binding
              << " controller_first_squeeze_entry="
              << aggregate.controller_diverged_during_squeeze_entry
              << " controller_first_squeeze="
              << aggregate.controller_diverged_during_squeeze
              << " controller_never=" << aggregate.controller_never_diverged
              << " full32_distance_min=" << aggregate.full_distance.minimum
              << " full32_distance_max=" << aggregate.full_distance.maximum
              << " full32_distance_sum=" << aggregate.full_distance.distance_sum
              << " extended64_distance_min=" << aggregate.extended_distance.minimum
              << " extended64_distance_max=" << aggregate.extended_distance.maximum
              << " extended64_distance_sum="
              << aggregate.extended_distance.distance_sum
              << " non_cube=" << aggregate.geometry.non_cube;
    print_count_array("x", aggregate.geometry.x);
    print_count_array("y", aggregate.geometry.y);
    print_count_array("z", aggregate.geometry.z);
    print_count_array("cell_bit", aggregate.geometry.cell_bit);
    std::cout << '\n';
}

void print_diagnostic_map_record(const DiagnosticRecord& record) {
    std::cout << record.profile_bits << ','
              << record.case_index << ','
              << record.state_bit << ','
              << state_region_name(state_region(record.state_bit)) << ',';
    if (record.state_bit < kCubeStateBits) {
        const auto cell = record.state_bit / 8U;
        std::cout << (cell & 7U) << ','
                  << ((cell >> 3U) & 7U) << ','
                  << ((cell >> 6U) & 7U) << ','
                  << (record.state_bit & 7U) << ',';
    } else {
        std::cout << ",,,,";
    }
    std::cout << record.prefix_distance << ','
              << record.full_distance << ','
              << record.extended_distance << ',';
    if (record.first_changed_byte != kNoIndex) {
        std::cout << record.first_changed_byte;
    }
    std::cout << ',';
    if (record.changed_prefix_bit != kNoIndex) {
        std::cout << record.changed_prefix_bit;
    }
    std::cout << ',';
    if (record.first_controller_stage != kNoIndex) {
        std::cout << record.first_controller_stage;
    }
    std::cout << ',';
    if (record.first_non_single_stage != kNoIndex) {
        std::cout << record.first_non_single_stage;
    }
    std::cout << ',' << (record.single_bit_until_first_output ? 1 : 0) << '\n';
}

FamilyFaultSets classify_cube_faults(const pvc1::WorkingState& base_state,
                                     const pvc1::ResearchOutput& canonical,
                                     std::uint64_t message_length,
                                     std::size_t tag_bytes) {
    FamilyFaultSets sets;
    const auto canonical_prefix =
        std::span<const std::uint8_t>(canonical).first(tag_bytes);
    for (std::size_t state_bit = 0U; state_bit < kCubeStateBits; ++state_bit) {
        auto faulted_state = base_state;
        flip_c1_state_bit(faulted_state, state_bit);
        const auto entry_distance = working_state_distance(base_state, faulted_state);
        require(entry_distance.cube_bits == 1U
                    && entry_distance.controller_bits == 0U
                    && entry_distance.metadata_bits == 0U,
                "family fault was not present exactly at finalizer entry");
        const auto faulted = pvc1::research_bound_output_a2(
            faulted_state, message_length);
        const auto distance = bit_distance(
            canonical_prefix,
            std::span<const std::uint8_t>(faulted).first(tag_bytes));
        if (distance == 0U) sets.unchanged.set(state_bit);
        if (distance == 1U) sets.one_bit.set(state_bit);
    }
    return sets;
}

void print_family_overlap(const char* family,
                          std::size_t profile_bits,
                          const std::array<FamilyFaultSets,
                                           kReplicationCasesPerProfile>& cases,
                          bool one_bit) {
    CubeFaultSet intersection;
    intersection.set();
    CubeFaultSet combined;
    std::uint64_t total = 0U;
    for (std::size_t case_index = 0U; case_index < cases.size(); ++case_index) {
        const auto& selected = one_bit
            ? cases[case_index].one_bit
            : cases[case_index].unchanged;
        intersection &= selected;
        combined |= selected;
        total += selected.count();
        std::cout << "fault-family-case family=" << family
                  << " category=" << (one_bit ? "prefix-one" : "prefix-silent")
                  << " profile_bits=" << profile_bits
                  << " case=" << case_index
                  << " selected=" << selected.count() << '\n';
    }

    std::uint64_t pair_count = 0U;
    std::uint64_t pair_min_ppm = UINT64_C(1000000);
    std::uint64_t pair_max_ppm = 0U;
    for (std::size_t left = 0U; left < cases.size(); ++left) {
        for (std::size_t right = left + 1U; right < cases.size(); ++right) {
            const auto& left_set = one_bit
                ? cases[left].one_bit
                : cases[left].unchanged;
            const auto& right_set = one_bit
                ? cases[right].one_bit
                : cases[right].unchanged;
            const auto pair_union = (left_set | right_set).count();
            if (pair_union == 0U) continue;
            const auto pair_intersection = (left_set & right_set).count();
            const auto ppm = static_cast<std::uint64_t>(pair_intersection)
                           * UINT64_C(1000000)
                           / static_cast<std::uint64_t>(pair_union);
            pair_min_ppm = std::min(pair_min_ppm, ppm);
            pair_max_ppm = std::max(pair_max_ppm, ppm);
            ++pair_count;
        }
    }
    if (pair_count == 0U) pair_min_ppm = 0U;
    std::cout << "fault-family-overlap family=" << family
              << " category=" << (one_bit ? "prefix-one" : "prefix-silent")
              << " profile_bits=" << profile_bits
              << " cases=" << cases.size()
              << " total_selected=" << total
              << " intersection=" << intersection.count()
              << " union=" << combined.count()
              << " nonempty_pairs=" << pair_count
              << " pair_jaccard_min_ppm=" << pair_min_ppm
              << " pair_jaccard_max_ppm=" << pair_max_ppm << '\n';
}

void test_tag_and_mac_result_bits(const std::array<CampaignCase, 3>& cases) {
    std::uint64_t tag_attempts = 0U;
    std::uint64_t tag_acceptances = 0U;
    std::uint64_t mac_result_faults = 0U;
    std::uint64_t canonical_tag_acceptances = 0U;

    for (const auto& test_case : cases) {
        for (std::size_t bit = 0U; bit < test_case.sealed.tag.size() * 8U; ++bit) {
            auto supplied = test_case.sealed.tag;
            flip_vector_bit(supplied, bit);
            ++tag_attempts;
            if (pvcrotsymenc1::open(
                    test_case.keys,
                    test_case.nonce,
                    test_case.associated_data,
                    test_case.sealed.ciphertext,
                    supplied).has_value()) {
                ++tag_acceptances;
            }

            auto faulted_result = test_case.sealed.tag;
            flip_vector_bit(faulted_result, bit);
            ++mac_result_faults;
            if (comparison_model(
                    faulted_result,
                    test_case.sealed.tag,
                    faulted_result.size())) {
                ++canonical_tag_acceptances;
            }
        }
    }
    require(tag_acceptances == 0U, "canonical open accepted a one-bit tag fault");
    require(canonical_tag_acceptances == 0U,
            "faulted MAC result accepted the canonical tag in comparison model");
    std::cout << "tag-bit-fault attempts=" << tag_attempts
              << " canonical_acceptances=" << tag_acceptances << '\n'
              << "mac-result-bit-fault attempts=" << mac_result_faults
              << " canonical_tag_acceptances=" << canonical_tag_acceptances
              << " availability_failures=" << mac_result_faults << '\n';
}

void test_comparison_skip(const std::array<CampaignCase, 3>& cases) {
    std::uint64_t attempts = 0U;
    std::uint64_t canonical_acceptances = 0U;
    std::uint64_t model_bypasses = 0U;
    for (const auto& test_case : cases) {
        for (std::size_t skipped = 0U; skipped < test_case.sealed.tag.size(); ++skipped) {
            auto supplied = test_case.sealed.tag;
            supplied[skipped] ^= UINT8_C(1);
            ++attempts;
            if (pvcrotsymenc1::open(
                    test_case.keys,
                    test_case.nonce,
                    test_case.associated_data,
                    test_case.sealed.ciphertext,
                    supplied).has_value()) {
                ++canonical_acceptances;
            }
            if (comparison_model(
                    test_case.sealed.tag,
                    supplied,
                    supplied.size(),
                    skipped)) {
                ++model_bypasses;
            }
        }
    }
    require(canonical_acceptances == 0U,
            "canonical open accepted a skipped-byte control tag");
    require(model_bypasses == attempts,
            "comparison-skip model did not bypass its sole mismatch");
    std::cout << "comparison-skip-fault attempts=" << attempts
              << " canonical_acceptances=" << canonical_acceptances
              << " model_bypasses=" << model_bypasses << '\n';
}

void test_tag_length_faults(const std::array<CampaignCase, 3>& cases) {
    std::uint64_t prevalidation_attempts = 0U;
    std::uint64_t prevalidation_acceptances = 0U;
    for (const auto& test_case : cases) {
        const auto original_length = test_case.sealed.tag.size();
        for (std::size_t bit = 0U; bit < 6U; ++bit) {
            const auto changed_length = original_length ^ (std::size_t{1U} << bit);
            std::vector<std::uint8_t> supplied(changed_length, UINT8_C(0));
            const auto copied = std::min(original_length, changed_length);
            std::copy_n(test_case.sealed.tag.begin(), copied, supplied.begin());
            ++prevalidation_attempts;
            if (pvcrotsymenc1::open(
                    test_case.keys,
                    test_case.nonce,
                    test_case.associated_data,
                    test_case.sealed.ciphertext,
                    supplied).has_value()) {
                ++prevalidation_acceptances;
            }
        }
    }
    require(prevalidation_acceptances == 0U,
            "canonical open accepted a one-bit pre-validation length fault");

    std::uint64_t postvalidation_attempts = 0U;
    std::uint64_t postvalidation_canonical_acceptances = 0U;
    std::uint64_t postvalidation_model_bypasses = 0U;
    for (const auto& test_case : cases) {
        auto supplied = test_case.sealed.tag;
        std::size_t comparison_length = 0U;
        if (supplied.size() == 24U) {
            supplied.back() ^= UINT8_C(1);
            comparison_length = 16U;
        } else {
            supplied.front() ^= UINT8_C(1);
        }
        ++postvalidation_attempts;
        if (pvcrotsymenc1::open(
                test_case.keys,
                test_case.nonce,
                test_case.associated_data,
                test_case.sealed.ciphertext,
                supplied).has_value()) {
            ++postvalidation_canonical_acceptances;
        }
        if (comparison_model(
                test_case.sealed.tag,
                supplied,
                comparison_length)) {
            ++postvalidation_model_bypasses;
        }
    }
    require(postvalidation_canonical_acceptances == 0U,
            "canonical open accepted a post-validation length control tag");
    require(postvalidation_model_bypasses == postvalidation_attempts,
            "post-validation length model did not bypass its omitted mismatch");
    std::cout << "tag-length-prevalidation-fault attempts=" << prevalidation_attempts
              << " canonical_acceptances=" << prevalidation_acceptances << '\n'
              << "tag-length-postvalidation-fault attempts=" << postvalidation_attempts
              << " canonical_acceptances=" << postvalidation_canonical_acceptances
              << " model_bypasses=" << postvalidation_model_bypasses << '\n';
}

void test_authentication_branch_skip(const std::array<CampaignCase, 3>& cases) {
    std::uint64_t attempts = 0U;
    std::uint64_t canonical_acceptances = 0U;
    std::uint64_t model_plaintext_releases = 0U;
    std::uint64_t model_wrong_plaintexts = 0U;

    for (const auto& test_case : cases) {
        for (std::size_t variant = 0U; variant < 4U; ++variant) {
            auto nonce = test_case.nonce;
            auto associated_data = test_case.associated_data;
            auto ciphertext = test_case.sealed.ciphertext;
            auto tag = test_case.sealed.tag;
            switch (variant) {
                case 0U: tag.front() ^= UINT8_C(1); break;
                case 1U: ciphertext.front() ^= UINT8_C(1); break;
                case 2U: flip_nonce_bit(nonce, 0U); break;
                case 3U: associated_data.front() ^= UINT8_C(1); break;
                default: fail("invalid branch-skip variant");
            }
            ++attempts;
            if (pvcrotsymenc1::open(
                    test_case.keys,
                    nonce,
                    associated_data,
                    ciphertext,
                    tag).has_value()) {
                ++canonical_acceptances;
            }
            const auto released = apply_stream(
                test_case.keys.encryption_key,
                nonce,
                ciphertext,
                test_case.tag_size);
            ++model_plaintext_releases;
            if (released != test_case.plaintext) ++model_wrong_plaintexts;
        }
    }
    require(canonical_acceptances == 0U,
            "canonical open accepted a branch-skip control mutation");
    require(model_plaintext_releases == attempts,
            "branch-skip model did not release plaintext");
    std::cout << "authentication-branch-skip-fault attempts=" << attempts
              << " canonical_acceptances=" << canonical_acceptances
              << " model_plaintext_releases=" << model_plaintext_releases
              << " model_wrong_plaintexts=" << model_wrong_plaintexts << '\n';
}

void test_post_authentication_faults(const CampaignCase& test_case) {
    const auto opened = pvcrotsymenc1::open(
        test_case.keys,
        test_case.nonce,
        test_case.associated_data,
        test_case.sealed.ciphertext,
        test_case.sealed.tag);
    require(opened.has_value() && *opened == test_case.plaintext,
            "post-authentication fault baseline did not authenticate");

    DistanceStats counter_stats;
    const auto blocks = test_case.sealed.ciphertext.size() / kStreamBlockBytes;
    require(blocks == 3U, "counter fault case does not have three full blocks");
    for (std::size_t block = 0U; block < blocks; ++block) {
        for (std::size_t bit = 0U; bit < 64U; ++bit) {
            const auto faulted = apply_stream(
                test_case.keys.encryption_key,
                test_case.nonce,
                test_case.sealed.ciphertext,
                test_case.tag_size,
                block,
                UINT64_C(1) << bit);
            observe(counter_stats, bit_distance(faulted, test_case.plaintext));
        }
    }
    print_distance("post-auth-counter-fault", counter_stats);

    DistanceStats nonce_stats;
    for (std::size_t bit = 0U; bit < test_case.nonce.size() * 8U; ++bit) {
        auto faulted_nonce = test_case.nonce;
        flip_nonce_bit(faulted_nonce, bit);
        const auto faulted = apply_stream(
            test_case.keys.encryption_key,
            faulted_nonce,
            test_case.sealed.ciphertext,
            test_case.tag_size);
        observe(nonce_stats, bit_distance(faulted, test_case.plaintext));
    }
    print_distance("post-auth-nonce-fault", nonce_stats);
}

void test_c1_stream_state_faults(const CampaignCase& test_case, bool localize) {
    const auto frame = pvcaead0::frame_stream_block(
        test_case.nonce, UINT64_C(0), to_a1_tag_size(test_case.tag_size));
    const auto canonical = pvc1::research_keyed_return_output_a2(
        test_case.keys.encryption_key, frame);
    const auto base_state = pvc1::evaluate_keyed_return_a2(
        test_case.keys.encryption_key, frame);
    require(pvc1::research_bound_output_a2(base_state, frame.size()) == canonical,
            "C1 stream state baseline output mismatch");

    DistanceStats stats;
    StateLocalization localization;
    for (std::size_t bit = 0U; bit < kC1StateBits; ++bit) {
        auto faulted_state = base_state;
        flip_c1_state_bit(faulted_state, bit);
        const auto faulted = pvc1::research_bound_output_a2(
            faulted_state, frame.size());
        const auto distance = bit_distance(canonical, faulted);
        observe(stats, distance);
        if (localize) {
            localize_state_fault(localization, bit, distance, canonical, faulted);
        }
    }
    print_distance("c1-stream-state-bit-fault", stats);
    if (localize) print_localization("c1-stream-state", 256U, localization);
}

void test_c1_mac_state_faults(const std::array<CampaignCase, 3>& cases,
                              bool localize) {
    for (const auto& test_case : cases) {
        const auto a1_tag_size = to_a1_tag_size(test_case.tag_size);
        const auto context = pvcaead0::frame_authentication_context(
            test_case.nonce,
            test_case.associated_data,
            a1_tag_size);
        const auto mac_frame = pvcmac0::frame_message(
            context,
            test_case.sealed.ciphertext,
            to_mac_tag_size(test_case.tag_size));
        const auto canonical = pvc1::research_keyed_return_output_a2(
            test_case.keys.authentication_key, mac_frame);
        require(std::equal(
                    test_case.sealed.tag.begin(),
                    test_case.sealed.tag.end(),
                    canonical.begin()),
                "C1 MAC baseline does not match sealed tag");
        const auto base_state = pvc1::evaluate_keyed_return_a2(
            test_case.keys.authentication_key, mac_frame);
        require(pvc1::research_bound_output_a2(base_state, mac_frame.size()) == canonical,
                "C1 MAC state baseline output mismatch");

        DistanceStats stats;
        StateLocalization localization;
        const auto tag_bytes = test_case.sealed.tag.size();
        const auto canonical_prefix = std::span<const std::uint8_t>(canonical).first(tag_bytes);
        for (std::size_t bit = 0U; bit < kC1StateBits; ++bit) {
            auto faulted_state = base_state;
            flip_c1_state_bit(faulted_state, bit);
            const auto faulted = pvc1::research_bound_output_a2(
                faulted_state, mac_frame.size());
            const auto faulted_prefix =
                std::span<const std::uint8_t>(faulted).first(tag_bytes);
            const auto distance = bit_distance(canonical_prefix, faulted_prefix);
            observe(stats, distance);
            if (localize) {
                localize_state_fault(
                    localization, bit, distance, canonical_prefix, faulted_prefix);
            }
        }
        std::cout << "c1-mac-state-bit-fault profile_bits=" << tag_bytes * 8U
                  << " faults=" << stats.attempts
                  << " unchanged=" << stats.unchanged
                  << " one_bit=" << stats.one_bit
                  << " distance_min=" << stats.minimum
                  << " distance_max=" << stats.maximum
                  << " distance_sum=" << stats.distance_sum << '\n';
        if (localize) {
            print_localization(
                "c1-mac-state", tag_bytes * 8U, localization);
        }
    }
}

void test_c1_mac_state_replication() {
    const std::array<TagSize, 3> profiles{
        TagSize::Bits128,
        TagSize::Bits192,
        TagSize::Bits256,
    };
    for (std::size_t profile_index = 0U;
         profile_index < profiles.size();
         ++profile_index) {
        auto random_state = kSeed
            ^ (UINT64_C(0x9E3779B97F4A7C15)
               * static_cast<std::uint64_t>(profile_index + 1U));
        DistanceStats aggregate;
        std::uint64_t cases_with_unchanged = 0U;
        std::uint64_t cases_with_one_bit = 0U;
        std::vector<std::array<std::size_t, 3>> candidates;

        for (std::size_t case_index = 0U;
             case_index < kReplicationCasesPerProfile;
             ++case_index) {
            const auto test_case = make_case(random_state, profiles[profile_index]);
            const auto context = pvcaead0::frame_authentication_context(
                test_case.nonce,
                test_case.associated_data,
                to_a1_tag_size(test_case.tag_size));
            const auto mac_frame = pvcmac0::frame_message(
                context,
                test_case.sealed.ciphertext,
                to_mac_tag_size(test_case.tag_size));
            const auto canonical = pvc1::research_keyed_return_output_a2(
                test_case.keys.authentication_key, mac_frame);
            require(std::equal(
                        test_case.sealed.tag.begin(),
                        test_case.sealed.tag.end(),
                        canonical.begin()),
                    "replication C1 MAC baseline does not match sealed tag");
            const auto base_state = pvc1::evaluate_keyed_return_a2(
                test_case.keys.authentication_key, mac_frame);
            require(
                pvc1::research_bound_output_a2(base_state, mac_frame.size()) == canonical,
                "replication C1 MAC state baseline output mismatch");

            const auto tag_bytes = test_case.sealed.tag.size();
            const auto canonical_prefix =
                std::span<const std::uint8_t>(canonical).first(tag_bytes);
            std::uint64_t case_unchanged = 0U;
            std::uint64_t case_one_bit = 0U;
            for (std::size_t state_bit = 0U; state_bit < kC1StateBits; ++state_bit) {
                auto faulted_state = base_state;
                flip_c1_state_bit(faulted_state, state_bit);
                const auto faulted = pvc1::research_bound_output_a2(
                    faulted_state, mac_frame.size());
                const auto faulted_prefix =
                    std::span<const std::uint8_t>(faulted).first(tag_bytes);
                const auto distance = bit_distance(canonical_prefix, faulted_prefix);
                observe(aggregate, distance);
                if (distance == 0U) ++case_unchanged;
                if (distance == 1U) {
                    ++case_one_bit;
                    candidates.push_back(
                        {case_index,
                         state_bit,
                         changed_bit(canonical_prefix, faulted_prefix)});
                }
            }
            if (case_unchanged > 0U) ++cases_with_unchanged;
            if (case_one_bit > 0U) ++cases_with_one_bit;
        }

        const auto profile_bits =
            pvcrotsymenc1::tag_size_bytes(profiles[profile_index]) * 8U;
        std::cout << "c1-mac-state-replication profile_bits=" << profile_bits
                  << " cases=" << kReplicationCasesPerProfile
                  << " faults=" << aggregate.attempts
                  << " unchanged=" << aggregate.unchanged
                  << " one_bit=" << aggregate.one_bit
                  << " cases_with_unchanged=" << cases_with_unchanged
                  << " cases_with_one_bit=" << cases_with_one_bit
                  << " distance_min=" << aggregate.minimum
                  << " distance_max=" << aggregate.maximum
                  << " distance_sum=" << aggregate.distance_sum << '\n';
        for (const auto& candidate : candidates) {
            std::cout << "c1-mac-state-replication-one-bit-candidate"
                      << " profile_bits=" << profile_bits
                      << " case=" << candidate[0]
                      << " state_bit=" << candidate[1]
                      << " state_region="
                      << state_region_name(state_region(candidate[1]))
                      << " tag_bit=" << candidate[2] << '\n';
        }
    }
}

std::vector<std::uint8_t> mac_frame_for_case(const CampaignCase& test_case) {
    const auto context = pvcaead0::frame_authentication_context(
        test_case.nonce,
        test_case.associated_data,
        to_a1_tag_size(test_case.tag_size));
    return pvcmac0::frame_message(
        context,
        test_case.sealed.ciphertext,
        to_mac_tag_size(test_case.tag_size));
}

void test_finalization_diagnosis(bool print_map) {
    const std::array<TagSize, 3> profiles{
        TagSize::Bits128,
        TagSize::Bits192,
        TagSize::Bits256,
    };
    constexpr std::array<std::uint64_t, 3> kExpectedSilent{3671U, 2462U, 1666U};
    constexpr std::array<std::uint64_t, 3> kExpectedOneBit{9U, 18U, 8U};
    std::uint64_t entry_checks = 0U;
    std::uint64_t baseline_mirror_checks = 0U;

    if (print_map) {
        std::cout << "profile_bits,case,state_bit,state_region,x,y,z,cell_bit,"
                     "prefix_distance,full32_distance,extended64_distance,"
                     "first_changed_byte,changed_prefix_bit,"
                     "first_controller_stage,first_non_single_stage,"
                     "single_bit_until_first_output\n";
    }

    for (std::size_t profile_index = 0U;
         profile_index < profiles.size();
         ++profile_index) {
        auto random_state = kSeed
            ^ (UINT64_C(0x9E3779B97F4A7C15)
               * static_cast<std::uint64_t>(profile_index + 1U));
        DiagnosticAggregate silent;
        DiagnosticAggregate one_bit;
        for (std::size_t case_index = 0U;
             case_index < kReplicationCasesPerProfile;
             ++case_index) {
            const auto test_case = make_case(random_state, profiles[profile_index]);
            const auto mac_frame = mac_frame_for_case(test_case);
            const auto canonical = pvc1::research_keyed_return_output_a2(
                test_case.keys.authentication_key, mac_frame);
            require(std::equal(
                        test_case.sealed.tag.begin(),
                        test_case.sealed.tag.end(),
                        canonical.begin()),
                    "diagnostic C1 MAC baseline does not match sealed tag");
            const auto base_state = pvc1::evaluate_keyed_return_a2(
                test_case.keys.authentication_key, mac_frame);
            const auto canonical_trace = trace_finalization(
                base_state, static_cast<std::uint64_t>(mac_frame.size()));
            require(std::equal(
                        canonical.begin(),
                        canonical.end(),
                        canonical_trace.output.begin()),
                    "diagnostic mirror does not match canonical finalizer");
            ++baseline_mirror_checks;

            const auto tag_bytes = test_case.sealed.tag.size();
            const auto canonical_prefix =
                std::span<const std::uint8_t>(canonical).first(tag_bytes);
            for (std::size_t state_bit = 0U;
                 state_bit < kC1StateBits;
                 ++state_bit) {
                auto faulted_state = base_state;
                flip_c1_state_bit(faulted_state, state_bit);
                const auto entry_distance = working_state_distance(
                    base_state, faulted_state);
                require(entry_distance.total() == 1U,
                        "fault was not present exactly at finalizer entry");
                if (state_bit < kCubeStateBits) {
                    require(entry_distance.cube_bits == 1U
                                && entry_distance.controller_bits == 0U
                                && entry_distance.metadata_bits == 0U,
                            "cube fault altered a non-cube entry field");
                }
                ++entry_checks;

                const auto faulted = pvc1::research_bound_output_a2(
                    faulted_state, mac_frame.size());
                const auto faulted_prefix =
                    std::span<const std::uint8_t>(faulted).first(tag_bytes);
                const auto prefix_distance = bit_distance(
                    canonical_prefix, faulted_prefix);
                if (prefix_distance > 1U) continue;

                const auto faulted_trace = trace_finalization(
                    faulted_state, static_cast<std::uint64_t>(mac_frame.size()));
                require(std::equal(
                            faulted.begin(),
                            faulted.end(),
                            faulted_trace.output.begin()),
                        "diagnostic mirror does not match faulted finalizer");
                const auto full_distance = bit_distance(
                    std::span<const std::uint8_t>(canonical_trace.output)
                        .first(kCanonicalOutputBytes),
                    std::span<const std::uint8_t>(faulted_trace.output)
                        .first(kCanonicalOutputBytes));
                const auto extended_distance = bit_distance(
                    canonical_trace.output, faulted_trace.output);
                const auto first_output = first_changed_byte(
                    canonical_trace.output, faulted_trace.output);

                DiagnosticRecord record{
                    .profile_bits = tag_bytes * 8U,
                    .case_index = case_index,
                    .state_bit = state_bit,
                    .prefix_distance = prefix_distance,
                    .full_distance = full_distance,
                    .extended_distance = extended_distance,
                    .first_changed_byte = first_output,
                    .changed_prefix_bit = prefix_distance == 1U
                        ? changed_bit(canonical_prefix, faulted_prefix)
                        : kNoIndex,
                    .first_controller_stage = first_controller_stage(
                        canonical_trace, faulted_trace),
                    .first_non_single_stage = first_non_single_stage(
                        canonical_trace, faulted_trace),
                    .single_bit_until_first_output = remains_single_bit_until_output(
                        canonical_trace,
                        faulted_trace,
                        first_output == kNoIndex
                            ? kExtendedOutputBytes - 1U
                            : first_output),
                };
                auto& aggregate = prefix_distance == 0U ? silent : one_bit;
                observe_diagnostic(aggregate, record, tag_bytes);
                if (print_map) print_diagnostic_map_record(record);
            }
        }
        require(silent.count == kExpectedSilent[profile_index],
                "diagnostic campaign did not reproduce silent-prefix count");
        require(one_bit.count == kExpectedOneBit[profile_index],
                "diagnostic campaign did not reproduce distance-one count");
        if (!print_map) {
            print_diagnostic_aggregate(
                "prefix-silent",
                pvcrotsymenc1::tag_size_bytes(profiles[profile_index]) * 8U,
                silent);
            print_diagnostic_aggregate(
                "prefix-one",
                pvcrotsymenc1::tag_size_bytes(profiles[profile_index]) * 8U,
                one_bit);
        }
    }
    if (!print_map) {
        std::cout << "fault-diagnosis-validation"
                  << " entry_checks=" << entry_checks
                  << " baseline_mirror_checks=" << baseline_mirror_checks
                  << " selected_mirror_checks="
                  << (kExpectedSilent[0] + kExpectedSilent[1] + kExpectedSilent[2]
                      + kExpectedOneBit[0] + kExpectedOneBit[1]
                      + kExpectedOneBit[2])
                  << " prior_counts_reproduced=1\n";
    }
}

void test_fault_dependency_families() {
    const std::array<TagSize, 3> profiles{
        TagSize::Bits128,
        TagSize::Bits192,
        TagSize::Bits256,
    };
    for (std::size_t profile_index = 0U;
         profile_index < profiles.size();
         ++profile_index) {
        auto random_state = kFamilySeed
            ^ (UINT64_C(0xD1B54A32D192ED03)
               * static_cast<std::uint64_t>(profile_index + 1U));
        KeyPair512 fixed_keys;
        fixed_keys.encryption_key = random_array<32U>(random_state);
        fixed_keys.authentication_key = random_array<32U>(random_state);
        require(fixed_keys.encryption_key != fixed_keys.authentication_key,
                "family role keys unexpectedly match");
        const auto fixed_ad = random_vector(random_state, kAssociatedDataBytes);
        const auto fixed_plaintext = random_vector(random_state, kPlaintextBytes);
        std::array<FamilyFaultSets, kReplicationCasesPerProfile> nonce_family;
        std::vector<std::uint8_t> fixed_frame;

        for (std::size_t case_index = 0U;
             case_index < nonce_family.size();
             ++case_index) {
            CampaignCase test_case;
            test_case.keys = fixed_keys;
            test_case.nonce = random_array<24U>(random_state);
            test_case.associated_data = fixed_ad;
            test_case.plaintext = fixed_plaintext;
            test_case.tag_size = profiles[profile_index];
            test_case.sealed = pvcrotsymenc1::seal(
                test_case.keys,
                test_case.nonce,
                test_case.associated_data,
                test_case.plaintext,
                test_case.tag_size);
            const auto opened = pvcrotsymenc1::open(
                test_case.keys,
                test_case.nonce,
                test_case.associated_data,
                test_case.sealed.ciphertext,
                test_case.sealed.tag);
            require(opened.has_value() && *opened == test_case.plaintext,
                    "nonce-family canonical round trip failed");
            auto mac_frame = mac_frame_for_case(test_case);
            if (case_index == 0U) fixed_frame = mac_frame;
            const auto canonical = pvc1::research_keyed_return_output_a2(
                fixed_keys.authentication_key, mac_frame);
            const auto base_state = pvc1::evaluate_keyed_return_a2(
                fixed_keys.authentication_key, mac_frame);
            require(pvc1::research_bound_output_a2(
                        base_state, mac_frame.size()) == canonical,
                    "nonce-family finalizer baseline mismatch");
            nonce_family[case_index] = classify_cube_faults(
                base_state,
                canonical,
                static_cast<std::uint64_t>(mac_frame.size()),
                test_case.sealed.tag.size());
        }
        const auto profile_bits =
            pvcrotsymenc1::tag_size_bytes(profiles[profile_index]) * 8U;
        print_family_overlap(
            "fixed-key-valid-nonce", profile_bits, nonce_family, false);
        print_family_overlap(
            "fixed-key-valid-nonce", profile_bits, nonce_family, true);

        std::array<FamilyFaultSets, kReplicationCasesPerProfile> key_family;
        for (std::size_t case_index = 0U;
             case_index < key_family.size();
             ++case_index) {
            const auto authentication_key = random_array<32U>(random_state);
            const auto canonical = pvc1::research_keyed_return_output_a2(
                authentication_key, fixed_frame);
            const auto base_state = pvc1::evaluate_keyed_return_a2(
                authentication_key, fixed_frame);
            require(pvc1::research_bound_output_a2(
                        base_state, fixed_frame.size()) == canonical,
                    "key-family finalizer baseline mismatch");
            key_family[case_index] = classify_cube_faults(
                base_state,
                canonical,
                static_cast<std::uint64_t>(fixed_frame.size()),
                pvcrotsymenc1::tag_size_bytes(profiles[profile_index]));
        }
        print_family_overlap(
            "fixed-frame-vary-key", profile_bits, key_family, false);
        print_family_overlap(
            "fixed-frame-vary-key", profile_bits, key_family, true);
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        bool localize = false;
        bool replicate = false;
        bool diagnose = false;
        bool print_map = false;
        if (argc == 2) {
            const std::string_view mode(argv[1]);
            if (mode == "--localize") {
                localize = true;
            } else if (mode == "--replicate") {
                replicate = true;
            } else if (mode == "--diagnose") {
                diagnose = true;
            } else if (mode == "--map") {
                print_map = true;
            } else {
                fail("unknown fault campaign mode");
            }
        } else if (argc != 1) {
            fail("usage: pvc-rotsymenc1-fault-injection-campaign "
                 "[--localize|--replicate|--diagnose|--map]");
        }
        if (!print_map) {
            std::cout << "PVC-RotSymEnc-1 software fault-injection campaign\n"
                      << "campaign_version=1\n"
                      << "construction_version=0.1.0-draft\n"
                      << "seed=0x4641554C54494E4A\n"
                      << "fault_model=analysis-only-single-software-fault\n"
                      << "c1_fault_point=after-transcript-return-before-finalization\n"
                      << "c1_state_bits=" << kC1StateBits << '\n';
        }
        if (replicate) {
            std::cout << "replication_mode=1\n"
                      << "replication_cases_per_profile="
                      << kReplicationCasesPerProfile << '\n';
            test_c1_mac_state_replication();
            std::cout << "unexpected_failure_count=0\n"
                      << "interpretation=targeted-replication-not-physical-feasibility\n";
            return 0;
        }
        if (diagnose || print_map) {
            if (!print_map) {
                std::cout << "diagnosis_mode=1\n"
                          << "diagnosis_version=1\n"
                          << "canonical_output_bytes=" << kCanonicalOutputBytes << '\n'
                          << "analysis_continuation_bytes="
                          << kExtendedOutputBytes - kCanonicalOutputBytes << '\n'
                          << "family_cases_per_profile="
                          << kReplicationCasesPerProfile << '\n';
            }
            test_finalization_diagnosis(print_map);
            if (!print_map) {
                test_fault_dependency_families();
                std::cout << "unexpected_failure_count=0\n"
                          << "interpretation=diagnostic-layer-separation-not-remediation\n";
            }
            return 0;
        }

        const auto cases = make_cases();
        if (localize) std::cout << "localization_mode=1\n";
        test_tag_and_mac_result_bits(cases);
        test_comparison_skip(cases);
        test_tag_length_faults(cases);
        test_authentication_branch_skip(cases);
        test_post_authentication_faults(cases.back());
        test_c1_stream_state_faults(cases.back(), localize);
        test_c1_mac_state_faults(cases, localize);
        std::cout << "unexpected_canonical_acceptances=0\n"
                  << "explicit_model_bypass_classes=3\n"
                  << "unexpected_failure_count=0\n"
                  << "interpretation=bounded-fault-map-not-a-physical-attack\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "fault campaign failure: " << error.what() << '\n';
        return 1;
    }
}
