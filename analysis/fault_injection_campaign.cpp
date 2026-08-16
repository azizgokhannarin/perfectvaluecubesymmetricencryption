#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include "pvc1/key_schedule.hpp"
#include "pvcaead0/aead.hpp"
#include "pvcmac0/mac.hpp"

#include <algorithm>
#include <array>
#include <bit>
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

} // namespace

int main(int argc, char** argv) {
    try {
        bool localize = false;
        bool replicate = false;
        if (argc == 2) {
            const std::string_view mode(argv[1]);
            if (mode == "--localize") {
                localize = true;
            } else if (mode == "--replicate") {
                replicate = true;
            } else {
                fail("unknown fault campaign mode");
            }
        } else if (argc != 1) {
            fail("usage: pvc-rotsymenc1-fault-injection-campaign "
                 "[--localize|--replicate]");
        }
        std::cout << "PVC-RotSymEnc-1 software fault-injection campaign\n"
                  << "campaign_version=1\n"
                  << "construction_version=0.1.0-draft\n"
                  << "seed=0x4641554C54494E4A\n"
                  << "fault_model=analysis-only-single-software-fault\n"
                  << "c1_fault_point=after-transcript-return-before-finalization\n"
                  << "c1_state_bits=" << kC1StateBits << '\n';
        if (replicate) {
            std::cout << "replication_mode=1\n"
                      << "replication_cases_per_profile="
                      << kReplicationCasesPerProfile << '\n';
            test_c1_mac_state_replication();
            std::cout << "unexpected_failure_count=0\n"
                      << "interpretation=targeted-replication-not-physical-feasibility\n";
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
