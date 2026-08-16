#include "pvc1/key_schedule.hpp"
#include "pvcaead0/aead.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kOutputBits = 256U;
constexpr std::size_t kStreamFrameBytes = 48U;
constexpr std::size_t kCountersPerNonce = 1024U;
constexpr std::size_t kCensusNonces = 8U;
constexpr std::uint64_t kMaximumPayloadCounter = (std::uint64_t{1U} << 59U) - 1U;
constexpr std::uint64_t kDefaultSeed = UINT64_C(0x53545245414D4631);

using Output = pvc1::ResearchOutput;

struct Config {
    std::size_t samples = 4096U;
    std::size_t walsh_variables = 12U;
    std::size_t walsh_trials = 2U;
    std::uint64_t seed = kDefaultSeed;
};

struct DifferentialStats {
    std::uint64_t pairs{};
    std::uint64_t input_distance_sum{};
    std::uint64_t output_distance_sum{};
    std::size_t minimum_distance = kOutputBits;
    std::size_t maximum_distance{};
    std::uint64_t equal_outputs{};
    std::uint64_t prefix16_equal{};
    std::uint64_t prefix24_equal{};
    std::uint64_t prefix32_equal{};
    std::uint64_t prefix64_equal{};
    std::array<std::uint64_t, kOutputBits> flipped_bits{};
};

struct OutputStats {
    std::uint64_t samples{};
    std::array<std::uint64_t, kOutputBits> one_bits{};
    std::array<std::uint64_t, 256U> byte_frequencies{};
    std::set<Output> distinct_outputs;
    std::uint64_t collisions{};
};

struct WalshAggregate {
    std::uint64_t observations{};
    double maximum_correlation_sum{};
    double nonlinearity_sum{};
    int global_maximum_correlation{};
    std::size_t global_minimum_nonlinearity = std::numeric_limits<std::size_t>::max();
    std::uint64_t affine_outputs{};
};

enum class VariableKind {
    Nonce,
    Counter,
};

struct Variable {
    VariableKind kind{};
    std::size_t bit{};
};

struct WalshTrialResult {
    int candidate_maximum_correlation{};
    double candidate_mean_nonlinearity{};
    int control_maximum_correlation{};
    double control_mean_nonlinearity{};
    std::uint64_t candidate_output_collisions{};
};

std::size_t parse_size(std::string_view text) {
    std::size_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid integer: " + std::string(text));
    }
    return value;
}

std::uint64_t parse_u64(std::string_view text) {
    int base = 10;
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2U);
        base = 16;
    }
    std::uint64_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid u64: " + std::string(text));
    }
    return value;
}

Config parse_config(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        const auto next = [&](const char* name) {
            ++i;
            if (i >= argc) throw std::invalid_argument(std::string("missing ") + name);
            return std::string_view(argv[i]);
        };
        if (argument == "--samples") {
            config.samples = parse_size(next("samples"));
        } else if (argument == "--walsh-variables") {
            config.walsh_variables = parse_size(next("walsh variables"));
        } else if (argument == "--walsh-trials") {
            config.walsh_trials = parse_size(next("walsh trials"));
        } else if (argument == "--seed") {
            config.seed = parse_u64(next("seed"));
        } else {
            throw std::invalid_argument("unknown option: " + std::string(argument));
        }
    }
    if (config.samples < 256U) {
        throw std::invalid_argument("samples must be at least 256");
    }
    if (config.walsh_variables < 2U || config.walsh_variables > 16U) {
        throw std::invalid_argument("walsh variables must be in 2..16");
    }
    if (config.walsh_trials == 0U) {
        throw std::invalid_argument("walsh trials must be positive");
    }
    return config;
}

std::uint64_t splitmix64(std::uint64_t& state) {
    state += UINT64_C(0x9E3779B97F4A7C15);
    auto value = state;
    value = (value ^ (value >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31U);
}

std::uint64_t campaign_seed(std::uint64_t seed, std::uint64_t domain) {
    auto state = seed ^ domain;
    return splitmix64(state);
}

template <std::size_t Size>
std::array<std::uint8_t, Size> random_array(std::uint64_t& state) {
    std::array<std::uint8_t, Size> result{};
    std::uint64_t word{};
    for (std::size_t index = 0U; index < Size; ++index) {
        if ((index % 8U) == 0U) word = splitmix64(state);
        result[index] = static_cast<std::uint8_t>(word & UINT64_C(0xFF));
        word >>= 8U;
    }
    return result;
}

bool output_bit(const Output& output, std::size_t bit) {
    const auto byte = output[bit / 8U];
    return ((byte >> (bit % 8U)) & 1U) != 0U;
}

std::size_t bit_distance(std::span<const std::uint8_t> left,
                         std::span<const std::uint8_t> right) {
    if (left.size() != right.size()) throw std::logic_error("distance length mismatch");
    std::size_t distance{};
    for (std::size_t index = 0U; index < left.size(); ++index) {
        const auto difference = static_cast<unsigned>(left[index] ^ right[index]);
        distance += static_cast<std::size_t>(std::popcount(difference));
    }
    return distance;
}

bool equal_prefix(const Output& left, const Output& right, std::size_t bytes) {
    return std::equal(left.begin(), left.begin() + static_cast<std::ptrdiff_t>(bytes), right.begin());
}

Output evaluate_frame(const pvc1::ResearchKey256& key,
                      const pvcaead0::Nonce192& nonce,
                      std::uint64_t counter,
                      pvcaead0::TagSize tag_size) {
    const auto frame = pvcaead0::frame_stream_block(nonce, counter, tag_size);
    if (frame.size() != kStreamFrameBytes) throw std::logic_error("unexpected StreamFrame size");
    return pvc1::research_keyed_return_output_a2(key, frame);
}

void add_pair(DifferentialStats& stats,
              const Output& left,
              const Output& right,
              std::size_t input_distance) {
    const auto distance = bit_distance(left, right);
    ++stats.pairs;
    stats.input_distance_sum += static_cast<std::uint64_t>(input_distance);
    stats.output_distance_sum += static_cast<std::uint64_t>(distance);
    stats.minimum_distance = std::min(stats.minimum_distance, distance);
    stats.maximum_distance = std::max(stats.maximum_distance, distance);
    if (left == right) ++stats.equal_outputs;
    if (equal_prefix(left, right, 2U)) ++stats.prefix16_equal;
    if (equal_prefix(left, right, 3U)) ++stats.prefix24_equal;
    if (equal_prefix(left, right, 4U)) ++stats.prefix32_equal;
    if (equal_prefix(left, right, 8U)) ++stats.prefix64_equal;
    for (std::size_t bit = 0U; bit < kOutputBits; ++bit) {
        if (output_bit(left, bit) != output_bit(right, bit)) ++stats.flipped_bits[bit];
    }
}

void add_control_pair(DifferentialStats& stats,
                      std::uint64_t& state,
                      std::size_t input_distance) {
    const auto left = random_array<32U>(state);
    const auto right = random_array<32U>(state);
    add_pair(stats, left, right, input_distance);
}

std::pair<double, std::size_t> maximum_absolute_z(
    const std::array<std::uint64_t, kOutputBits>& counts,
    std::uint64_t samples) {
    double maximum{};
    std::size_t maximum_bit{};
    const auto denominator = std::sqrt(static_cast<double>(samples));
    for (std::size_t bit = 0U; bit < counts.size(); ++bit) {
        const auto numerator = 2.0 * static_cast<double>(counts[bit])
            - static_cast<double>(samples);
        const auto absolute_z = std::abs(numerator / denominator);
        if (absolute_z > maximum) {
            maximum = absolute_z;
            maximum_bit = bit;
        }
    }
    return {maximum, maximum_bit};
}

void print_differential(std::string_view family,
                        std::string_view profile,
                        const DifferentialStats& candidate,
                        const DifferentialStats& control) {
    const auto [candidate_z, candidate_bit] =
        maximum_absolute_z(candidate.flipped_bits, candidate.pairs);
    const auto [control_z, control_bit] = maximum_absolute_z(control.flipped_bits, control.pairs);
    std::cout << "differential"
              << " family=" << family
              << " profile=" << profile
              << " pairs=" << candidate.pairs
              << " mean_input_hd="
              << static_cast<double>(candidate.input_distance_sum)
                     / static_cast<double>(candidate.pairs)
              << " candidate_mean_hd="
              << static_cast<double>(candidate.output_distance_sum)
                     / static_cast<double>(candidate.pairs)
              << " candidate_min_hd=" << candidate.minimum_distance
              << " candidate_max_hd=" << candidate.maximum_distance
              << " candidate_equal=" << candidate.equal_outputs
              << " candidate_prefix16_equal=" << candidate.prefix16_equal
              << " candidate_prefix24_equal=" << candidate.prefix24_equal
              << " candidate_prefix32_equal=" << candidate.prefix32_equal
              << " candidate_prefix64_equal=" << candidate.prefix64_equal
              << " candidate_max_abs_bit_z=" << candidate_z
              << " candidate_max_z_bit=" << candidate_bit
              << " control_mean_hd="
              << static_cast<double>(control.output_distance_sum)
                     / static_cast<double>(control.pairs)
              << " control_min_hd=" << control.minimum_distance
              << " control_max_hd=" << control.maximum_distance
              << " control_equal=" << control.equal_outputs
              << " control_prefix16_equal=" << control.prefix16_equal
              << " control_prefix24_equal=" << control.prefix24_equal
              << " control_prefix32_equal=" << control.prefix32_equal
              << " control_prefix64_equal=" << control.prefix64_equal
              << " control_max_abs_bit_z=" << control_z
              << " control_max_z_bit=" << control_bit
              << '\n';
}

void add_output(OutputStats& stats, const Output& output) {
    ++stats.samples;
    if (!stats.distinct_outputs.insert(output).second) ++stats.collisions;
    for (std::size_t bit = 0U; bit < kOutputBits; ++bit) {
        if (output_bit(output, bit)) ++stats.one_bits[bit];
    }
    for (const auto byte : output) ++stats.byte_frequencies[byte];
}

double byte_chi_square(const OutputStats& stats) {
    const auto total = static_cast<double>(stats.samples) * 32.0;
    const auto expected = total / 256.0;
    double result{};
    for (const auto count : stats.byte_frequencies) {
        const auto difference = static_cast<double>(count) - expected;
        result += difference * difference / expected;
    }
    return result;
}

void print_output_stats(std::string_view profile,
                        const OutputStats& candidate,
                        const OutputStats& control) {
    const auto [candidate_z, candidate_bit] =
        maximum_absolute_z(candidate.one_bits, candidate.samples);
    const auto [control_z, control_bit] = maximum_absolute_z(control.one_bits, control.samples);
    const auto [candidate_minimum, candidate_maximum] =
        std::minmax_element(candidate.one_bits.begin(), candidate.one_bits.end());
    const auto [control_minimum, control_maximum] =
        std::minmax_element(control.one_bits.begin(), control.one_bits.end());
    std::cout << "output-census"
              << " profile=" << profile
              << " samples=" << candidate.samples
              << " candidate_collisions=" << candidate.collisions
              << " candidate_min_one_rate="
              << static_cast<double>(*candidate_minimum) / static_cast<double>(candidate.samples)
              << " candidate_max_one_rate="
              << static_cast<double>(*candidate_maximum) / static_cast<double>(candidate.samples)
              << " candidate_max_abs_bit_z=" << candidate_z
              << " candidate_max_z_bit=" << candidate_bit
              << " candidate_byte_chi_square=" << byte_chi_square(candidate)
              << " control_collisions=" << control.collisions
              << " control_min_one_rate="
              << static_cast<double>(*control_minimum) / static_cast<double>(control.samples)
              << " control_max_one_rate="
              << static_cast<double>(*control_maximum) / static_cast<double>(control.samples)
              << " control_max_abs_bit_z=" << control_z
              << " control_max_z_bit=" << control_bit
              << " control_byte_chi_square=" << byte_chi_square(control)
              << '\n';
}

std::array<pvcaead0::TagSize, 3U> tag_sizes() {
    return {pvcaead0::TagSize::Bits128,
            pvcaead0::TagSize::Bits192,
            pvcaead0::TagSize::Bits256};
}

std::string_view tag_name(pvcaead0::TagSize tag_size) {
    switch (tag_size) {
        case pvcaead0::TagSize::Bits128: return "128";
        case pvcaead0::TagSize::Bits192: return "192";
        case pvcaead0::TagSize::Bits256: return "256";
    }
    throw std::logic_error("unknown tag size");
}

std::size_t frame_distance(const pvcaead0::Nonce192& left_nonce,
                           std::uint64_t left_counter,
                           pvcaead0::TagSize left_tag,
                           const pvcaead0::Nonce192& right_nonce,
                           std::uint64_t right_counter,
                           pvcaead0::TagSize right_tag) {
    const auto left = pvcaead0::frame_stream_block(left_nonce, left_counter, left_tag);
    const auto right = pvcaead0::frame_stream_block(right_nonce, right_counter, right_tag);
    return bit_distance(left, right);
}

std::uint64_t run_differential_campaign(const Config& config) {
    const auto tags = tag_sizes();
    std::array<DifferentialStats, 3U> adjacent{};
    std::array<DifferentialStats, 3U> adjacent_control{};
    std::array<DifferentialStats, 3U> nonce_bit{};
    std::array<DifferentialStats, 3U> nonce_bit_control{};
    std::array<DifferentialStats, 3U> counter_weight{};
    std::array<DifferentialStats, 3U> counter_weight_control{};
    std::array<DifferentialStats, 3U> tag_relation{};
    std::array<DifferentialStats, 3U> tag_relation_control{};

    auto adjacent_state = campaign_seed(config.seed, UINT64_C(0xA11CE001));
    auto nonce_state = campaign_seed(config.seed, UINT64_C(0xB17F11F0));
    auto weight_state = campaign_seed(config.seed, UINT64_C(0xC017E167));
    auto tag_state = campaign_seed(config.seed, UINT64_C(0x7A6F11E0));
    auto control_state = campaign_seed(config.seed, UINT64_C(0xC017C017));

    const auto adjacent_key = random_array<32U>(adjacent_state);
    pvcaead0::Nonce192 adjacent_nonce{};
    for (std::size_t sample = 0U; sample < config.samples; ++sample) {
        const auto counter = static_cast<std::uint64_t>(sample % kCountersPerNonce);
        if ((sample % kCountersPerNonce) == 0U) {
            adjacent_nonce = random_array<24U>(adjacent_state);
        }
        for (std::size_t profile = 0U; profile < tags.size(); ++profile) {
            const auto left = evaluate_frame(adjacent_key, adjacent_nonce, counter, tags[profile]);
            const auto right = evaluate_frame(adjacent_key, adjacent_nonce, counter + 1U, tags[profile]);
            const auto input_hd = frame_distance(adjacent_nonce, counter, tags[profile],
                                                 adjacent_nonce, counter + 1U, tags[profile]);
            add_pair(adjacent[profile], left, right, input_hd);
            add_control_pair(adjacent_control[profile], control_state, input_hd);
        }
    }

    const auto nonce_key = random_array<32U>(nonce_state);
    for (std::size_t sample = 0U; sample < config.samples; ++sample) {
        const auto counter = static_cast<std::uint64_t>(sample % kCountersPerNonce);
        const auto left_nonce = random_array<24U>(nonce_state);
        auto right_nonce = left_nonce;
        const auto nonce_bit_index = sample % 192U;
        right_nonce[nonce_bit_index / 8U] ^=
            static_cast<std::uint8_t>(1U << (nonce_bit_index % 8U));
        for (std::size_t profile = 0U; profile < tags.size(); ++profile) {
            const auto left = evaluate_frame(nonce_key, left_nonce, counter, tags[profile]);
            const auto right = evaluate_frame(nonce_key, right_nonce, counter, tags[profile]);
            const auto input_hd = frame_distance(left_nonce, counter, tags[profile],
                                                 right_nonce, counter, tags[profile]);
            add_pair(nonce_bit[profile], left, right, input_hd);
            add_control_pair(nonce_bit_control[profile], control_state, input_hd);
        }
    }

    const auto weight_key = random_array<32U>(weight_state);
    for (std::size_t sample = 0U; sample < config.samples; ++sample) {
        const auto nonce = random_array<24U>(weight_state);
        const auto counter_bit = sample % 59U;
        const auto low_counter = std::uint64_t{1U} << counter_bit;
        const auto high_counter = kMaximumPayloadCounter ^ low_counter;
        for (std::size_t profile = 0U; profile < tags.size(); ++profile) {
            const auto left = evaluate_frame(weight_key, nonce, low_counter, tags[profile]);
            const auto right = evaluate_frame(weight_key, nonce, high_counter, tags[profile]);
            const auto input_hd = frame_distance(nonce, low_counter, tags[profile],
                                                 nonce, high_counter, tags[profile]);
            add_pair(counter_weight[profile], left, right, input_hd);
            add_control_pair(counter_weight_control[profile], control_state, input_hd);
        }
    }

    constexpr std::array<std::pair<std::size_t, std::size_t>, 3U> tag_pairs{{
        {0U, 1U}, {0U, 2U}, {1U, 2U},
    }};
    const auto tag_key = random_array<32U>(tag_state);
    pvcaead0::Nonce192 tag_nonce{};
    for (std::size_t sample = 0U; sample < config.samples; ++sample) {
        const auto counter = static_cast<std::uint64_t>(sample % kCountersPerNonce);
        if ((sample % kCountersPerNonce) == 0U) tag_nonce = random_array<24U>(tag_state);
        std::array<Output, 3U> outputs{};
        for (std::size_t profile = 0U; profile < tags.size(); ++profile) {
            outputs[profile] = evaluate_frame(tag_key, tag_nonce, counter, tags[profile]);
        }
        for (std::size_t relation = 0U; relation < tag_pairs.size(); ++relation) {
            const auto [left_profile, right_profile] = tag_pairs[relation];
            const auto input_hd = frame_distance(tag_nonce, counter, tags[left_profile],
                                                 tag_nonce, counter, tags[right_profile]);
            add_pair(tag_relation[relation], outputs[left_profile], outputs[right_profile], input_hd);
            add_control_pair(tag_relation_control[relation], control_state, input_hd);
        }
    }

    for (std::size_t profile = 0U; profile < tags.size(); ++profile) {
        print_differential("counter-adjacent", tag_name(tags[profile]),
                           adjacent[profile], adjacent_control[profile]);
        print_differential("nonce-single-bit", tag_name(tags[profile]),
                           nonce_bit[profile], nonce_bit_control[profile]);
        print_differential("counter-low-vs-high-weight", tag_name(tags[profile]),
                           counter_weight[profile], counter_weight_control[profile]);
    }
    for (std::size_t relation = 0U; relation < tag_pairs.size(); ++relation) {
        const auto [left_profile, right_profile] = tag_pairs[relation];
        const auto name = std::string(tag_name(tags[left_profile])) + "-vs-"
            + std::string(tag_name(tags[right_profile]));
        print_differential("tag-profile", name,
                           tag_relation[relation], tag_relation_control[relation]);
    }

    std::uint64_t alarms{};
    const auto count_alarms = [&](const auto& collections) {
        for (const auto& stats : collections) alarms += stats.equal_outputs;
    };
    count_alarms(adjacent);
    count_alarms(nonce_bit);
    count_alarms(counter_weight);
    count_alarms(tag_relation);
    return alarms;
}

std::uint64_t run_output_census(const Config& config) {
    const auto tags = tag_sizes();
    auto state = campaign_seed(config.seed, UINT64_C(0xCE115E00));
    auto control_state = campaign_seed(config.seed, UINT64_C(0xCE11C017));
    const auto key = random_array<32U>(state);
    std::array<pvcaead0::Nonce192, kCensusNonces> nonces{};
    for (auto& nonce : nonces) nonce = random_array<24U>(state);

    std::array<OutputStats, 3U> candidate{};
    std::array<OutputStats, 3U> control{};
    std::set<Output> cross_profile_outputs;
    std::uint64_t cross_profile_collisions{};
    for (std::size_t sample = 0U; sample < config.samples; ++sample) {
        const auto stream = sample % kCensusNonces;
        const auto counter = static_cast<std::uint64_t>(sample / kCensusNonces);
        for (std::size_t profile = 0U; profile < tags.size(); ++profile) {
            const auto output = evaluate_frame(key, nonces[stream], counter, tags[profile]);
            add_output(candidate[profile], output);
            if (!cross_profile_outputs.insert(output).second) ++cross_profile_collisions;
            add_output(control[profile], random_array<32U>(control_state));
        }
    }
    for (std::size_t profile = 0U; profile < tags.size(); ++profile) {
        print_output_stats(tag_name(tags[profile]), candidate[profile], control[profile]);
    }
    std::cout << "output-census-cross-profile"
              << " outputs=" << config.samples * tags.size()
              << " distinct=" << cross_profile_outputs.size()
              << " collisions=" << cross_profile_collisions
              << '\n';
    return cross_profile_collisions;
}

void fwht(std::vector<int>& values) {
    for (std::size_t length = 1U; length < values.size(); length <<= 1U) {
        for (std::size_t base = 0U; base < values.size(); base += length << 1U) {
            for (std::size_t offset = 0U; offset < length; ++offset) {
                const auto left = values[base + offset];
                const auto right = values[base + offset + length];
                values[base + offset] = left + right;
                values[base + offset + length] = left - right;
            }
        }
    }
}

void add_walsh_observation(WalshAggregate& aggregate,
                           int maximum_correlation,
                           std::size_t nonlinearity) {
    ++aggregate.observations;
    aggregate.maximum_correlation_sum += static_cast<double>(maximum_correlation);
    aggregate.nonlinearity_sum += static_cast<double>(nonlinearity);
    aggregate.global_maximum_correlation =
        std::max(aggregate.global_maximum_correlation, maximum_correlation);
    aggregate.global_minimum_nonlinearity =
        std::min(aggregate.global_minimum_nonlinearity, nonlinearity);
}

std::vector<Variable> choose_variables(std::string_view family, std::size_t count) {
    std::vector<Variable> variables;
    variables.reserve(count);
    if (family == "nonce-spread") {
        for (std::size_t index = 0U; index < count; ++index) {
            variables.push_back({VariableKind::Nonce, (index * 192U) / count});
        }
    } else if (family == "counter-low") {
        for (std::size_t index = 0U; index < count; ++index) {
            variables.push_back({VariableKind::Counter, index});
        }
    } else if (family == "mixed") {
        const auto nonce_count = count / 2U;
        const auto counter_count = count - nonce_count;
        for (std::size_t index = 0U; index < nonce_count; ++index) {
            variables.push_back({VariableKind::Nonce, (index * 192U) / nonce_count});
        }
        for (std::size_t index = 0U; index < counter_count; ++index) {
            variables.push_back({VariableKind::Counter, index});
        }
    } else {
        throw std::logic_error("unknown Walsh family");
    }
    return variables;
}

void clear_counter_variables(std::uint64_t& counter, std::span<const Variable> variables) {
    for (const auto& variable : variables) {
        if (variable.kind == VariableKind::Counter) {
            counter &= ~(std::uint64_t{1U} << variable.bit);
        }
    }
}

void apply_walsh_mask(pvcaead0::Nonce192& nonce,
                      std::uint64_t& counter,
                      std::span<const Variable> variables,
                      std::size_t mask) {
    for (std::size_t index = 0U; index < variables.size(); ++index) {
        if (((mask >> index) & 1U) == 0U) continue;
        const auto& variable = variables[index];
        if (variable.kind == VariableKind::Nonce) {
            nonce[variable.bit / 8U] ^=
                static_cast<std::uint8_t>(1U << (variable.bit % 8U));
        } else {
            counter ^= std::uint64_t{1U} << variable.bit;
        }
    }
}

WalshTrialResult measure_walsh_trial(const std::vector<Output>& candidate_outputs,
                                     const std::vector<Output>& control_outputs,
                                     WalshAggregate& candidate,
                                     WalshAggregate& control) {
    const auto count = candidate_outputs.size();
    WalshTrialResult result;
    std::vector<int> spectrum(count);
    std::set<Output> distinct;
    for (const auto& output : candidate_outputs) {
        if (!distinct.insert(output).second) ++result.candidate_output_collisions;
    }
    for (std::size_t bit = 0U; bit < kOutputBits; ++bit) {
        for (std::size_t mask = 0U; mask < count; ++mask) {
            spectrum[mask] = output_bit(candidate_outputs[mask], bit) ? -1 : 1;
        }
        fwht(spectrum);
        int candidate_maximum{};
        for (const auto coefficient : spectrum) {
            candidate_maximum = std::max(candidate_maximum, std::abs(coefficient));
        }
        const auto candidate_nonlinearity = count / 2U
            - static_cast<std::size_t>(candidate_maximum / 2);
        add_walsh_observation(candidate, candidate_maximum, candidate_nonlinearity);
        if (candidate_maximum == static_cast<int>(count)) ++candidate.affine_outputs;
        result.candidate_maximum_correlation =
            std::max(result.candidate_maximum_correlation, candidate_maximum);
        result.candidate_mean_nonlinearity += static_cast<double>(candidate_nonlinearity);

        for (std::size_t mask = 0U; mask < count; ++mask) {
            spectrum[mask] = output_bit(control_outputs[mask], bit) ? -1 : 1;
        }
        fwht(spectrum);
        int control_maximum{};
        for (const auto coefficient : spectrum) {
            control_maximum = std::max(control_maximum, std::abs(coefficient));
        }
        const auto control_nonlinearity = count / 2U
            - static_cast<std::size_t>(control_maximum / 2);
        add_walsh_observation(control, control_maximum, control_nonlinearity);
        if (control_maximum == static_cast<int>(count)) ++control.affine_outputs;
        result.control_maximum_correlation =
            std::max(result.control_maximum_correlation, control_maximum);
        result.control_mean_nonlinearity += static_cast<double>(control_nonlinearity);
    }
    result.candidate_mean_nonlinearity /= static_cast<double>(kOutputBits);
    result.control_mean_nonlinearity /= static_cast<double>(kOutputBits);
    return result;
}

std::uint64_t run_walsh_stratum(const Config& config,
                                std::string_view family,
                                pvcaead0::TagSize tag_size,
                                std::uint64_t domain) {
    const auto variables = choose_variables(family, config.walsh_variables);
    const auto count = std::size_t{1U} << config.walsh_variables;
    auto state = campaign_seed(config.seed, domain);
    auto control_state = campaign_seed(config.seed, domain ^ UINT64_C(0xC017C017));
    WalshAggregate candidate;
    WalshAggregate control;
    std::uint64_t collision_alarms{};

    for (std::size_t trial = 0U; trial < config.walsh_trials; ++trial) {
        const auto key = random_array<32U>(state);
        const auto base_nonce = random_array<24U>(state);
        auto base_counter = splitmix64(state) & kMaximumPayloadCounter;
        clear_counter_variables(base_counter, variables);
        std::vector<Output> candidate_outputs(count);
        std::vector<Output> control_outputs(count);
        for (std::size_t mask = 0U; mask < count; ++mask) {
            auto nonce = base_nonce;
            auto counter = base_counter;
            apply_walsh_mask(nonce, counter, variables, mask);
            candidate_outputs[mask] = evaluate_frame(key, nonce, counter, tag_size);
            control_outputs[mask] = random_array<32U>(control_state);
        }
        const auto result = measure_walsh_trial(candidate_outputs, control_outputs,
                                                candidate, control);
        collision_alarms += result.candidate_output_collisions;
        std::cout << "walsh-trial"
                  << " family=" << family
                  << " profile=" << tag_name(tag_size)
                  << " trial=" << trial
                  << " points=" << count
                  << " candidate_max_correlation="
                  << result.candidate_maximum_correlation
                  << " candidate_mean_nonlinearity="
                  << result.candidate_mean_nonlinearity
                  << " candidate_output_collisions="
                  << result.candidate_output_collisions
                  << " control_max_correlation=" << result.control_maximum_correlation
                  << " control_mean_nonlinearity=" << result.control_mean_nonlinearity
                  << '\n';
    }

    std::cout << "walsh-summary"
              << " family=" << family
              << " profile=" << tag_name(tag_size)
              << " observations=" << candidate.observations
              << " candidate_mean_max_correlation="
              << candidate.maximum_correlation_sum
                     / static_cast<double>(candidate.observations)
              << " candidate_global_max_correlation="
              << candidate.global_maximum_correlation
              << " candidate_mean_nonlinearity="
              << candidate.nonlinearity_sum / static_cast<double>(candidate.observations)
              << " candidate_min_nonlinearity="
              << candidate.global_minimum_nonlinearity
              << " candidate_affine_outputs=" << candidate.affine_outputs
              << " control_mean_max_correlation="
              << control.maximum_correlation_sum / static_cast<double>(control.observations)
              << " control_global_max_correlation="
              << control.global_maximum_correlation
              << " control_mean_nonlinearity="
              << control.nonlinearity_sum / static_cast<double>(control.observations)
              << " control_min_nonlinearity=" << control.global_minimum_nonlinearity
              << " control_affine_outputs=" << control.affine_outputs
              << '\n';
    return collision_alarms + candidate.affine_outputs;
}

std::uint64_t run_walsh_campaign(const Config& config) {
    std::uint64_t alarms{};
    alarms += run_walsh_stratum(config, "nonce-spread", pvcaead0::TagSize::Bits128,
                                UINT64_C(0xA11F1280));
    alarms += run_walsh_stratum(config, "counter-low", pvcaead0::TagSize::Bits192,
                                UINT64_C(0xA11F1920));
    alarms += run_walsh_stratum(config, "mixed", pvcaead0::TagSize::Bits256,
                                UINT64_C(0xA11F2560));
    return alarms;
}

std::string_view compiler_name() {
#if defined(__clang__)
    return "clang-" __clang_version__;
#elif defined(__GNUC__)
    return "gcc-" __VERSION__;
#elif defined(_MSC_VER)
    return "msvc";
#else
    return "unknown";
#endif
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto config = parse_config(argc, argv);
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "PVC-RotSymEnc-1 StreamFrame-domain audit\n";
        std::cout << "campaign_version=1\n";
        std::cout << "construction_version=0.1.0-draft\n";
        std::cout << "compiler=" << compiler_name() << '\n';
        std::cout << "seed=0x" << std::hex << std::uppercase << config.seed
                  << std::nouppercase << std::dec << '\n';
        std::cout << "samples=" << config.samples << '\n';
        std::cout << "counters_per_nonce=" << kCountersPerNonce << '\n';
        std::cout << "census_nonces=" << kCensusNonces << '\n';
        std::cout << "walsh_variables=" << config.walsh_variables << '\n';
        std::cout << "walsh_trials=" << config.walsh_trials << '\n';
        std::cout << "alarm_definition=full-output-equality-or-collision-or-affine-output-bit\n";

        std::uint64_t alarms{};
        alarms += run_differential_campaign(config);
        alarms += run_output_census(config);
        alarms += run_walsh_campaign(config);
        std::cout << "alarm_count=" << alarms << '\n';
        std::cout << "interpretation=bounded-empirical-campaign-not-a-security-proof\n";
        return alarms == 0U ? 0 : 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
