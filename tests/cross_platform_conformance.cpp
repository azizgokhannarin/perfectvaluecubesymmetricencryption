#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::uint64_t kSeed = UINT64_C(0x43524F5353504C31);
constexpr std::size_t kDefaultCases = 4096U;
constexpr std::string_view kMagic = "PVC-RotSymEnc-1 cross-platform transcript v1\n";

struct Config {
    std::string output_path;
    std::size_t cases = kDefaultCases;
};

std::size_t parse_size(std::string_view text) {
    std::size_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid integer: " + std::string(text));
    }
    return value;
}

Config parse_config(int argc, char** argv) {
    Config config;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        const auto next = [&](const char* name) {
            ++index;
            if (index >= argc) throw std::invalid_argument(std::string("missing ") + name);
            return std::string_view(argv[index]);
        };
        if (argument == "--output") {
            config.output_path = std::string(next("output path"));
        } else if (argument == "--count") {
            config.cases = parse_size(next("case count"));
        } else {
            throw std::invalid_argument("unknown option: " + std::string(argument));
        }
    }
    if (config.output_path.empty()) throw std::invalid_argument("--output is required");
    if (config.cases == 0U) throw std::invalid_argument("case count must be positive");
    return config;
}

std::uint64_t next_random(std::uint64_t& state) noexcept {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
}

template <typename Container>
void fill_random(Container& output, std::uint64_t& state) {
    for (auto& value : output) {
        value = static_cast<std::uint8_t>(next_random(state) & UINT64_C(0xFF));
    }
}

std::size_t associated_data_length(std::size_t case_index, std::uint64_t& state) {
    constexpr std::array<std::size_t, 15> boundaries{
        0U, 1U, 2U, 7U, 8U, 15U, 16U, 17U, 31U, 32U, 33U, 63U, 64U, 65U, 128U};
    if ((case_index % 8U) == 0U) {
        return boundaries[(case_index / 8U) % boundaries.size()];
    }
    return static_cast<std::size_t>(next_random(state) % UINT64_C(129));
}

std::size_t plaintext_length(std::size_t case_index, std::uint64_t& state) {
    constexpr std::array<std::size_t, 23> boundaries{
        0U, 1U, 2U, 7U, 8U, 15U, 16U, 17U, 31U, 32U, 33U, 47U,
        48U, 63U, 64U, 65U, 95U, 96U, 97U, 127U, 128U, 255U, 256U};
    if ((case_index % 1024U) == 1023U) return 4096U;
    if ((case_index % 257U) == 256U) return 1024U;
    if ((case_index % 8U) == 0U) {
        return boundaries[(case_index / 8U) % boundaries.size()];
    }
    return static_cast<std::size_t>(next_random(state) % UINT64_C(257));
}

void apply_structure(std::vector<std::uint8_t>& bytes, std::size_t case_index) {
    switch (case_index % 64U) {
        case 0U:
            std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
            break;
        case 1U:
            std::fill(bytes.begin(), bytes.end(), std::uint8_t{0xFFU});
            break;
        case 2U:
            for (std::size_t index = 0U; index < bytes.size(); ++index) {
                bytes[index] = static_cast<std::uint8_t>(index & 0xFFU);
            }
            break;
        case 3U:
            for (std::size_t index = 0U; index < bytes.size(); ++index) {
                bytes[index] = (index % 2U) == 0U ? UINT8_C(0x55) : UINT8_C(0xAA);
            }
            break;
        default:
            break;
    }
}

pvcrotsymenc1::TagSize tag_size(std::size_t case_index) {
    switch (case_index % 3U) {
        case 0U: return pvcrotsymenc1::TagSize::Bits128;
        case 1U: return pvcrotsymenc1::TagSize::Bits192;
        default: return pvcrotsymenc1::TagSize::Bits256;
    }
}

void write_bytes(std::ofstream& output, std::span<const std::uint8_t> bytes) {
    if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::length_error("transcript field exceeds streamsize");
    }
    if (bytes.empty()) return;
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("transcript write failed");
}

void write_text(std::ofstream& output, std::string_view text) {
    const auto bytes = std::span(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    write_bytes(output, bytes);
}

void write_u64_be(std::ofstream& output, std::uint64_t value) {
    std::array<std::uint8_t, 8> encoded{};
    for (std::size_t index = 0U; index < encoded.size(); ++index) {
        const auto shift = static_cast<unsigned>((encoded.size() - 1U - index) * 8U);
        encoded[index] = static_cast<std::uint8_t>((value >> shift) & UINT64_C(0xFF));
    }
    write_bytes(output, encoded);
}

void write_field(std::ofstream& output, std::span<const std::uint8_t> bytes) {
    write_u64_be(output, static_cast<std::uint64_t>(bytes.size()));
    write_bytes(output, bytes);
}

void write_case(std::ofstream& output,
                std::size_t case_index,
                const pvcrotsymenc1::KeyPair512& keys,
                const pvcrotsymenc1::Nonce192& nonce,
                std::span<const std::uint8_t> associated_data,
                std::span<const std::uint8_t> plaintext,
                pvcrotsymenc1::TagSize selected_tag_size) {
    const auto sealed = pvcrotsymenc1::seal(
        keys, nonce, associated_data, plaintext, selected_tag_size);
    const auto opened = pvcrotsymenc1::open(
        keys, nonce, associated_data, sealed.ciphertext, sealed.tag);
    if (!opened || !std::equal(
            opened->begin(), opened->end(), plaintext.begin(), plaintext.end())) {
        throw std::runtime_error("valid open failed at case " + std::to_string(case_index));
    }

    auto invalid_tag = sealed.tag;
    invalid_tag[case_index % invalid_tag.size()] ^= UINT8_C(1);
    if (pvcrotsymenc1::open(
            keys, nonce, associated_data, sealed.ciphertext, invalid_tag).has_value()) {
        throw std::runtime_error("invalid tag accepted at case " + std::to_string(case_index));
    }

    write_text(output, "CASE");
    write_u64_be(output, static_cast<std::uint64_t>(case_index));
    write_u64_be(output, static_cast<std::uint64_t>(
        pvcrotsymenc1::tag_size_bytes(selected_tag_size)));
    write_bytes(output, keys.encryption_key);
    write_bytes(output, keys.authentication_key);
    write_bytes(output, nonce);
    write_field(output, associated_data);
    write_field(output, plaintext);
    write_field(output, sealed.ciphertext);
    write_field(output, sealed.tag);
    write_field(output, *opened);
    const std::array<std::uint8_t, 1> invalid_open_status{0U};
    write_bytes(output, invalid_open_status);
}

void generate(const Config& config) {
    std::ofstream output(config.output_path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot open output: " + config.output_path);

    write_text(output, kMagic);
    write_u64_be(output, kSeed);
    write_u64_be(output, static_cast<std::uint64_t>(config.cases));

    auto state = kSeed;
    for (std::size_t case_index = 0U; case_index < config.cases; ++case_index) {
        pvcrotsymenc1::KeyPair512 keys{};
        pvcrotsymenc1::Nonce192 nonce{};
        fill_random(keys.encryption_key, state);
        fill_random(keys.authentication_key, state);
        fill_random(nonce, state);

        std::vector<std::uint8_t> associated_data(
            associated_data_length(case_index, state));
        std::vector<std::uint8_t> plaintext(plaintext_length(case_index, state));
        fill_random(associated_data, state);
        fill_random(plaintext, state);
        apply_structure(associated_data, case_index);
        apply_structure(plaintext, case_index + 17U);

        write_case(output,
                   case_index,
                   keys,
                   nonce,
                   associated_data,
                   plaintext,
                   tag_size(case_index));
    }
    output.close();
    if (!output) throw std::runtime_error("transcript close failed");
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto config = parse_config(argc, argv);
        generate(config);
        std::printf("conformance_version=1 seed=0x%016llX cases=%zu output=%s\n",
                    static_cast<unsigned long long>(kSeed),
                    config.cases,
                    config.output_path.c_str());
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return 1;
    }
}
