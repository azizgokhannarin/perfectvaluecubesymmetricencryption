#include "pvcmac0/mac.hpp"
#include "pvcmac0_independent/mac.hpp"

#include "pvc1/key_schedule.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

class SplitMix64 {
public:
    explicit SplitMix64(std::uint64_t seed) : state_(seed) {}

    std::uint64_t next() noexcept {
        state_ += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state_;
        z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31U);
    }

    std::uint8_t byte() noexcept { return static_cast<std::uint8_t>(next() & 0xFFU); }

private:
    std::uint64_t state_;
};

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::size_t selected_length(std::size_t index, SplitMix64& rng, bool message) {
    constexpr std::array<std::size_t, 30> boundaries{
        0U, 1U, 2U, 7U, 8U, 9U, 15U, 16U, 17U, 23U,
        24U, 25U, 29U, 30U, 31U, 32U, 33U, 63U, 64U, 65U,
        127U, 128U, 129U, 255U, 256U, 257U, 511U, 512U, 513U, 1024U,
    };
    const auto cadence = message ? 13U : 19U;
    if ((index % cadence) == 0U) {
        return boundaries[(index / cadence) % boundaries.size()];
    }
    const auto limit = message ? 193U : 97U;
    return static_cast<std::size_t>(rng.next() % limit);
}

Bytes random_bytes(std::size_t length, SplitMix64& rng) {
    Bytes output(length);
    for (auto& byte : output) byte = rng.byte();
    return output;
}

pvcmac0::TagSize canonical_size(std::size_t bytes) {
    return pvcmac0::tag_size_from_bytes(bytes);
}

pvcmac0_independent::TagSize independent_size(std::size_t bytes) {
    return pvcmac0_independent::tag_size_from_bytes(bytes);
}

template <typename Range>
void write_hex(std::ostream& output, const Range& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    for (const auto value : bytes) {
        const auto byte = static_cast<unsigned>(value);
        output.put(digits[(byte >> 4U) & 0x0FU]);
        output.put(digits[byte & 0x0FU]);
    }
}

struct CaseData {
    pvcmac0::Key256 key{};
    Bytes context;
    Bytes message;
    std::size_t tag_bytes{};
};

CaseData make_case(std::size_t index, SplitMix64& rng) {
    CaseData data;
    for (auto& byte : data.key) byte = rng.byte();
    data.context = random_bytes(selected_length(index, rng, false), rng);
    data.message = random_bytes(selected_length(index, rng, true), rng);
    constexpr std::array<std::size_t, 3> sizes{16U, 24U, 32U};
    data.tag_bytes = sizes[index % sizes.size()];
    return data;
}

void compare_case(std::size_t index, const CaseData& data, std::ostream* corpus) {
    const auto c_size = canonical_size(data.tag_bytes);
    const auto i_size = independent_size(data.tag_bytes);

    const auto canonical_frame = pvcmac0::frame_message(data.context, data.message, c_size);
    const auto independent_frame = pvcmac0_independent::frame_message(data.context, data.message, i_size);
    require(canonical_frame == independent_frame,
            "frame mismatch at differential case " + std::to_string(index));

    const auto canonical_full = pvc1::research_keyed_return_output_a2(data.key, canonical_frame);
    const auto independent_full = pvcmac0_independent::compute_full_output(
        data.key, data.context, data.message, i_size);
    require(canonical_full == independent_full,
            "full C1 output mismatch at differential case " + std::to_string(index));

    const auto canonical_tag = pvcmac0::compute_tag(data.key, data.context, data.message, c_size);
    const auto independent_tag = pvcmac0_independent::compute_tag(
        data.key, data.context, data.message, i_size);
    require(canonical_tag == independent_tag,
            "truncated tag mismatch at differential case " + std::to_string(index));

    require(pvcmac0::verify_tag(data.key, data.context, data.message, independent_tag),
            "canonical verifier rejected independent tag at case " + std::to_string(index));
    require(pvcmac0_independent::verify_tag(data.key, data.context, data.message, canonical_tag),
            "independent verifier rejected canonical tag at case " + std::to_string(index));

    auto modified = canonical_tag;
    modified[index % modified.size()] ^= static_cast<std::uint8_t>(1U << (index % 8U));
    require(!pvcmac0::verify_tag(data.key, data.context, data.message, modified),
            "canonical verifier accepted modified tag at case " + std::to_string(index));
    require(!pvcmac0_independent::verify_tag(data.key, data.context, data.message, modified),
            "independent verifier accepted modified tag at case " + std::to_string(index));

    if (corpus != nullptr) {
        *corpus << index << ',';
        write_hex(*corpus, data.key); *corpus << ',';
        write_hex(*corpus, data.context); *corpus << ',';
        write_hex(*corpus, data.message); *corpus << ',';
        *corpus << data.tag_bytes << ',';
        write_hex(*corpus, canonical_frame); *corpus << ',';
        write_hex(*corpus, canonical_full); *corpus << ',';
        write_hex(*corpus, canonical_tag); *corpus << '\n';
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::optional<std::string> output_path;
        std::size_t count = 4096U;
        for (int i = 1; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--write-corpus" && i + 1 < argc) {
                output_path = argv[++i];
            } else if (arg == "--count" && i + 1 < argc) {
                count = static_cast<std::size_t>(std::stoull(argv[++i]));
            } else {
                throw std::invalid_argument("usage: independent-differential [--count N] [--write-corpus FILE]");
            }
        }
        if (count == 0U) throw std::invalid_argument("count must be nonzero");

        std::ofstream corpus_file;
        std::ostream* corpus = nullptr;
        if (output_path.has_value()) {
            corpus_file.open(*output_path, std::ios::binary | std::ios::trunc);
            if (!corpus_file) throw std::runtime_error("cannot create differential corpus");
            corpus_file << "index,key_hex,context_hex,message_hex,tag_bytes,frame_hex,full_output_hex,tag_hex\n";
            corpus = &corpus_file;
        }

        SplitMix64 rng(0x5056434D41434D31ULL); // "PVCMACM1"
        for (std::size_t index = 0; index < count; ++index) {
            compare_case(index, make_case(index, rng), corpus);
        }

        std::cout << "PASS " << count
                  << " independent differential cases: frame/full-output/tag/verify matched\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
