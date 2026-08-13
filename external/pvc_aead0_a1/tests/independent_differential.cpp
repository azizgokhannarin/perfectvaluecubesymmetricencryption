#include "pvcaead0/aead.hpp"
#include "pvcaead0_independent/aead.hpp"

#include "pvc1/key_schedule.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
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

std::size_t selected_length(std::size_t index, SplitMix64& rng, bool plaintext) {
    constexpr std::array<std::size_t, 34> boundaries{
        0U,1U,2U,3U,7U,8U,9U,15U,16U,17U,23U,24U,25U,31U,32U,33U,47U,
        48U,49U,63U,64U,65U,95U,96U,97U,127U,128U,129U,255U,256U,257U,
        511U,512U,1024U,
    };
    const auto cadence = plaintext ? 67U : 83U;
    if ((index % cadence) == 0U) return boundaries[(index / cadence) % boundaries.size()];
    const auto limit = plaintext ? 65U : 49U;
    return static_cast<std::size_t>(rng.next() % limit);
}

Bytes random_bytes(std::size_t length, SplitMix64& rng) {
    Bytes output(length);
    for (auto& byte : output) byte = rng.byte();
    return output;
}

template <std::size_t N>
std::array<std::uint8_t, N> random_array(SplitMix64& rng) {
    std::array<std::uint8_t, N> out{};
    for (auto& byte : out) byte = rng.byte();
    return out;
}

pvcaead0::TagSize canonical_size(std::size_t bytes) {
    return pvcaead0::tag_size_from_bytes(bytes);
}

pvcaead0_independent::TagSize independent_size(std::size_t bytes) {
    return pvcaead0_independent::tag_size_from_bytes(bytes);
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

void write_block_list(std::ostream& output,
                      const std::vector<Bytes>& blocks) {
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        if (i != 0U) output.put(';');
        write_hex(output, blocks[i]);
    }
}

struct Stats {
    std::size_t tag_tamper_cases{};
    std::size_t nonce_tamper_cases{};
    std::size_t ad_tamper_cases{};
    std::size_t ciphertext_tamper_cases{};
    std::size_t boundary_counter_cases{};
};

struct CaseData {
    pvcaead0::KeyPair512 canonical_keys{};
    pvcaead0_independent::KeyPair512 independent_keys{};
    pvcaead0::Nonce192 canonical_nonce{};
    pvcaead0_independent::Nonce192 independent_nonce{};
    Bytes ad;
    Bytes plaintext;
    std::size_t tag_bytes{};
};

CaseData make_case(std::size_t index, SplitMix64& rng) {
    CaseData data;
    data.canonical_keys.encryption_key = random_array<32>(rng);
    data.canonical_keys.authentication_key = random_array<32>(rng);
    data.independent_keys.encryption_key = data.canonical_keys.encryption_key;
    data.independent_keys.authentication_key = data.canonical_keys.authentication_key;
    data.canonical_nonce = random_array<24>(rng);
    data.independent_nonce = data.canonical_nonce;

    if ((index % 64U) == 0U) {
        data.canonical_nonce.fill(0U);
        data.independent_nonce.fill(0U);
    } else if ((index % 64U) == 1U) {
        data.canonical_nonce.fill(0xFFU);
        data.independent_nonce.fill(0xFFU);
    }

    data.ad = random_bytes(selected_length(index, rng, false), rng);
    data.plaintext = random_bytes(selected_length(index, rng, true), rng);
    constexpr std::array<std::size_t, 3> sizes{16U,24U,32U};
    data.tag_bytes = sizes[index % sizes.size()];
    return data;
}

struct Trace {
    std::vector<Bytes> stream_frames;
    Bytes auth_context;
};

Trace canonical_trace(const CaseData& data) {
    Trace trace;
    const auto size = canonical_size(data.tag_bytes);
    const std::size_t blocks = data.plaintext.empty() ? 0U : 1U + ((data.plaintext.size() - 1U) / 32U);
    for (std::size_t i = 0; i < blocks; ++i) {
        trace.stream_frames.push_back(
            pvcaead0::frame_stream_block(data.canonical_nonce, static_cast<std::uint64_t>(i), size));
    }
    trace.auth_context = pvcaead0::frame_authentication_context(data.canonical_nonce, data.ad, size);
    return trace;
}

Trace independent_trace(const CaseData& data) {
    Trace trace;
    const auto size = independent_size(data.tag_bytes);
    const std::size_t blocks = data.plaintext.empty() ? 0U : 1U + ((data.plaintext.size() - 1U) / 32U);
    for (std::size_t i = 0; i < blocks; ++i) {
        trace.stream_frames.push_back(
            pvcaead0_independent::frame_stream_block(data.independent_nonce, static_cast<std::uint64_t>(i), size));
    }
    trace.auth_context = pvcaead0_independent::frame_authentication_context(data.independent_nonce, data.ad, size);
    return trace;
}

void compare_boundary_counters(const CaseData& data, std::size_t index) {
    constexpr std::array<std::uint64_t, 7> counters{
        0ULL,1ULL,0xFFULL,0xFFFFFFFFULL,0x100000000ULL,
        0x7FFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
    };
    const auto cs = canonical_size(data.tag_bytes);
    const auto is = independent_size(data.tag_bytes);
    for (const auto counter : counters) {
        const auto a = pvcaead0::frame_stream_block(data.canonical_nonce, counter, cs);
        const auto b = pvcaead0_independent::frame_stream_block(data.independent_nonce, counter, is);
        require(a == b, "counter-boundary frame mismatch at case " + std::to_string(index));
    }
}

void compare_case(std::size_t index, const CaseData& data, std::ostream* corpus, Stats& stats) {
    const auto c_size = canonical_size(data.tag_bytes);
    const auto i_size = independent_size(data.tag_bytes);
    const auto c_trace = canonical_trace(data);
    const auto i_trace = independent_trace(data);
    require(c_trace.stream_frames == i_trace.stream_frames,
            "stream-frame mismatch at case " + std::to_string(index));
    require(c_trace.auth_context == i_trace.auth_context,
            "auth-context mismatch at case " + std::to_string(index));
    if ((index % 31U) == 0U) { compare_boundary_counters(data, index); ++stats.boundary_counter_cases; }

    const auto canonical = pvcaead0::seal(data.canonical_keys,
                                          data.canonical_nonce,
                                          data.ad,
                                          data.plaintext,
                                          c_size);
    const auto independent = pvcaead0_independent::seal(data.independent_keys,
                                                        data.independent_nonce,
                                                        data.ad,
                                                        data.plaintext,
                                                        i_size);
    require(canonical.ciphertext == independent.ciphertext,
            "ciphertext mismatch at case " + std::to_string(index));
    require(canonical.tag == independent.tag,
            "tag mismatch at case " + std::to_string(index));

    Bytes canonical_keystream(data.plaintext.size());
    Bytes independent_keystream(data.plaintext.size());
    for (std::size_t i = 0; i < data.plaintext.size(); ++i) {
        canonical_keystream[i] = static_cast<std::uint8_t>(data.plaintext[i] ^ canonical.ciphertext[i]);
        independent_keystream[i] = static_cast<std::uint8_t>(data.plaintext[i] ^ independent.ciphertext[i]);
    }
    require(canonical_keystream == independent_keystream,
            "used keystream mismatch at case " + std::to_string(index));

    const auto c_open_i = pvcaead0::open(data.canonical_keys,
                                         data.canonical_nonce,
                                         data.ad,
                                         independent.ciphertext,
                                         independent.tag);
    const auto i_open_c = pvcaead0_independent::open(data.independent_keys,
                                                     data.independent_nonce,
                                                     data.ad,
                                                     canonical.ciphertext,
                                                     canonical.tag);
    require(c_open_i.has_value() && *c_open_i == data.plaintext,
            "canonical open rejected independent output at case " + std::to_string(index));
    require(i_open_c.has_value() && *i_open_c == data.plaintext,
            "independent open rejected canonical output at case " + std::to_string(index));

    if ((index % 8U) == 0U) {
        ++stats.tag_tamper_cases;
        auto modified_tag = canonical.tag;
        modified_tag[index % modified_tag.size()] ^= static_cast<std::uint8_t>(1U << (index % 8U));
        require(!pvcaead0::open(data.canonical_keys, data.canonical_nonce, data.ad,
                                canonical.ciphertext, modified_tag).has_value(),
                "canonical accepted modified tag at case " + std::to_string(index));
        require(!pvcaead0_independent::open(data.independent_keys, data.independent_nonce, data.ad,
                                            canonical.ciphertext, modified_tag).has_value(),
                "independent accepted modified tag at case " + std::to_string(index));
    }

    if ((index % 64U) == 0U) {
        ++stats.nonce_tamper_cases;
        auto nonce = data.canonical_nonce;
        nonce[index % nonce.size()] ^= 0x01U;
        pvcaead0_independent::Nonce192 inonce = nonce;
        require(!pvcaead0::open(data.canonical_keys, nonce, data.ad, canonical.ciphertext, canonical.tag).has_value(),
                "canonical accepted wrong nonce at case " + std::to_string(index));
        require(!pvcaead0_independent::open(data.independent_keys, inonce, data.ad, canonical.ciphertext, canonical.tag).has_value(),
                "independent accepted wrong nonce at case " + std::to_string(index));
    }
    if ((index % 64U) == 1U) {
        ++stats.ad_tamper_cases;
        auto ad = data.ad;
        ad.push_back(static_cast<std::uint8_t>(index));
        require(!pvcaead0::open(data.canonical_keys, data.canonical_nonce, ad, canonical.ciphertext, canonical.tag).has_value(),
                "canonical accepted wrong AD at case " + std::to_string(index));
        require(!pvcaead0_independent::open(data.independent_keys, data.independent_nonce, ad, canonical.ciphertext, canonical.tag).has_value(),
                "independent accepted wrong AD at case " + std::to_string(index));
    }
    if ((index % 64U) == 2U && !canonical.ciphertext.empty()) {
        ++stats.ciphertext_tamper_cases;
        auto ciphertext = canonical.ciphertext;
        ciphertext[index % ciphertext.size()] ^= 0x80U;
        require(!pvcaead0::open(data.canonical_keys, data.canonical_nonce, data.ad, ciphertext, canonical.tag).has_value(),
                "canonical accepted wrong ciphertext at case " + std::to_string(index));
        require(!pvcaead0_independent::open(data.independent_keys, data.independent_nonce, data.ad, ciphertext, canonical.tag).has_value(),
                "independent accepted wrong ciphertext at case " + std::to_string(index));
    }

    if (corpus != nullptr) {
        *corpus << index << ',';
        write_hex(*corpus, data.canonical_keys.encryption_key); *corpus << ',';
        write_hex(*corpus, data.canonical_keys.authentication_key); *corpus << ',';
        write_hex(*corpus, data.canonical_nonce); *corpus << ',';
        *corpus << data.tag_bytes << ',';
        write_hex(*corpus, data.ad); *corpus << ',';
        write_hex(*corpus, data.plaintext); *corpus << ',';
        write_block_list(*corpus, c_trace.stream_frames); *corpus << ',';
        write_hex(*corpus, canonical_keystream); *corpus << ',';
        write_hex(*corpus, canonical.ciphertext); *corpus << ',';
        write_hex(*corpus, c_trace.auth_context); *corpus << ',';
        write_hex(*corpus, canonical.tag); *corpus << '\n';
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::optional<std::string> output_path;
        std::size_t count = 4096U;
        for (int i = 1; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--write-corpus" && i + 1 < argc) output_path = argv[++i];
            else if (arg == "--count" && i + 1 < argc) count = static_cast<std::size_t>(std::stoull(argv[++i]));
            else throw std::invalid_argument("usage: independent-differential [--count N] [--write-corpus FILE]");
        }
        if (count == 0U) throw std::invalid_argument("count must be nonzero");

        std::ofstream corpus_file;
        std::ostream* corpus = nullptr;
        if (output_path.has_value()) {
            corpus_file.open(*output_path, std::ios::binary | std::ios::trunc);
            if (!corpus_file) throw std::runtime_error("cannot create differential corpus");
            corpus_file << "index,enc_key_hex,mac_key_hex,nonce_hex,tag_bytes,ad_hex,plaintext_hex,stream_frames_hex,used_keystream_hex,ciphertext_hex,auth_context_hex,tag_hex\n";
            corpus = &corpus_file;
        }

        SplitMix64 rng(0x5056434145414441ULL); // "PVCAEADA"
        Stats stats;
        for (std::size_t index = 0; index < count; ++index) {
            compare_case(index, make_case(index, rng), corpus, stats);
        }
        std::cout << "PASS " << count
                  << " independent differential cases: frames/keystream/ciphertext/auth-context/tag/open matched\n"
                  << "tag_tamper_cases=" << stats.tag_tamper_cases
                  << " nonce_tamper_cases=" << stats.nonce_tamper_cases
                  << " ad_tamper_cases=" << stats.ad_tamper_cases
                  << " ciphertext_tamper_cases=" << stats.ciphertext_tamper_cases
                  << " boundary_counter_cases=" << stats.boundary_counter_cases << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
