#include "pvcaead0/aead.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string hex(std::span<const std::uint8_t> data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2U);
    for (const auto byte : data) {
        out.push_back(digits[(byte >> 4U) & 0x0fU]);
        out.push_back(digits[byte & 0x0fU]);
    }
    return out;
}

std::uint64_t next(std::uint64_t& state) {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
}

std::uint8_t next_byte(std::uint64_t& state) {
    return static_cast<std::uint8_t>(next(state) >> 56U);
}

template <std::size_t N>
std::array<std::uint8_t, N> array_bytes(std::uint64_t& state) {
    std::array<std::uint8_t, N> out{};
    for (auto& byte : out) byte = next_byte(state);
    return out;
}

std::vector<std::uint8_t> vector_bytes(std::uint64_t& state, std::size_t size) {
    std::vector<std::uint8_t> out(size);
    for (auto& byte : out) byte = next_byte(state);
    return out;
}

pvcaead0::TagSize tag_for(std::size_t index) {
    switch (index % 3U) {
        case 0U: return pvcaead0::TagSize::Bits128;
        case 1U: return pvcaead0::TagSize::Bits192;
        default: return pvcaead0::TagSize::Bits256;
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) {
            std::cerr << "usage: pvc-aead0-vector-generator OUTPUT.csv\n";
            return 2;
        }
        std::ofstream out(argv[1], std::ios::binary);
        if (!out) throw std::runtime_error("cannot open output file");
        out << "id,enc_key,mac_key,nonce,tag_bits,associated_data,plaintext,ciphertext,tag\n";

        constexpr std::array<std::size_t, 16> lengths{0U,1U,2U,3U,7U,15U,16U,17U,31U,32U,33U,47U,63U,64U,65U,97U};
        std::uint64_t state = 0x5056434145414430ULL;
        for (std::size_t i = 0; i < 48U; ++i) {
            pvcaead0::KeyPair512 keys{array_bytes<32>(state), array_bytes<32>(state)};
            const auto nonce = array_bytes<24>(state);
            const auto tag_size = tag_for(i);
            const auto ad = vector_bytes(state, lengths[i % lengths.size()] / 2U);
            const auto plaintext = vector_bytes(state, lengths[(i * 5U) % lengths.size()]);
            const auto sealed = pvcaead0::seal(keys, nonce, ad, plaintext, tag_size);
            out << "V" << (i + 1U) << ','
                << hex(keys.encryption_key) << ','
                << hex(keys.authentication_key) << ','
                << hex(nonce) << ','
                << (pvcaead0::tag_size_bytes(tag_size) * 8U) << ','
                << hex(ad) << ','
                << hex(plaintext) << ','
                << hex(sealed.ciphertext) << ','
                << hex(sealed.tag) << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
