#include "pvcaead0/aead.hpp"

#include <cctype>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::uint8_t nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(10 + c - 'a');
    throw std::invalid_argument("invalid hex character");
}

std::vector<std::uint8_t> from_hex(const std::string& value) {
    if ((value.size() % 2U) != 0U) throw std::invalid_argument("hex input must have even length");
    std::vector<std::uint8_t> out(value.size() / 2U);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(value[2U*i]) << 4U) | nibble(value[2U*i+1U]));
    }
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed_hex(const std::string& value, const char* field) {
    const auto parsed = from_hex(value);
    if (parsed.size() != N) throw std::invalid_argument(std::string(field) + " has wrong length");
    std::array<std::uint8_t, N> out{};
    std::copy(parsed.begin(), parsed.end(), out.begin());
    return out;
}

std::string to_hex(std::span<const std::uint8_t> value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() * 2U);
    for (const auto byte : value) {
        out.push_back(digits[(byte >> 4U) & 0x0fU]);
        out.push_back(digits[byte & 0x0fU]);
    }
    return out;
}

pvcaead0::TagSize parse_tag_size(const std::string& value) {
    if (value == "128") return pvcaead0::TagSize::Bits128;
    if (value == "192") return pvcaead0::TagSize::Bits192;
    if (value == "256") return pvcaead0::TagSize::Bits256;
    throw std::invalid_argument("tag bits must be 128, 192, or 256");
}

void usage() {
    std::cerr << "seal: pvc-aead0 seal ENC_KEY_HEX MAC_KEY_HEX NONCE_HEX TAG_BITS AD_HEX PLAINTEXT_HEX\n"
              << "open: pvc-aead0 open ENC_KEY_HEX MAC_KEY_HEX NONCE_HEX AD_HEX CIPHERTEXT_HEX TAG_HEX\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) { usage(); return 2; }
        const std::string command = argv[1];
        if (command == "seal") {
            if (argc != 8) { usage(); return 2; }
            pvcaead0::KeyPair512 keys{fixed_hex<32>(argv[2], "encryption key"), fixed_hex<32>(argv[3], "authentication key")};
            const auto nonce = fixed_hex<24>(argv[4], "nonce");
            const auto tag_size = parse_tag_size(argv[5]);
            const auto ad = from_hex(argv[6]);
            const auto plaintext = from_hex(argv[7]);
            const auto sealed = pvcaead0::seal(keys, nonce, ad, plaintext, tag_size);
            std::cout << "ciphertext=" << to_hex(sealed.ciphertext) << '\n'
                      << "tag=" << to_hex(sealed.tag) << '\n';
            return 0;
        }
        if (command == "open") {
            if (argc != 8) { usage(); return 2; }
            pvcaead0::KeyPair512 keys{fixed_hex<32>(argv[2], "encryption key"), fixed_hex<32>(argv[3], "authentication key")};
            const auto nonce = fixed_hex<24>(argv[4], "nonce");
            const auto ad = from_hex(argv[5]);
            const auto ciphertext = from_hex(argv[6]);
            const auto tag = from_hex(argv[7]);
            const auto plaintext = pvcaead0::open(keys, nonce, ad, ciphertext, tag);
            if (!plaintext.has_value()) {
                std::cout << "authentication=failed\n";
                return 1;
            }
            std::cout << "authentication=ok\nplaintext=" << to_hex(*plaintext) << '\n';
            return 0;
        }
        usage();
        return 2;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
