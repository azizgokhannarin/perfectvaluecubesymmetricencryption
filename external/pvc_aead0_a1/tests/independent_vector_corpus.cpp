#include "pvcaead0_independent/aead.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::uint8_t nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(10 + c - 'a');
    throw std::invalid_argument("invalid hex");
}

std::vector<std::uint8_t> unhex(const std::string& value) {
    if ((value.size() % 2U) != 0U) throw std::invalid_argument("odd hex");
    std::vector<std::uint8_t> out(value.size() / 2U);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(value[2U*i]) << 4U) | nibble(value[2U*i+1U]));
    }
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(const std::string& value) {
    const auto parsed = unhex(value);
    if (parsed.size() != N) throw std::invalid_argument("fixed hex length mismatch");
    std::array<std::uint8_t, N> out{};
    std::copy(parsed.begin(), parsed.end(), out.begin());
    return out;
}

std::vector<std::string> split(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream stream(line);
    std::string field;
    while (std::getline(stream, field, ',')) fields.push_back(field);
    if (!line.empty() && line.back() == ',') fields.emplace_back();
    return fields;
}

pvcaead0_independent::TagSize parse_tag(const std::string& bits) {
    if (bits == "128") return pvcaead0_independent::TagSize::Bits128;
    if (bits == "192") return pvcaead0_independent::TagSize::Bits192;
    if (bits == "256") return pvcaead0_independent::TagSize::Bits256;
    throw std::invalid_argument("invalid tag bits");
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) return 2;
        std::ifstream input(argv[1], std::ios::binary);
        if (!input) throw std::runtime_error("cannot open vector corpus");
        std::string line;
        std::getline(input, line);
        std::size_t count = 0U;
        while (std::getline(input, line)) {
            if (line.empty()) continue;
            const auto f = split(line);
            if (f.size() != 9U) throw std::runtime_error("vector field count mismatch");
            pvcaead0_independent::KeyPair512 keys{fixed<32>(f[1]), fixed<32>(f[2])};
            const auto nonce = fixed<24>(f[3]);
            const auto tag_size = parse_tag(f[4]);
            const auto ad = unhex(f[5]);
            const auto plaintext = unhex(f[6]);
            const auto expected_ciphertext = unhex(f[7]);
            const auto expected_tag = unhex(f[8]);
            const auto sealed = pvcaead0_independent::seal(keys, nonce, ad, plaintext, tag_size);
            if (sealed.ciphertext != expected_ciphertext || sealed.tag != expected_tag) {
                throw std::runtime_error("independent vector mismatch: " + f[0]);
            }
            const auto opened = pvcaead0_independent::open(keys, nonce, ad, sealed.ciphertext, sealed.tag);
            if (!opened.has_value() || *opened != plaintext) {
                throw std::runtime_error("independent open mismatch: " + f[0]);
            }
            ++count;
        }
        if (count != 48U) throw std::runtime_error("expected 48 vectors");
        std::cout << "PASS independent implementation: 48/48 PVC-AEAD-0 vectors\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
