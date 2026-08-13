#include "pvcmac0_independent/mac.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

unsigned nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a') + 10U;
    if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A') + 10U;
    throw std::runtime_error("invalid hex in corpus");
}

std::vector<std::uint8_t> parse_hex(std::string_view input) {
    if ((input.size() & 1U) != 0U) throw std::runtime_error("odd hex length in corpus");
    std::vector<std::uint8_t> out(input.size() / 2U);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(input[2U * i]) << 4U)
                                          | nibble(input[2U * i + 1U]));
    }
    return out;
}

std::vector<std::string> split_csv(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream stream(line);
    std::string field;
    while (std::getline(stream, field, ',')) fields.push_back(field);
    if (!line.empty() && line.back() == ',') fields.emplace_back();
    return fields;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::invalid_argument("usage: pvc-mac0-independent-vector-corpus FILE");
        std::ifstream input(argv[1], std::ios::binary);
        if (!input) throw std::runtime_error("cannot open vector corpus");

        std::string line;
        if (!std::getline(input, line)
            || line != "index,key_hex,context_hex,message_hex,tag_bytes,tag_hex") {
            throw std::runtime_error("unexpected corpus header");
        }

        std::size_t vectors = 0U;
        while (std::getline(input, line)) {
            if (line.empty()) continue;
            const auto fields = split_csv(line);
            if (fields.size() != 6U) throw std::runtime_error("malformed corpus row");
            if (std::stoull(fields[0]) != vectors) throw std::runtime_error("non-canonical corpus index");
            const auto key_bytes = parse_hex(fields[1]);
            if (key_bytes.size() != 32U) throw std::runtime_error("invalid corpus key length");
            pvcmac0_independent::Key256 key{};
            std::copy(key_bytes.begin(), key_bytes.end(), key.begin());
            const auto context = parse_hex(fields[2]);
            const auto message = parse_hex(fields[3]);
            const auto tag_size = pvcmac0_independent::tag_size_from_bytes(
                static_cast<std::size_t>(std::stoull(fields[4])));
            const auto expected = parse_hex(fields[5]);
            const auto actual = pvcmac0_independent::compute_tag(key, context, message, tag_size);
            if (actual != expected) {
                throw std::runtime_error("independent corpus mismatch at index " + fields[0]);
            }
            ++vectors;
        }
        if (vectors != 48U) throw std::runtime_error("unexpected corpus vector count");
        std::cout << "PASS independent implementation: 48/48 PVC-MAC-0 vectors\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
