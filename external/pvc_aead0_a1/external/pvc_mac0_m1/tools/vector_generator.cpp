#include "pvcmac0/mac.hpp"

#include <array>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

class DeterministicGenerator {
public:
    explicit DeterministicGenerator(std::uint64_t state) : state_(state) {}
    std::uint8_t byte() {
        state_ ^= state_ << 13U;
        state_ ^= state_ >> 7U;
        state_ ^= state_ << 17U;
        return static_cast<std::uint8_t>(state_ >> 56U);
    }
private:
    std::uint64_t state_;
};

std::size_t parse_size(std::string_view text) {
    std::size_t value{};
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size()) throw std::invalid_argument("invalid integer");
    return value;
}

template <typename Range>
void write_hex(std::ostream& out, const Range& bytes) {
    for (const auto byte : bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    }
    out << std::dec;
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string output_path = "PVC_MAC0_VECTORS_0.1.0.csv";
        std::size_t count = 48U;
        for (int i = 1; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--output" && i + 1 < argc) output_path = argv[++i];
            else if (arg == "--count" && i + 1 < argc) count = parse_size(argv[++i]);
            else throw std::invalid_argument("usage: pvc-mac0-vector-generator [--output FILE] [--count N]");
        }

        std::ofstream out(output_path, std::ios::binary);
        if (!out) throw std::runtime_error("cannot open output file");
        out << "index,key_hex,context_hex,message_hex,tag_bytes,tag_hex\n";

        DeterministicGenerator generator(0x5056434D41433031ULL); // "PVCMAC01"
        const std::array<std::size_t, 3> tag_sizes{16U, 24U, 32U};
        for (std::size_t index = 0; index < count; ++index) {
            pvcmac0::Key256 key{};
            for (auto& byte : key) byte = generator.byte();
            const std::size_t context_length = index % 13U;
            const std::size_t message_length = (index * 17U + index / 3U) % 65U;
            std::vector<std::uint8_t> context(context_length);
            std::vector<std::uint8_t> message(message_length);
            for (auto& byte : context) byte = generator.byte();
            for (auto& byte : message) byte = generator.byte();
            const auto tag_size = pvcmac0::tag_size_from_bytes(tag_sizes[index % tag_sizes.size()]);
            const auto tag = pvcmac0::compute_tag(key, context, message, tag_size);

            out << index << ',';
            write_hex(out, key); out << ',';
            write_hex(out, context); out << ',';
            write_hex(out, message); out << ',';
            out << tag_sizes[index % tag_sizes.size()] << ',';
            write_hex(out, tag); out << '\n';
        }
        std::cout << "wrote " << count << " vectors to " << output_path << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
