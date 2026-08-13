#include "pvcmac0/mac.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

unsigned hex_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a') + 10U;
    if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A') + 10U;
    throw std::invalid_argument("non-hexadecimal character");
}

std::vector<std::uint8_t> parse_hex(std::string_view text) {
    if ((text.size() & 1U) != 0U) throw std::invalid_argument("hex input must have even length");
    std::vector<std::uint8_t> out(text.size() / 2U);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((hex_nibble(text[2U * i]) << 4U)
                                          | hex_nibble(text[2U * i + 1U]));
    }
    return out;
}

pvcmac0::Key256 parse_key(std::string_view text) {
    const auto bytes = parse_hex(text);
    if (bytes.size() != 32U) throw std::invalid_argument("--key-hex requires exactly 64 hex characters");
    pvcmac0::Key256 key{};
    std::copy(bytes.begin(), bytes.end(), key.begin());
    return key;
}

std::size_t parse_size(std::string_view text) {
    std::size_t value{};
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid integer: " + std::string(text));
    }
    return value;
}

std::vector<std::uint8_t> bytes_from_text(std::string_view text) {
    return {text.begin(), text.end()};
}

void print_hex(std::span<const std::uint8_t> bytes) {
    for (const auto byte : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(byte);
    }
    std::cout << std::dec << '\n';
}

void usage() {
    std::cout
        << "PVC-MAC-0 Candidate M1 / v0.2.0 research CLI\n"
        << "Usage:\n"
        << "  pvc-mac0 --key-hex 64HEX [--text TEXT | --message-hex HEX]\n"
        << "           [--context TEXT | --context-hex HEX] [--tag-bytes 16|24|32]\n"
        << "           [--verify-hex HEX] [--print-frame]\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::optional<pvcmac0::Key256> key;
        std::vector<std::uint8_t> message;
        std::vector<std::uint8_t> context;
        std::size_t tag_bytes = 32U;
        std::optional<std::vector<std::uint8_t>> verify;
        bool print_frame = false;
        bool message_set = false;
        bool context_set = false;

        for (int i = 1; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--key-hex" && i + 1 < argc) {
                key = parse_key(argv[++i]);
            } else if (arg == "--text" && i + 1 < argc) {
                if (message_set) throw std::invalid_argument("message specified more than once");
                message = bytes_from_text(argv[++i]);
                message_set = true;
            } else if (arg == "--message-hex" && i + 1 < argc) {
                if (message_set) throw std::invalid_argument("message specified more than once");
                message = parse_hex(argv[++i]);
                message_set = true;
            } else if (arg == "--context" && i + 1 < argc) {
                if (context_set) throw std::invalid_argument("context specified more than once");
                context = bytes_from_text(argv[++i]);
                context_set = true;
            } else if (arg == "--context-hex" && i + 1 < argc) {
                if (context_set) throw std::invalid_argument("context specified more than once");
                context = parse_hex(argv[++i]);
                context_set = true;
            } else if (arg == "--tag-bytes" && i + 1 < argc) {
                tag_bytes = parse_size(argv[++i]);
            } else if (arg == "--verify-hex" && i + 1 < argc) {
                verify = parse_hex(argv[++i]);
            } else if (arg == "--print-frame") {
                print_frame = true;
            } else if (arg == "--help") {
                usage();
                return 0;
            } else {
                throw std::invalid_argument("unknown or incomplete argument: " + std::string(arg));
            }
        }

        if (!key.has_value()) throw std::invalid_argument("--key-hex is required");
        const auto tag_size = pvcmac0::tag_size_from_bytes(tag_bytes);

        if (print_frame) {
            const auto frame = pvcmac0::frame_message(context, message, tag_size);
            std::cout << "frame=";
            print_hex(frame);
        }

        if (verify.has_value()) {
            if (verify->size() != tag_bytes) {
                throw std::invalid_argument("--verify-hex length must match --tag-bytes");
            }
            const bool ok = pvcmac0::verify_tag(*key, context, message, *verify);
            std::cout << (ok ? "VALID" : "INVALID") << '\n';
            return ok ? 0 : 2;
        }

        const auto tag = pvcmac0::compute_tag(*key, context, message, tag_size);
        std::cout << "tag=";
        print_hex(tag);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
