#include "pvcmac0/mac.hpp"
#include "pvcmac0_independent/mac.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

Bytes text(const char* value) {
    const auto* begin = reinterpret_cast<const std::uint8_t*>(value);
    const auto length = std::char_traits<char>::length(value);
    return Bytes(begin, begin + static_cast<std::ptrdiff_t>(length));
}

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

pvcmac0::Key256 key_value() {
    pvcmac0::Key256 key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>((i * 29U + 7U) & 0xFFU);
    }
    return key;
}

pvcmac0_independent::TagSize independent_size(std::size_t bytes) {
    return pvcmac0_independent::tag_size_from_bytes(bytes);
}

} // namespace

int main() {
    try {
        const auto key = key_value();
        auto wrong_key = key;
        wrong_key[0] ^= 0x80U;
        const auto context = text("firmware-manifest/v1");
        const Bytes message{0x00U, 0x01U, 0x7FU, 0x80U, 0xFFU, 0x00U, 0x41U};

        for (const std::size_t tag_bytes : {16U, 24U, 32U}) {
            const auto size = pvcmac0::tag_size_from_bytes(tag_bytes);
            const auto tag = pvcmac0::compute_tag(key, context, message, size);
            require(pvcmac0::verify_tag(key, context, message, tag), "valid tag rejected");
            require(pvcmac0_independent::verify_tag(
                        key, context, message, tag),
                    "independent verifier rejected canonical tag");

            require(!pvcmac0::verify_tag(wrong_key, context, message, tag), "wrong key accepted");
            require(!pvcmac0::verify_tag(key, text("firmware-manifest/v2"), message, tag),
                    "wrong context accepted");
            auto changed_message = message;
            changed_message.back() ^= 0x01U;
            require(!pvcmac0::verify_tag(key, context, changed_message, tag),
                    "wrong message accepted");

            for (std::size_t position = 0; position < tag.size(); ++position) {
                auto changed_tag = tag;
                changed_tag[position] ^= 0x01U;
                require(!pvcmac0::verify_tag(key, context, message, changed_tag),
                        "single-byte tag modification accepted");
            }

            const auto independent_tag = pvcmac0_independent::compute_tag(
                key, context, message, independent_size(tag_bytes));
            require(tag == independent_tag, "independent tag mismatch in misuse audit");
        }

        const auto frame_ab_c = pvcmac0::frame_message(text("ab"), text("c"), pvcmac0::TagSize::Bits256);
        const auto frame_a_bc = pvcmac0::frame_message(text("a"), text("bc"), pvcmac0::TagSize::Bits256);
        require(frame_ab_c != frame_a_bc, "context/message repartition alias");

        const auto frame_empty_a = pvcmac0::frame_message({}, text("a"), pvcmac0::TagSize::Bits256);
        const auto frame_a_empty = pvcmac0::frame_message(text("a"), {}, pvcmac0::TagSize::Bits256);
        require(frame_empty_a != frame_a_empty, "empty-field repartition alias");

        const Bytes base{0x41U, 0x42U};
        const Bytes extended{0x41U, 0x42U, 0x00U};
        require(pvcmac0::compute_tag(key, {}, base, pvcmac0::TagSize::Bits256)
                    != pvcmac0::compute_tag(key, {}, extended, pvcmac0::TagSize::Bits256),
                "zero extension retained the tag");

        const auto tag256 = pvcmac0::compute_tag(key, context, message, pvcmac0::TagSize::Bits256);
        const Bytes prefix16(tag256.begin(), tag256.begin() + 16);
        const Bytes prefix24(tag256.begin(), tag256.begin() + 24);
        require(!pvcmac0::verify_tag(key, context, message, prefix16),
                "256-profile prefix accepted under 128 profile");
        require(!pvcmac0::verify_tag(key, context, message, prefix24),
                "256-profile prefix accepted under 192 profile");

        for (const std::size_t invalid : {0U, 1U, 15U, 17U, 20U, 23U, 25U, 31U, 33U, 64U}) {
            const Bytes candidate(invalid, 0xA5U);
            require(!pvcmac0::verify_tag(key, context, message, candidate),
                    "invalid public tag length accepted");
            require(!pvcmac0_independent::verify_tag(key, context, message, candidate),
                    "independent implementation accepted invalid tag length");
        }

        std::cout << "PASS bounded integration/API misuse audit\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
