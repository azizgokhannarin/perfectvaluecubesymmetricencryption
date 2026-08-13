#include "pvcaead0/aead.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using pvcaead0::KeyPair512;
using pvcaead0::Nonce192;
using pvcaead0::TagSize;

std::vector<std::uint8_t> bytes(std::initializer_list<unsigned> values) {
    std::vector<std::uint8_t> out;
    out.reserve(values.size());
    for (const auto value : values) out.push_back(static_cast<std::uint8_t>(value));
    return out;
}

std::vector<std::uint8_t> text(const std::string& value) {
    return {value.begin(), value.end()};
}

KeyPair512 base_keys() {
    KeyPair512 keys{};
    for (std::size_t i = 0; i < 32U; ++i) {
        keys.encryption_key[i] = static_cast<std::uint8_t>(i);
        keys.authentication_key[i] = static_cast<std::uint8_t>(0x80U + i);
    }
    return keys;
}

Nonce192 base_nonce() {
    Nonce192 nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<std::uint8_t>(0xA0U + i);
    return nonce;
}

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void flip_first(std::vector<std::uint8_t>& value) {
    require(!value.empty(), "cannot flip empty vector");
    value[0] ^= 0x01U;
}

void run_case(const std::string& name) {
    const auto keys = base_keys();
    const auto nonce = base_nonce();
    const auto ad = text("header");
    const auto message = text("PVC-AEAD-0 test message");

    if (name == "stream-frame-exact") {
        Nonce192 zero{};
        const auto frame = pvcaead0::frame_stream_block(zero, 0U, TagSize::Bits256);
        std::vector<std::uint8_t> expected{
            0x50,0x56,0x43,0x2d,0x41,0x45,0x41,0x44,0x2d,0x30,
            0x00,0x01,0x53,0xc1,0x20,0x00};
        expected.insert(expected.end(), 24U, 0U);
        expected.insert(expected.end(), 8U, 0U);
        require(frame == expected, "stream frame mismatch");
        return;
    }
    if (name == "auth-frame-exact") {
        Nonce192 zero{};
        const auto frame = pvcaead0::frame_authentication_context(zero, {}, TagSize::Bits256);
        std::vector<std::uint8_t> expected{
            0x50,0x56,0x43,0x2d,0x41,0x45,0x41,0x44,0x2d,0x30,
            0x00,0x01,0x41,0xc1,0xd1,0x20,0x00};
        expected.insert(expected.end(), 24U, 0U);
        expected.insert(expected.end(), 8U, 0U);
        require(frame == expected, "authentication frame mismatch");
        return;
    }
    if (name == "independent-key-canonical-vector") {
        Nonce192 zero{};
        const auto sealed = pvcaead0::seal(keys, zero, {}, text("abc"), TagSize::Bits256);
        const auto expected_ciphertext = bytes({0xa1,0x0b,0x4d});
        const auto expected_tag = bytes({
            0xa1,0x6f,0xf4,0xb4,0xdd,0x13,0xb4,0x8b,
            0xab,0x07,0x01,0xcd,0x8a,0x67,0xf1,0x24,
            0x8e,0xbb,0x4b,0xf3,0x7a,0x31,0x46,0x93,
            0x1f,0x04,0xe0,0x8c,0x83,0x4d,0x5c,0xee});
        require(sealed.ciphertext == expected_ciphertext, "canonical ciphertext mismatch");
        require(sealed.tag == expected_tag, "canonical tag mismatch");
        return;
    }
    if (name == "stream-counter-boundaries") {
        Nonce192 zero{};
        const auto first = pvcaead0::frame_stream_block(zero, 0U, TagSize::Bits256);
        const auto second = pvcaead0::frame_stream_block(zero, 1U, TagSize::Bits256);
        const auto last = pvcaead0::frame_stream_block(
            zero, std::numeric_limits<std::uint64_t>::max(), TagSize::Bits256);
        require(first != second && second != last && first != last, "counter frames collided");
        require(std::all_of(first.end() - 8, first.end(), [](std::uint8_t b) { return b == 0U; }),
                "counter zero encoding mismatch");
        require(std::all_of(last.end() - 8, last.end(), [](std::uint8_t b) { return b == 0xffU; }),
                "maximum counter encoding mismatch");
        return;
    }
    if (name == "frame-family-domain-separation") {
        Nonce192 zero{};
        const auto stream = pvcaead0::frame_stream_block(zero, 0U, TagSize::Bits256);
        const auto auth = pvcaead0::frame_authentication_context(zero, {}, TagSize::Bits256);
        require(stream != auth, "stream and authentication frame families overlap");
        require(stream[12] == 0x53U && auth[12] == 0x41U, "role-domain bytes mismatch");
        return;
    }
    if (name == "auth-frame-injectivity-witnesses") {
        Nonce192 zero{};
        auto other_nonce = zero;
        other_nonce[23] = 1U;
        const auto empty = pvcaead0::frame_authentication_context(zero, {}, TagSize::Bits256);
        const auto one_zero = pvcaead0::frame_authentication_context(zero, bytes({0x00}), TagSize::Bits256);
        const auto nonce_changed = pvcaead0::frame_authentication_context(other_nonce, {}, TagSize::Bits256);
        const auto profile_changed = pvcaead0::frame_authentication_context(zero, {}, TagSize::Bits128);
        require(empty != one_zero, "AD length/content was not injectively framed");
        require(empty != nonce_changed, "nonce was not injectively framed");
        require(empty != profile_changed, "tag profile was not injectively framed");
        return;
    }
    if (name == "empty-roundtrip") {
        const auto sealed = pvcaead0::seal(keys, nonce, {}, {}, TagSize::Bits256);
        require(sealed.ciphertext.empty(), "empty plaintext produced ciphertext");
        const auto opened = pvcaead0::open(keys, nonce, {}, sealed.ciphertext, sealed.tag);
        require(opened.has_value() && opened->empty(), "empty roundtrip failed");
        return;
    }
    if (name == "binary-roundtrip") {
        const auto binary_ad = bytes({0x00,0xff,0x00,0x80,0x7f});
        const auto binary_message = bytes({0x00,0x01,0xff,0x00,0x10,0x80,0xfe});
        const auto sealed = pvcaead0::seal(keys, nonce, binary_ad, binary_message, TagSize::Bits192);
        const auto opened = pvcaead0::open(keys, nonce, binary_ad, sealed.ciphertext, sealed.tag);
        require(opened.has_value() && *opened == binary_message, "binary roundtrip failed");
        return;
    }
    if (name == "multiblock-roundtrip") {
        std::vector<std::uint8_t> long_message(97U);
        for (std::size_t i = 0; i < long_message.size(); ++i) long_message[i] = static_cast<std::uint8_t>(i * 17U + 3U);
        const auto sealed = pvcaead0::seal(keys, nonce, ad, long_message, TagSize::Bits128);
        const auto opened = pvcaead0::open(keys, nonce, ad, sealed.ciphertext, sealed.tag);
        require(opened.has_value() && *opened == long_message, "multiblock roundtrip failed");
        return;
    }
    if (name == "determinism") {
        const auto a = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        const auto b = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        require(a.ciphertext == b.ciphertext && a.tag == b.tag, "seal is not deterministic");
        return;
    }
    if (name == "nonce-binding") {
        auto other_nonce = nonce;
        other_nonce[0] ^= 0x01U;
        const auto a = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        const auto b = pvcaead0::seal(keys, other_nonce, ad, message, TagSize::Bits256);
        require(a.ciphertext != b.ciphertext && a.tag != b.tag, "nonce is not bound");
        return;
    }
    if (name == "encryption-key-binding") {
        auto other = keys;
        other.encryption_key[0] ^= 0x01U;
        const auto a = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        const auto b = pvcaead0::seal(other, nonce, ad, message, TagSize::Bits256);
        require(a.ciphertext != b.ciphertext && a.tag != b.tag, "encryption key is not bound");
        return;
    }
    if (name == "authentication-key-binding") {
        auto other = keys;
        other.authentication_key[0] ^= 0x01U;
        const auto a = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        const auto b = pvcaead0::seal(other, nonce, ad, message, TagSize::Bits256);
        require(a.ciphertext == b.ciphertext && a.tag != b.tag, "authentication key separation failed");
        require(!pvcaead0::open(other, nonce, ad, a.ciphertext, a.tag).has_value(), "wrong auth key accepted");
        return;
    }
    if (name == "associated-data-binding") {
        const auto a = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        auto other_ad = ad;
        flip_first(other_ad);
        const auto b = pvcaead0::seal(keys, nonce, other_ad, message, TagSize::Bits256);
        require(a.ciphertext == b.ciphertext, "AD unexpectedly changes ciphertext");
        require(a.tag != b.tag, "AD is not authenticated");
        return;
    }
    if (name == "ciphertext-binding") {
        const auto sealed = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        auto modified = sealed.ciphertext;
        flip_first(modified);
        require(!pvcaead0::open(keys, nonce, ad, modified, sealed.tag).has_value(), "modified ciphertext accepted");
        return;
    }
    if (name == "tag-binding" || name == "wrong-tag-reject") {
        const auto sealed = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        auto modified = sealed.tag;
        flip_first(modified);
        require(!pvcaead0::open(keys, nonce, ad, sealed.ciphertext, modified).has_value(), "modified tag accepted");
        return;
    }
    if (name == "tag-size-domain-binding") {
        const auto a = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits128);
        const auto b = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits192);
        const auto c = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        require(a.ciphertext != b.ciphertext && a.ciphertext != c.ciphertext && b.ciphertext != c.ciphertext,
                "tag profiles reuse keystream");
        require(a.tag.size() == 16U && b.tag.size() == 24U && c.tag.size() == 32U, "tag sizes wrong");
        return;
    }
    if (name == "wrong-nonce-reject") {
        const auto sealed = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        auto other = nonce;
        other[23] ^= 0x01U;
        require(!pvcaead0::open(keys, other, ad, sealed.ciphertext, sealed.tag).has_value(), "wrong nonce accepted");
        return;
    }
    if (name == "wrong-ad-reject") {
        const auto sealed = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        auto other = ad;
        other.push_back(0U);
        require(!pvcaead0::open(keys, nonce, other, sealed.ciphertext, sealed.tag).has_value(), "wrong AD accepted");
        return;
    }
    if (name == "wrong-ciphertext-reject") {
        const auto sealed = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        auto other = sealed.ciphertext;
        flip_first(other);
        require(!pvcaead0::open(keys, nonce, ad, other, sealed.tag).has_value(), "wrong ciphertext accepted");
        return;
    }
    if (name == "invalid-tag-length-reject") {
        const auto sealed = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        for (const std::size_t length : {0U,1U,15U,17U,23U,25U,31U,33U}) {
            std::vector<std::uint8_t> invalid(length, 0U);
            require(!pvcaead0::open(keys, nonce, ad, sealed.ciphertext, invalid).has_value(), "invalid tag length accepted");
        }
        return;
    }
    if (name == "cross-profile-prefix-reject") {
        const auto full = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        const std::vector<std::uint8_t> prefix16(full.tag.begin(), full.tag.begin() + 16);
        const std::vector<std::uint8_t> prefix24(full.tag.begin(), full.tag.begin() + 24);
        require(!pvcaead0::open(keys, nonce, ad, full.ciphertext, prefix16).has_value(), "256-to-128 prefix accepted");
        require(!pvcaead0::open(keys, nonce, ad, full.ciphertext, prefix24).has_value(), "256-to-192 prefix accepted");
        return;
    }
    if (name == "verify-before-decrypt") {
        const auto sealed = pvcaead0::seal(keys, nonce, ad, message, TagSize::Bits256);
        auto invalid = sealed.tag;
        flip_first(invalid);
        const auto opened = pvcaead0::open(keys, nonce, ad, sealed.ciphertext, invalid);
        require(!opened.has_value(), "plaintext returned before authentication");
        return;
    }
    if (name == "nonce-reuse-xor-demonstration") {
        const auto p1 = text("same-length-message-one");
        const auto p2 = text("same-length-message-two");
        require(p1.size() == p2.size(), "test messages differ in length");
        const auto a = pvcaead0::seal(keys, nonce, ad, p1, TagSize::Bits256);
        const auto b = pvcaead0::seal(keys, nonce, ad, p2, TagSize::Bits256);
        for (std::size_t i = 0; i < p1.size(); ++i) {
            require(static_cast<std::uint8_t>(a.ciphertext[i] ^ b.ciphertext[i])
                    == static_cast<std::uint8_t>(p1[i] ^ p2[i]), "nonce-reuse XOR relation missing");
        }
        return;
    }
    if (name == "zero-length-ciphertext-authentication") {
        const auto a = pvcaead0::seal(keys, nonce, ad, {}, TagSize::Bits256);
        auto other_ad = ad;
        other_ad.push_back(0U);
        const auto b = pvcaead0::seal(keys, nonce, other_ad, {}, TagSize::Bits256);
        require(a.ciphertext.empty() && b.ciphertext.empty(), "empty ciphertext expected");
        require(a.tag != b.tag, "empty ciphertext failed to authenticate AD");
        require(!pvcaead0::open(keys, nonce, other_ad, a.ciphertext, a.tag).has_value(), "wrong AD accepted for empty ciphertext");
        return;
    }

    throw std::runtime_error("unknown test case: " + name);
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 3 || std::string(argv[1]) != "--case") {
            std::cerr << "usage: pvc-aead0-tests --case NAME\n";
            return 2;
        }
        run_case(argv[2]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
