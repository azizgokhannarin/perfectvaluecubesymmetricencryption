#include "pvcmac0/mac.hpp"
#include "pvc1/key_schedule.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

void require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

Bytes text(std::string_view value) { return {value.begin(), value.end()}; }

Bytes hex(std::string_view input) {
    auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a') + 10U;
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A') + 10U;
        throw std::runtime_error("bad test hex");
    };
    require((input.size() & 1U) == 0U, "test hex must have even length");
    Bytes out(input.size() / 2U);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(input[2U * i]) << 4U) | nibble(input[2U * i + 1U]));
    }
    return out;
}

pvcmac0::Key256 zero_key() { return {}; }

pvcmac0::Key256 incremental_key() {
    pvcmac0::Key256 key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i);
    return key;
}

void test_upstream_prf_vector() {
    const auto output = pvc1::research_keyed_return_output_a2(zero_key(), text("abc"));
    const auto expected = hex("7a56cb57bc6d988b1718f62ef637554377e6412790d1f66a57ef6cf0cf9b49c4");
    require(std::equal(output.begin(), output.end(), expected.begin(), expected.end()), "vendored C1 vector mismatch");
}

void test_framing_empty_exact() {
    const auto frame = pvcmac0::frame_message({}, {}, pvcmac0::TagSize::Bits256);
    const auto expected = hex("5056432d4d41432d300001c1200000000000000000000000000000000000");
    require(frame == expected, "empty frame encoding mismatch");
}

void test_framing_binary_exact() {
    const Bytes context{0x00U, 0xFFU};
    const Bytes message{0x41U, 0x00U, 0x42U};
    const auto frame = pvcmac0::frame_message(context, message, pvcmac0::TagSize::Bits128);
    const auto expected = hex("5056432d4d41432d300001c110000000000000000002000000000000000300ff410042");
    require(frame == expected, "binary frame encoding mismatch");
}

void test_framing_injective() {
    const auto a = pvcmac0::frame_message(text("a"), text("bc"), pvcmac0::TagSize::Bits256);
    const auto b = pvcmac0::frame_message(text("ab"), text("c"), pvcmac0::TagSize::Bits256);
    const Bytes with_nul{0x62U, 0x63U, 0x00U};
    const auto c = pvcmac0::frame_message(text("a"), with_nul, pvcmac0::TagSize::Bits256);
    require(a != b && a != c && b != c, "framing collision in boundary/null cases");
}

// Filled after the implementation is compiled; these vectors freeze v0.1.0.
void test_vector_zero_empty_256() {
    const auto tag = pvcmac0::compute_tag(zero_key(), {}, {}, pvcmac0::TagSize::Bits256);
    const auto expected = hex("1c3f146197db72c01793c5a80d2c6586ab544053e82d1fffae50f339c92421d4");
    require(tag == expected, "zero/empty/256 vector mismatch");
}

void test_vector_zero_abc_256() {
    const auto tag = pvcmac0::compute_tag(zero_key(), {}, text("abc"), pvcmac0::TagSize::Bits256);
    const auto expected = hex("1d6ea3a692d0dbf839adb1d4c3e31b2d1a4e0887351d14d1834b3ab88c4cc35f");
    require(tag == expected, "zero/abc/256 vector mismatch");
}

void test_vector_incremental_binary_128() {
    const Bytes context{0x50U, 0x56U, 0x43U, 0x00U};
    const Bytes message{0x00U, 0x01U, 0x7FU, 0x80U, 0xFFU};
    const auto tag = pvcmac0::compute_tag(incremental_key(), context, message, pvcmac0::TagSize::Bits128);
    const auto expected = hex("e36f8f6a274aab512b5245e61f1bced8");
    require(tag == expected, "incremental/binary/128 vector mismatch");
}

void test_determinism() {
    const auto first = pvcmac0::compute_tag(incremental_key(), text("protocol"), text("message"), pvcmac0::TagSize::Bits192);
    const auto second = pvcmac0::compute_tag(incremental_key(), text("protocol"), text("message"), pvcmac0::TagSize::Bits192);
    require(first == second, "MAC is not deterministic");
}

void test_message_binding() {
    const auto a = pvcmac0::compute_tag(zero_key(), {}, text("message"), pvcmac0::TagSize::Bits256);
    auto changed = text("message");
    changed[3] ^= 0x01U;
    const auto b = pvcmac0::compute_tag(zero_key(), {}, changed, pvcmac0::TagSize::Bits256);
    require(a != b, "message bit change did not change tag");
}

void test_message_length_binding() {
    const Bytes a{0x41U};
    const Bytes b{0x41U, 0x00U};
    require(pvcmac0::compute_tag(zero_key(), {}, a, pvcmac0::TagSize::Bits256)
            != pvcmac0::compute_tag(zero_key(), {}, b, pvcmac0::TagSize::Bits256),
            "message length is not bound");
}

void test_key_binding() {
    auto changed = zero_key();
    changed[31] = 1U;
    const auto a = pvcmac0::compute_tag(zero_key(), {}, text("message"), pvcmac0::TagSize::Bits256);
    const auto b = pvcmac0::compute_tag(changed, {}, text("message"), pvcmac0::TagSize::Bits256);
    require(a != b, "key change did not change tag");
}

void test_context_binding() {
    const auto a = pvcmac0::compute_tag(zero_key(), text("A"), text("message"), pvcmac0::TagSize::Bits256);
    const auto b = pvcmac0::compute_tag(zero_key(), text("B"), text("message"), pvcmac0::TagSize::Bits256);
    require(a != b, "context change did not change tag");
}

void test_tag_size_domain_binding() {
    const auto tag16 = pvcmac0::compute_tag(zero_key(), {}, text("message"), pvcmac0::TagSize::Bits128);
    const auto tag32 = pvcmac0::compute_tag(zero_key(), {}, text("message"), pvcmac0::TagSize::Bits256);
    require(!std::equal(tag16.begin(), tag16.end(), tag32.begin()), "tag-size domains are not separated");
}

void test_verify_accept() {
    const auto tag = pvcmac0::compute_tag(incremental_key(), text("ctx"), text("message"), pvcmac0::TagSize::Bits192);
    require(pvcmac0::verify_tag(incremental_key(), text("ctx"), text("message"), tag), "valid tag rejected");
}

void test_verify_reject_tag() {
    auto tag = pvcmac0::compute_tag(incremental_key(), text("ctx"), text("message"), pvcmac0::TagSize::Bits256);
    tag[17] ^= 0x80U;
    require(!pvcmac0::verify_tag(incremental_key(), text("ctx"), text("message"), tag), "modified tag accepted");
}

void test_verify_reject_message() {
    const auto tag = pvcmac0::compute_tag(incremental_key(), text("ctx"), text("message"), pvcmac0::TagSize::Bits128);
    require(!pvcmac0::verify_tag(incremental_key(), text("ctx"), text("messagf"), tag), "modified message accepted");
}

void test_invalid_tag_size() {
    const Bytes short_tag(15U, 0U);
    require(!pvcmac0::verify_tag(zero_key(), {}, {}, short_tag), "invalid tag length accepted");
    bool threw = false;
    try { (void)pvcmac0::tag_size_from_bytes(20U); }
    catch (const std::invalid_argument&) { threw = true; }
    require(threw, "unsupported tag size did not throw");
}

void test_verify_all_supported_lengths() {
    const auto key = incremental_key();
    const auto context = text("verification-profile");
    const auto message = text("same tuple, three domains");
    for (const auto size : {pvcmac0::TagSize::Bits128,
                            pvcmac0::TagSize::Bits192,
                            pvcmac0::TagSize::Bits256}) {
        const auto tag = pvcmac0::compute_tag(key, context, message, size);
        require(pvcmac0::verify_tag(key, context, message, tag),
                "valid supported-length tag rejected");
    }
}

void test_verify_invalid_length_matrix() {
    const auto key = incremental_key();
    const auto context = text("ctx");
    const auto message = text("message");
    for (const std::size_t length : {0U, 1U, 15U, 17U, 20U, 23U, 25U, 31U, 33U, 64U}) {
        const Bytes tag(length, 0xA5U);
        require(!pvcmac0::verify_tag(key, context, message, tag),
                "unsupported tag length accepted");
    }
}

void test_verify_cross_profile_prefix_reject() {
    const auto key = incremental_key();
    const auto context = text("ctx");
    const auto message = text("message");
    const auto tag256 = pvcmac0::compute_tag(key, context, message, pvcmac0::TagSize::Bits256);
    const Bytes prefix128(tag256.begin(), tag256.begin() + 16);
    const Bytes prefix192(tag256.begin(), tag256.begin() + 24);
    require(!pvcmac0::verify_tag(key, context, message, prefix128),
            "256-bit profile prefix accepted as 128-bit profile tag");
    require(!pvcmac0::verify_tag(key, context, message, prefix192),
            "256-bit profile prefix accepted as 192-bit profile tag");
}

void test_binary_null_preservation() {
    const Bytes a{0x41U, 0x00U, 0x42U};
    const Bytes b{0x41U, 0x42U};
    require(pvcmac0::compute_tag(zero_key(), {}, a, pvcmac0::TagSize::Bits256)
            != pvcmac0::compute_tag(zero_key(), {}, b, pvcmac0::TagSize::Bits256),
            "embedded NUL not preserved");
}

using Test = std::function<void()>;

std::map<std::string, Test> tests() {
    return {
        {"upstream-prf-vector", test_upstream_prf_vector},
        {"framing-empty-exact", test_framing_empty_exact},
        {"framing-binary-exact", test_framing_binary_exact},
        {"framing-injective", test_framing_injective},
        {"vector-zero-empty-256", test_vector_zero_empty_256},
        {"vector-zero-abc-256", test_vector_zero_abc_256},
        {"vector-incremental-binary-128", test_vector_incremental_binary_128},
        {"determinism", test_determinism},
        {"message-binding", test_message_binding},
        {"message-length-binding", test_message_length_binding},
        {"key-binding", test_key_binding},
        {"context-binding", test_context_binding},
        {"tag-size-domain-binding", test_tag_size_domain_binding},
        {"verify-accept", test_verify_accept},
        {"verify-reject-tag", test_verify_reject_tag},
        {"verify-reject-message", test_verify_reject_message},
        {"invalid-tag-size", test_invalid_tag_size},
        {"verify-all-supported-lengths", test_verify_all_supported_lengths},
        {"verify-invalid-length-matrix", test_verify_invalid_length_matrix},
        {"verify-cross-profile-prefix-reject", test_verify_cross_profile_prefix_reject},
        {"binary-null-preservation", test_binary_null_preservation},
    };
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto all = tests();
        if (argc == 3 && std::string_view(argv[1]) == "--case") {
            const auto it = all.find(argv[2]);
            if (it == all.end()) throw std::invalid_argument("unknown test case");
            it->second();
            std::cout << "PASS " << it->first << '\n';
            return 0;
        }
        for (const auto& [name, test] : all) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << all.size() << "/" << all.size() << " tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
