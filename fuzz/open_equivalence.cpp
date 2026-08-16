#include "fuzz_input.hpp"

#include "pvcaead0_independent/aead.hpp"
#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace {

pvcaead0_independent::TagSize select_tag_profile(std::uint8_t selector) noexcept {
    switch (selector % 3U) {
        case 0U: return pvcaead0_independent::TagSize::Bits128;
        case 1U: return pvcaead0_independent::TagSize::Bits192;
        default: return pvcaead0_independent::TagSize::Bits256;
    }
}

std::size_t raw_tag_size(std::uint8_t selector) noexcept {
    if (selector == static_cast<std::uint8_t>('a')) return 16U;
    if (selector == static_cast<std::uint8_t>('b')) return 24U;
    if (selector == static_cast<std::uint8_t>('c')) return 32U;
    return static_cast<std::size_t>(selector);
}

void compare_open_results(
    const std::optional<std::vector<std::uint8_t>>& canonical,
    const std::optional<std::vector<std::uint8_t>>& independent) {
    pvcrotsymenc1::fuzzing::require(
        canonical.has_value() == independent.has_value(),
        "open differential failure: acceptance mismatch");
    if (!canonical.has_value()) return;
    pvcrotsymenc1::fuzzing::require(
        *canonical == *independent,
        "open differential failure: plaintext mismatch");
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    pvcrotsymenc1::fuzzing::InputReader input(
        std::span<const std::uint8_t>(data, size));

    const auto mode = input.take_byte();
    const auto tag_selector = input.take_byte();
    const auto split_hint = input.take_u16_be();
    const auto encryption_key = input.take_array<32U>();
    const auto authentication_key = input.take_array<32U>();
    const auto nonce = input.take_array<24U>();
    const auto payload = input.remaining();

    const pvcrotsymenc1::KeyPair512 canonical_keys{
        encryption_key,
        authentication_key,
    };
    const pvcaead0_independent::KeyPair512 independent_keys{
        encryption_key,
        authentication_key,
    };

    if ((mode & 1U) != 0U) {
        const auto tag_profile = select_tag_profile(tag_selector);
        const auto ad_size = pvcrotsymenc1::fuzzing::split_index(split_hint, payload.size());
        const auto associated_data = payload.first(ad_size);
        const auto plaintext = payload.subspan(ad_size);
        const auto sealed = pvcaead0_independent::seal(
            independent_keys, nonce, associated_data, plaintext, tag_profile);

        const auto canonical = pvcrotsymenc1::open(
            canonical_keys, nonce, associated_data, sealed.ciphertext, sealed.tag);
        const auto independent = pvcaead0_independent::open(
            independent_keys, nonce, associated_data, sealed.ciphertext, sealed.tag);
        compare_open_results(canonical, independent);
        pvcrotsymenc1::fuzzing::require(
            canonical.has_value(),
            "open differential failure: generated valid tuple was rejected");
        pvcrotsymenc1::fuzzing::require(
            canonical->size() == plaintext.size()
                && std::equal(canonical->begin(), canonical->end(),
                              plaintext.begin(), plaintext.end()),
            "open differential failure: generated tuple recovered wrong plaintext");
        return 0;
    }

    const auto requested_tag_size = raw_tag_size(tag_selector);
    const auto copied_tag_size = std::min(requested_tag_size, payload.size());
    const auto body = payload.first(payload.size() - copied_tag_size);
    const auto ad_size = pvcrotsymenc1::fuzzing::split_index(split_hint, body.size());
    const auto associated_data = body.first(ad_size);
    const auto ciphertext = body.subspan(ad_size);
    std::vector<std::uint8_t> supplied_tag(requested_tag_size, 0U);
    const auto tag_material = payload.last(copied_tag_size);
    std::copy(tag_material.begin(), tag_material.end(),
              supplied_tag.end() - static_cast<std::ptrdiff_t>(copied_tag_size));

    const auto canonical = pvcrotsymenc1::open(
        canonical_keys, nonce, associated_data, ciphertext, supplied_tag);
    const auto independent = pvcaead0_independent::open(
        independent_keys, nonce, associated_data, ciphertext, supplied_tag);
    compare_open_results(canonical, independent);
    if (canonical.has_value()) {
        pvcrotsymenc1::fuzzing::require(
            canonical->size() == ciphertext.size(),
            "open differential failure: accepted plaintext length mismatch");
    }
    return 0;
}
