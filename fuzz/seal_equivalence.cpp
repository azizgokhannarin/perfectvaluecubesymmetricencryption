#include "fuzz_input.hpp"

#include "pvcaead0_independent/aead.hpp"
#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {

struct TagProfiles {
    pvcrotsymenc1::TagSize canonical;
    pvcaead0_independent::TagSize independent;
};

TagProfiles select_tag_profiles(std::uint8_t selector) noexcept {
    switch (selector % 3U) {
        case 0U:
            return {pvcrotsymenc1::TagSize::Bits128,
                    pvcaead0_independent::TagSize::Bits128};
        case 1U:
            return {pvcrotsymenc1::TagSize::Bits192,
                    pvcaead0_independent::TagSize::Bits192};
        default:
            return {pvcrotsymenc1::TagSize::Bits256,
                    pvcaead0_independent::TagSize::Bits256};
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    pvcrotsymenc1::fuzzing::InputReader input(
        std::span<const std::uint8_t>(data, size));

    const auto tag_profiles = select_tag_profiles(input.take_byte());
    const auto split_hint = input.take_u16_be();
    const auto encryption_key = input.take_array<32U>();
    const auto authentication_key = input.take_array<32U>();
    const auto nonce = input.take_array<24U>();
    const auto payload = input.remaining();
    const auto ad_size = pvcrotsymenc1::fuzzing::split_index(split_hint, payload.size());
    const auto associated_data = payload.first(ad_size);
    const auto plaintext = payload.subspan(ad_size);

    const pvcrotsymenc1::KeyPair512 canonical_keys{
        encryption_key,
        authentication_key,
    };
    const pvcaead0_independent::KeyPair512 independent_keys{
        encryption_key,
        authentication_key,
    };

    const auto canonical = pvcrotsymenc1::seal(
        canonical_keys, nonce, associated_data, plaintext, tag_profiles.canonical);
    const auto independent = pvcaead0_independent::seal(
        independent_keys, nonce, associated_data, plaintext, tag_profiles.independent);

    pvcrotsymenc1::fuzzing::require(
        canonical.ciphertext == independent.ciphertext,
        "seal differential failure: ciphertext mismatch");
    pvcrotsymenc1::fuzzing::require(
        canonical.tag == independent.tag,
        "seal differential failure: tag mismatch");
    return 0;
}
