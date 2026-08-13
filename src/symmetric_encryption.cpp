#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include "pvcaead0/aead.hpp"

#include <stdexcept>

namespace pvcrotsymenc1 {
namespace {

pvcaead0::KeyPair512 to_a1_keys(const KeyPair512& keys) {
    return pvcaead0::KeyPair512{keys.encryption_key, keys.authentication_key};
}

pvcaead0::Nonce192 to_a1_nonce(const Nonce192& nonce) {
    return nonce;
}

pvcaead0::TagSize to_a1_tag_size(TagSize size) {
    switch (size) {
        case TagSize::Bits128: return pvcaead0::TagSize::Bits128;
        case TagSize::Bits192: return pvcaead0::TagSize::Bits192;
        case TagSize::Bits256: return pvcaead0::TagSize::Bits256;
    }
    throw std::invalid_argument("unsupported PVC-RotSymEnc-1 tag size");
}

} // namespace

bool is_supported_tag_size(std::size_t bytes) noexcept {
    return bytes == 16U || bytes == 24U || bytes == 32U;
}

TagSize tag_size_from_bytes(std::size_t bytes) {
    switch (bytes) {
        case 16U: return TagSize::Bits128;
        case 24U: return TagSize::Bits192;
        case 32U: return TagSize::Bits256;
        default: throw std::invalid_argument("PVC-RotSymEnc-1 tag size must be 16, 24, or 32 bytes");
    }
}

SealedMessage seal(const KeyPair512& keys,
                   const Nonce192& nonce,
                   std::span<const std::uint8_t> associated_data,
                   std::span<const std::uint8_t> plaintext,
                   TagSize tag_size) {
    const auto sealed = pvcaead0::seal(
        to_a1_keys(keys), to_a1_nonce(nonce), associated_data, plaintext, to_a1_tag_size(tag_size));
    return SealedMessage{sealed.ciphertext, sealed.tag};
}

std::optional<std::vector<std::uint8_t>> open(
    const KeyPair512& keys,
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> supplied_tag) {
    return pvcaead0::open(to_a1_keys(keys), to_a1_nonce(nonce), associated_data, ciphertext, supplied_tag);
}

} // namespace pvcrotsymenc1
