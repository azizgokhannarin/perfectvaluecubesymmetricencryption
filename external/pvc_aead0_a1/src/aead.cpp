#include "pvcaead0/aead.hpp"

#include "pvc1/key_schedule.hpp"
#include "pvcmac0/mac.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string>

namespace pvcaead0 {
namespace {

constexpr std::array<std::uint8_t, 10> kMagic{
    0x50U, 0x56U, 0x43U, 0x2DU, 0x41U, 0x45U, 0x41U, 0x44U, 0x2DU, 0x30U,
}; // "PVC-AEAD-0"
constexpr std::uint8_t kSeparator = 0x00U;
constexpr std::uint8_t kFrameVersion = 0x01U;
constexpr std::uint8_t kPrimitiveProfileC1 = 0xC1U;
constexpr std::uint8_t kMacProfileM1 = 0xD1U;
constexpr std::uint8_t kRoleStream = 0x53U; // 'S'
constexpr std::uint8_t kRoleAuthentication = 0x41U; // 'A'
constexpr std::uint8_t kReserved = 0x00U;
constexpr std::size_t kStreamFrameSize = 48U;
constexpr std::size_t kAuthFixedSize = 49U;
constexpr std::size_t kBlockSize = 32U;
constexpr std::uint64_t kMaximumEncodedLength = std::numeric_limits<std::uint64_t>::max();

void append_u64_be(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (unsigned shift = 56U;; shift -= 8U) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
        if (shift == 0U) break;
    }
}

std::uint64_t checked_u64_length(std::size_t size, const char* field) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (size > static_cast<std::size_t>(kMaximumEncodedLength)) {
            throw std::length_error(std::string(field) + " exceeds the u64 framing limit");
        }
    }
    return static_cast<std::uint64_t>(size);
}

void validate_authentication_context_length(std::size_t associated_data_size) {
    if (associated_data_size > std::numeric_limits<std::size_t>::max() - kAuthFixedSize) {
        throw std::length_error("PVC-AEAD-0 authentication context overflows size_t");
    }
    if constexpr (sizeof(std::size_t) >= sizeof(std::uint64_t)) {
        const auto maximum_associated_data =
            static_cast<std::size_t>(kMaximumEncodedLength - static_cast<std::uint64_t>(kAuthFixedSize));
        if (associated_data_size > maximum_associated_data) {
            throw std::length_error("PVC-AEAD-0 authentication context exceeds the u64 M1 context limit");
        }
    }
}

pvcmac0::TagSize to_mac_tag_size(TagSize size) {
    switch (size) {
        case TagSize::Bits128: return pvcmac0::TagSize::Bits128;
        case TagSize::Bits192: return pvcmac0::TagSize::Bits192;
        case TagSize::Bits256: return pvcmac0::TagSize::Bits256;
    }
    throw std::invalid_argument("unsupported PVC-AEAD-0 tag size");
}

std::vector<std::uint8_t> apply_keystream(const Key256& key,
                                          const Nonce192& nonce,
                                          std::span<const std::uint8_t> input,
                                          TagSize tag_size) {
    std::vector<std::uint8_t> output(input.size());
    const std::size_t blocks = input.empty() ? 0U : 1U + ((input.size() - 1U) / kBlockSize);

    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        const auto maximum_blocks = static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max()) + 1U;
        if (blocks > maximum_blocks) {
            throw std::length_error("PVC-AEAD-0 message exceeds the u64 counter domain");
        }
    }

    for (std::size_t block = 0U; block < blocks; ++block) {
        const auto counter = static_cast<std::uint64_t>(block);
        const auto framed = frame_stream_block(nonce, counter, tag_size);
        const auto stream = pvc1::research_keyed_return_output_a2(key, framed);
        const std::size_t offset = block * kBlockSize;
        const std::size_t remaining = input.size() - offset;
        const std::size_t take = std::min(kBlockSize, remaining);
        for (std::size_t i = 0U; i < take; ++i) {
            output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ stream[i]);
        }
    }
    return output;
}

} // namespace

bool is_supported_tag_size(std::size_t bytes) noexcept {
    return bytes == tag_size_bytes(TagSize::Bits128)
        || bytes == tag_size_bytes(TagSize::Bits192)
        || bytes == tag_size_bytes(TagSize::Bits256);
}

TagSize tag_size_from_bytes(std::size_t bytes) {
    switch (bytes) {
        case 16U: return TagSize::Bits128;
        case 24U: return TagSize::Bits192;
        case 32U: return TagSize::Bits256;
        default: throw std::invalid_argument("PVC-AEAD-0 tag size must be 16, 24, or 32 bytes");
    }
}

std::vector<std::uint8_t> frame_stream_block(const Nonce192& nonce,
                                             std::uint64_t counter,
                                             TagSize tag_size) {
    const auto tag_bytes = tag_size_bytes(tag_size);
    if (!is_supported_tag_size(tag_bytes)) {
        throw std::invalid_argument("unsupported PVC-AEAD-0 tag size");
    }

    std::vector<std::uint8_t> framed;
    framed.reserve(kStreamFrameSize);
    framed.insert(framed.end(), kMagic.begin(), kMagic.end());
    framed.push_back(kSeparator);
    framed.push_back(kFrameVersion);
    framed.push_back(kRoleStream);
    framed.push_back(kPrimitiveProfileC1);
    framed.push_back(static_cast<std::uint8_t>(tag_bytes));
    framed.push_back(kReserved);
    framed.insert(framed.end(), nonce.begin(), nonce.end());
    append_u64_be(framed, counter);
    return framed;
}

std::vector<std::uint8_t> frame_authentication_context(
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    TagSize tag_size) {
    const auto tag_bytes = tag_size_bytes(tag_size);
    if (!is_supported_tag_size(tag_bytes)) {
        throw std::invalid_argument("unsupported PVC-AEAD-0 tag size");
    }
    validate_authentication_context_length(associated_data.size());

    std::vector<std::uint8_t> framed;
    framed.reserve(kAuthFixedSize + associated_data.size());
    framed.insert(framed.end(), kMagic.begin(), kMagic.end());
    framed.push_back(kSeparator);
    framed.push_back(kFrameVersion);
    framed.push_back(kRoleAuthentication);
    framed.push_back(kPrimitiveProfileC1);
    framed.push_back(kMacProfileM1);
    framed.push_back(static_cast<std::uint8_t>(tag_bytes));
    framed.push_back(kReserved);
    framed.insert(framed.end(), nonce.begin(), nonce.end());
    append_u64_be(framed, checked_u64_length(associated_data.size(), "associated data"));
    framed.insert(framed.end(), associated_data.begin(), associated_data.end());
    return framed;
}

SealedMessage seal(const KeyPair512& keys,
                   const Nonce192& nonce,
                   std::span<const std::uint8_t> associated_data,
                   std::span<const std::uint8_t> plaintext,
                   TagSize tag_size) {
    (void)checked_u64_length(plaintext.size(), "plaintext");
    SealedMessage result;
    result.ciphertext = apply_keystream(keys.encryption_key, nonce, plaintext, tag_size);
    const auto context = frame_authentication_context(nonce, associated_data, tag_size);
    result.tag = pvcmac0::compute_tag(keys.authentication_key,
                                     context,
                                     result.ciphertext,
                                     to_mac_tag_size(tag_size));
    return result;
}

std::optional<std::vector<std::uint8_t>> open(
    const KeyPair512& keys,
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> supplied_tag) {
    if (!is_supported_tag_size(supplied_tag.size())) return std::nullopt;
    (void)checked_u64_length(ciphertext.size(), "ciphertext");
    const auto tag_size = tag_size_from_bytes(supplied_tag.size());
    const auto context = frame_authentication_context(nonce, associated_data, tag_size);

    // Encrypt-then-MAC: authenticate before deriving or exposing plaintext.
    if (!pvcmac0::verify_tag(keys.authentication_key, context, ciphertext, supplied_tag)) {
        return std::nullopt;
    }
    return apply_keystream(keys.encryption_key, nonce, ciphertext, tag_size);
}

} // namespace pvcaead0
