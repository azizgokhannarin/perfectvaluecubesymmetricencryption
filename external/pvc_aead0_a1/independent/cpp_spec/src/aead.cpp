#include "pvcaead0_independent/aead.hpp"

#include "pvc1/key_schedule.hpp"
#include "pvcmac0_independent/mac.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace pvcaead0_independent {
namespace {

constexpr std::array<std::uint8_t, 16> kStreamPrefix{
    0x50U,0x56U,0x43U,0x2DU,0x41U,0x45U,0x41U,0x44U,0x2DU,0x30U,
    0x00U,0x01U,0x53U,0xC1U,0x00U,0x00U,
};
constexpr std::array<std::uint8_t, 17> kAuthPrefix{
    0x50U,0x56U,0x43U,0x2DU,0x41U,0x45U,0x41U,0x44U,0x2DU,0x30U,
    0x00U,0x01U,0x41U,0xC1U,0xD1U,0x00U,0x00U,
};
constexpr std::size_t kStreamFrameBytes = 48U;
constexpr std::size_t kStreamTagOffset = 14U;
constexpr std::size_t kStreamNonceOffset = 16U;
constexpr std::size_t kStreamCounterOffset = 40U;
constexpr std::size_t kAuthFixedBytes = 49U;
constexpr std::size_t kAuthTagOffset = 15U;
constexpr std::size_t kAuthNonceOffset = 17U;
constexpr std::size_t kAuthLengthOffset = 41U;
constexpr std::size_t kBlockBytes = 32U;

void store_u64_be(std::span<std::uint8_t, 8> destination, std::uint64_t value) {
    for (std::size_t i = 0; i < destination.size(); ++i) {
        const auto shift = static_cast<unsigned>((destination.size() - 1U - i) * 8U);
        destination[i] = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
    }
}

std::uint64_t checked_u64_length(std::size_t value, const char* message) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
            throw std::length_error(message);
        }
    }
    return static_cast<std::uint64_t>(value);
}

void validate_auth_context_size(std::size_t ad_size) {
    if (ad_size > std::numeric_limits<std::size_t>::max() - kAuthFixedBytes) {
        throw std::length_error("PVC-AEAD-0 independent authentication context overflows size_t");
    }
    if constexpr (sizeof(std::size_t) >= sizeof(std::uint64_t)) {
        constexpr auto maximum = std::numeric_limits<std::uint64_t>::max()
                               - static_cast<std::uint64_t>(kAuthFixedBytes);
        if (ad_size > static_cast<std::size_t>(maximum)) {
            throw std::length_error("PVC-AEAD-0 independent authentication context exceeds u64");
        }
    }
}

pvcmac0_independent::TagSize to_mac_tag_size(TagSize size) {
    switch (size) {
        case TagSize::Bits128: return pvcmac0_independent::TagSize::Bits128;
        case TagSize::Bits192: return pvcmac0_independent::TagSize::Bits192;
        case TagSize::Bits256: return pvcmac0_independent::TagSize::Bits256;
    }
    throw std::invalid_argument("unsupported PVC-AEAD-0 independent tag size");
}

std::vector<std::uint8_t> xor_keystream(const Key256& key,
                                        const Nonce192& nonce,
                                        std::span<const std::uint8_t> input,
                                        TagSize tag_size) {
    std::vector<std::uint8_t> output(input.size());
    const std::size_t blocks = input.empty() ? 0U : ((input.size() + (kBlockBytes - 1U)) / kBlockBytes);
    for (std::size_t block = 0; block < blocks; ++block) {
        const auto frame = frame_stream_block(nonce, static_cast<std::uint64_t>(block), tag_size);
        const auto stream = pvc1::research_keyed_return_output_a2(key, frame);
        const std::size_t offset = block * kBlockBytes;
        const std::size_t take = std::min(kBlockBytes, input.size() - offset);
        for (std::size_t i = 0; i < take; ++i) {
            output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ stream[i]);
        }
    }
    return output;
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
        default: throw std::invalid_argument("PVC-AEAD-0 independent tag size must be 16, 24, or 32 bytes");
    }
}

std::vector<std::uint8_t> frame_stream_block(const Nonce192& nonce,
                                             std::uint64_t counter,
                                             TagSize tag_size) {
    const auto bytes = tag_size_bytes(tag_size);
    if (!is_supported_tag_size(bytes)) throw std::invalid_argument("unsupported independent tag size");
    std::vector<std::uint8_t> frame(kStreamFrameBytes);
    std::copy(kStreamPrefix.begin(), kStreamPrefix.end(), frame.begin());
    frame[kStreamTagOffset] = static_cast<std::uint8_t>(bytes);
    std::copy(nonce.begin(), nonce.end(), frame.begin() + static_cast<std::ptrdiff_t>(kStreamNonceOffset));
    store_u64_be(std::span<std::uint8_t, 8>(frame.data() + kStreamCounterOffset, 8U), counter);
    return frame;
}

std::vector<std::uint8_t> frame_authentication_context(
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    TagSize tag_size) {
    const auto bytes = tag_size_bytes(tag_size);
    if (!is_supported_tag_size(bytes)) throw std::invalid_argument("unsupported independent tag size");
    validate_auth_context_size(associated_data.size());
    std::vector<std::uint8_t> frame(kAuthFixedBytes + associated_data.size());
    std::copy(kAuthPrefix.begin(), kAuthPrefix.end(), frame.begin());
    frame[kAuthTagOffset] = static_cast<std::uint8_t>(bytes);
    std::copy(nonce.begin(), nonce.end(), frame.begin() + static_cast<std::ptrdiff_t>(kAuthNonceOffset));
    store_u64_be(std::span<std::uint8_t, 8>(frame.data() + kAuthLengthOffset, 8U),
                 checked_u64_length(associated_data.size(), "independent associated data exceeds u64"));
    std::copy(associated_data.begin(), associated_data.end(),
              frame.begin() + static_cast<std::ptrdiff_t>(kAuthFixedBytes));
    return frame;
}

SealedMessage seal(const KeyPair512& keys,
                   const Nonce192& nonce,
                   std::span<const std::uint8_t> associated_data,
                   std::span<const std::uint8_t> plaintext,
                   TagSize tag_size) {
    (void)checked_u64_length(plaintext.size(), "independent plaintext exceeds u64");
    SealedMessage sealed;
    sealed.ciphertext = xor_keystream(keys.encryption_key, nonce, plaintext, tag_size);
    const auto context = frame_authentication_context(nonce, associated_data, tag_size);
    sealed.tag = pvcmac0_independent::compute_tag(keys.authentication_key,
                                                  context,
                                                  sealed.ciphertext,
                                                  to_mac_tag_size(tag_size));
    return sealed;
}

std::optional<std::vector<std::uint8_t>> open(
    const KeyPair512& keys,
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> supplied_tag) {
    if (!is_supported_tag_size(supplied_tag.size())) return std::nullopt;
    (void)checked_u64_length(ciphertext.size(), "independent ciphertext exceeds u64");
    const auto tag_size = tag_size_from_bytes(supplied_tag.size());
    const auto context = frame_authentication_context(nonce, associated_data, tag_size);
    if (!pvcmac0_independent::verify_tag(keys.authentication_key,
                                         context,
                                         ciphertext,
                                         supplied_tag)) {
        return std::nullopt;
    }
    return xor_keystream(keys.encryption_key, nonce, ciphertext, tag_size);
}

} // namespace pvcaead0_independent
